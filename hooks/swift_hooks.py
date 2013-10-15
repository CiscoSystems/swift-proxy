#!/usr/bin/python

import os
import sys
import shutil
import uuid
import subprocess

import charmhelpers.contrib.openstack.utils as openstack
import charmhelpers.contrib.hahelpers.cluster as cluster
from swift_utils import (
    register_configs,
    restart_map,
    determine_packages,
    ensure_swift_dir,
    SWIFT_RINGS, WWW_DIR,
    initialize_ring,
    swift_user,
    SWIFT_HA_RES,
    balance_ring,
    SWIFT_CONF_DIR,
    get_zone,
    exists_in_ring,
    add_to_ring,
    should_balance,
    do_openstack_upgrade,
    write_rc_script
)
from swift_context import get_swift_hash

from charmhelpers.core.hookenv import (
    config,
    unit_get,
    relation_set,
    relation_ids,
    relation_get,
    log, ERROR,
    Hooks, UnregisteredHookError,
    open_port
)
from charmhelpers.core.host import (
    service_restart,
    restart_on_change
)
from charmhelpers.fetch import (
    apt_install,
    apt_update
)
from charmhelpers.payload.execd import execd_preinstall

extra_pkgs = [
    "haproxy",
    "python-jinja2"
]


hooks = Hooks()

CONFIGS = register_configs()


@hooks.hook('install')
def install():
    execd_preinstall()
    src = config('openstack-origin')
    if src != 'distro':
        openstack.configure_installation_source(src)
    apt_update(fatal=True)
    rel = openstack.get_os_codename_install_source(src)

    pkgs = determine_packages(rel)
    apt_install(pkgs, fatal=True)
    apt_install(extra_pkgs, fatal=True)

    ensure_swift_dir()
    # initialize new storage rings.
    for ring in SWIFT_RINGS.iteritems():
        initialize_ring(ring[1],
                        config('partition-power'),
                        config('replicas'),
                        config('min-hours'))

    # configure a directory on webserver for distributing rings.
    if not os.path.isdir(WWW_DIR):
        os.mkdir(WWW_DIR, 0755)
    uid, gid = swift_user()
    os.chown(WWW_DIR, uid, gid)


@hooks.hook('identity-service-relation-joined')
def keystone_joined(relid=None):
    if not cluster.eligible_leader(SWIFT_HA_RES):
        return
    if cluster.is_clustered():
        hostname = config('vip')
    else:
        hostname = unit_get('private-address')
    port = config('bind-port')
    if cluster.https():
        proto = 'https'
    else:
        proto = 'http'
    admin_url = '%s://%s:%s' % (proto, hostname, port)
    internal_url = public_url = '%s/v1/AUTH_$(tenant_id)s' % admin_url
    relation_set(service='swift',
                 region=config('region'),
                 public_url=public_url, internal_url=internal_url,
                 admin_url=admin_url,
                 requested_roles=config('operator-roles'),
                 relation_id=relid)


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map())
def keystone_changed():
    configure_https()


def balance_rings():
    '''handle doing ring balancing and distribution.'''
    new_ring = False
    for ring in SWIFT_RINGS.itervalues():
        if balance_ring(ring):
            log('Balanced ring %s' % ring)
            new_ring = True
    if not new_ring:
        return

    for ring in SWIFT_RINGS.keys():
        f = '%s.ring.gz' % ring
        shutil.copyfile(os.path.join(SWIFT_CONF_DIR, f),
                        os.path.join(WWW_DIR, f))

    if cluster.eligible_leader(SWIFT_HA_RES):
        msg = 'Broadcasting notification to all storage nodes that new '\
              'ring is ready for consumption.'
        log(msg)
        path = WWW_DIR.split('/var/www/')[1]
        trigger = uuid.uuid4()

        if cluster.is_clustered():
            hostname = config('vip')
        else:
            hostname = unit_get('private-address')

        rings_url = 'http://%s/%s' % (hostname, path)
        # notify storage nodes that there is a new ring to fetch.
        for relid in relation_ids('swift-storage'):
            relation_set(relation_id=relid, swift_hash=get_swift_hash(),
                         rings_url=rings_url, trigger=trigger)

    service_restart('swift-proxy')


@hooks.hook('swift-storage-relation-changed')
@restart_on_change(restart_map())
def storage_changed():
    zone = get_zone(config('zone-assignment'))
    node_settings = {
        'ip': openstack.get_host_ip(relation_get('private-address')),
        'zone': zone,
        'account_port': relation_get('account_port'),
        'object_port': relation_get('object_port'),
        'container_port': relation_get('container_port'),
    }
    if None in node_settings.itervalues():
        log('storage_changed: Relation not ready.')
        return None

    for k in ['zone', 'account_port', 'object_port', 'container_port']:
        node_settings[k] = int(node_settings[k])

    CONFIGS.write_all()

    # allow for multiple devs per unit, passed along as a : separated list
    devs = relation_get('device').split(':')
    for dev in devs:
        node_settings['device'] = dev
        for ring in SWIFT_RINGS.itervalues():
            if not exists_in_ring(ring, node_settings):
                add_to_ring(ring, node_settings)

    if should_balance([r for r in SWIFT_RINGS.itervalues()]):
        balance_rings()


@hooks.hook('swift-storage-relation-broken')
@restart_on_change(restart_map())
def storage_broken():
    CONFIGS.write_all()


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    configure_https()
    open_port(config('bind-port'))
    # Determine whether or not we should do an upgrade, based on the
    # the version offered in keyston-release.
    src = config('openstack-origin')
    available = openstack.get_os_codename_install_source(src)
    installed = openstack.get_os_codename_package('python-swift')
    if (available and
        openstack.get_os_version_codename(available) >
        openstack.get_os_version_codename(installed)):
        pkgs = determine_packages(available)
        do_openstack_upgrade(src, pkgs)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-joined')
@restart_on_change(restart_map())
def cluster_changed():
    CONFIGS.write_all()


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if clustered and cluster.is_leader(SWIFT_HA_RES):
        log('Cluster configured, notifying other services and'
            'updating keystone endpoint configuration')
        # Tell all related services to start using
        # the VIP instead
        for r_id in relation_ids('identity-service'):
            keystone_joined(relid=r_id)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    # Obtain the config values necessary for the cluster config. These
    # include multicast port and interface to bind to.
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')
    vip = config('vip')
    vip_cidr = config('vip_cidr')
    vip_iface = config('vip_iface')
    if not vip:
        log('Unable to configure hacluster as vip not provided',
            level=ERROR)
        sys.exit(1)

    # Obtain resources
    resources = {
        'res_swift_vip': 'ocf:heartbeat:IPaddr2',
        'res_swift_haproxy': 'lsb:haproxy'
    }
    resource_params = {
        'res_swift_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' %
        (vip, vip_cidr, vip_iface),
        'res_swift_haproxy': 'op monitor interval="5s"'
    }
    init_services = {
        'res_swift_haproxy': 'haproxy'
    }
    clones = {
        'cl_swift_haproxy': 'res_swift_haproxy'
    }

    relation_set(init_services=init_services,
                 corosync_bindiface=corosync_bindiface,
                 corosync_mcastport=corosync_mcastport,
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        subprocess.check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        subprocess.check_call(cmd)

    # Apache 2.4 required enablement of configuration
    if os.path.exists('/usr/sbin/a2enconf'):
        subprocess.check_call(['a2enconf', 'swift-rings'])

    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)

    write_rc_script()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()

#!/usr/bin/python

import os
import utils
import sys
import shutil
import uuid
from subprocess import check_call

import lib.openstack_common as openstack
import swift_utils as swift

extra_pkgs = [
    "haproxy",
    "python-jinja2"
    ]

def install():
    src = utils.config_get('openstack-origin')
    if src != 'distro':
        openstack.configure_installation_source(src)
    check_call(['apt-get', 'update'])
    rel = openstack.get_os_codename_install_source(src)

    pkgs = swift.determine_packages(rel)
    utils.install(*pkgs)
    utils.install(*extra_pkgs)

    swift.ensure_swift_dir()

    # initialize swift configs.
    # swift.conf hash
    ctxt = {
        'swift_hash': swift.get_swift_hash()
    }
    with open(swift.SWIFT_CONF, 'w') as conf:
        conf.write(swift.render_config(swift.SWIFT_CONF, ctxt))

    # swift-proxy.conf
    swift.write_proxy_config()

    # memcached.conf
    ctxt = { 'proxy_ip': utils.get_host_ip() }
    with open(swift.MEMCACHED_CONF, 'w') as conf:
        conf.write(swift.render_config(swift.MEMCACHED_CONF, ctxt))

    # generate or setup SSL certificate
    swift.configure_ssl()

    # initialize new storage rings.
    for ring in swift.SWIFT_RINGS.iteritems():
        swift.initialize_ring(ring[1],
                              utils.config_get('partition-power'),
                              utils.config_get('replicas'),
                              utils.config_get('min-hours'))

    # configure a directory on webserver for distributing rings.
    if not os.path.isdir(swift.WWW_DIR):
        os.mkdir(swift.WWW_DIR, 0755)
    uid, gid = swift.swift_user()
    os.chown(swift.WWW_DIR, uid, gid)
    swift.write_apache_config()


def keystone_joined(relid=None):
    if not utils.eligible_leader():
        return
    if utils.is_clustered():
        hostname = utils.config_get('vip')
    else:
        hostname = utils.unit_get('private-address')
    port = utils.config_get('bind-port')
    ssl = utils.config_get('use-https')
    if ssl == 'yes':
        proto = 'https'
    else:
        proto = 'http'
    admin_url = '%s://%s:%s' % (proto, hostname, port)
    internal_url = public_url = '%s/v1/AUTH_$(tenant_id)s' % admin_url
    utils.relation_set(service='swift',
                       region=utils.config_get('region'),
                       public_url=public_url, internal_url=internal_url,
                       admin_url=admin_url,
                       requested_roles=utils.config_get('operator-roles'),
                       rid=relid)


def keystone_changed():
    swift.write_proxy_config()


def balance_rings():
    '''handle doing ring balancing and distribution.'''
    new_ring = False
    for ring in swift.SWIFT_RINGS.itervalues():
        if swift.balance_ring(ring):
            utils.juju_log('INFO', 'Balanced ring %s' % ring)
            new_ring = True
    if not new_ring:
        return

    for ring in swift.SWIFT_RINGS.keys():
        f = '%s.ring.gz' % ring
        shutil.copyfile(os.path.join(swift.SWIFT_CONF_DIR, f),
                        os.path.join(swift.WWW_DIR, f))

    if utils.eligible_leader():
        msg = 'Broadcasting notification to all storage nodes that new '\
              'ring is ready for consumption.'
        utils.juju_log('INFO', msg)
        www_dir = swift.WWW_DIR.split('/var/www/')[1]
        trigger = uuid.uuid4()
        swift_hash = swift.get_swift_hash()
        # notify storage nodes that there is a new ring to fetch.
        for relid in utils.relation_ids('swift-storage'):
            utils.relation_set(rid=relid, swift_hash=swift_hash,
                               www_dir=www_dir, trigger=trigger)

    swift.proxy_control('restart')

def storage_changed():
    zone = swift.get_zone(utils.config_get('zone-assignment'))
    node_settings = {
        'ip': utils.get_host_ip(utils.relation_get('private-address')),
        'zone': zone,
        'account_port': utils.relation_get('account_port'),
        'object_port': utils.relation_get('object_port'),
        'container_port': utils.relation_get('container_port'),
    }
    if None in node_settings.itervalues():
        utils.juju_log('INFO', 'storage_changed: Relation not ready.')
        return None

    for k in ['zone', 'account_port', 'object_port', 'container_port']:
        node_settings[k] = int(node_settings[k])

    # Grant new node access to rings via apache.
    swift.write_apache_config()

    # allow for multiple devs per unit, passed along as a : separated list
    devs = utils.relation_get('device').split(':')
    for dev in devs:
        node_settings['device'] = dev
        for ring in swift.SWIFT_RINGS.itervalues():
            if not swift.exists_in_ring(ring, node_settings):
                swift.add_to_ring(ring, node_settings)

    if swift.should_balance([r for r in swift.SWIFT_RINGS.itervalues()]):
        balance_rings()

def storage_broken():
    swift.write_apache_config()

def config_changed():
    relids = utils.relation_ids('identity-service')
    if relids:
        for relid in relids:
            keystone_joined(relid)
    swift.write_proxy_config()
    cluster_changed()


SERVICE_PORTS = {
    "swift": [
        utils.config_get('bind-port'),
        int(utils.config_get('bind-port')) - 10
        ]
    }


def cluster_changed():
    cluster_hosts = {}
    cluster_hosts[os.getenv('JUJU_UNIT_NAME').replace('/', '-')] = \
        utils.unit_get('private-address')
    for r_id in utils.relation_ids('cluster'):
        for unit in utils.relation_list(r_id):
            cluster_hosts[unit.replace('/', '-')] = \
                utils.relation_get(attribute='private-address',
                                   rid=r_id,
                                   unit=unit)
    openstack.configure_haproxy(cluster_hosts,
                                SERVICE_PORTS)
    utils.reload('haproxy')


def ha_relation_changed():
    clustered = utils.relation_get('clustered')
    if clustered and utils.is_leader():
        utils.juju_log('INFO',
                       'Cluster configured, notifying other services and'
                       'updating keystone endpoint configuration')
        # Tell all related services to start using
        # the VIP and haproxy ports instead
        for r_id in utils.relation_ids('identity-service'):
            keystone_joined(relid=r_id)


def ha_relation_joined():
    # Obtain the config values necessary for the cluster config. These
    # include multicast port and interface to bind to.
    corosync_bindiface = utils.config_get('ha-bindiface')
    corosync_mcastport = utils.config_get('ha-mcastport')
    vip = utils.config_get('vip')
    vip_cidr = utils.config_get('vip_cidr')
    vip_iface = utils.config_get('vip_iface')
    if not vip:
        utils.juju_log('ERROR',
                       'Unable to configure hacluster as vip not provided')
        sys.exit(1)

    # Obtain resources
    resources = {
            'res_swift_vip': 'ocf:heartbeat:IPaddr2',
            'res_swift_haproxy': 'lsb:haproxy'
        }
    resource_params = {
            'res_swift_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                              (vip, vip_cidr, vip_iface),
            'res_swift_haproxy': 'op monitor interval="5s"'
        }
    init_services = {
            'res_swift_haproxy': 'haproxy'
        }
    clones = {
            'cl_swift_haproxy': 'res_swift_haproxy'
        }

    utils.relation_set(init_services=init_services,
                       corosync_bindiface=corosync_bindiface,
                       corosync_mcastport=corosync_mcastport,
                       resources=resources,
                       resource_params=resource_params,
                       clones=clones)


hooks = {
    'install': install,
    'config-changed': config_changed,
    'identity-service-relation-joined': keystone_joined,
    'identity-service-relation-changed': keystone_changed,
    'swift-storage-relation-changed': storage_changed,
    'swift-storage-relation-broken': storage_broken,
    "cluster-relation-joined": cluster_changed,
    "cluster-relation-changed": cluster_changed,
    "ha-relation-joined": ha_relation_joined,
    "ha-relation-changed": ha_relation_changed
}

utils.do_hooks(hooks)

sys.exit(0)

import os
import pwd
import subprocess
import charmhelpers.contrib.openstack.utils as openstack
import sys
from base64 import b64encode
from collections import OrderedDict

from charmhelpers.core.hookenv import (
    log, ERROR,
    config,
    relation_get,
)
from charmhelpers.fetch import (
    apt_update,
    apt_install
)

import charmhelpers.contrib.openstack.context as context
import charmhelpers.contrib.openstack.templating as templating
import swift_context


# Various config files that are managed via templating.
SWIFT_CONF = '/etc/swift/swift.conf'
SWIFT_PROXY_CONF = '/etc/swift/proxy-server.conf'
SWIFT_CONF_DIR = os.path.dirname(SWIFT_CONF)
MEMCACHED_CONF = '/etc/memcached.conf'
SWIFT_RINGS_CONF = '/etc/apache2/conf.d/swift-rings'
SWIFT_RINGS_24_CONF = '/etc/apache2/conf-available/swift-rings.conf'
HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_SITE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_SITE_24_CONF = '/etc/apache2/sites-available/' \
    'openstack_https_frontend.conf'

WWW_DIR = '/var/www/swift-rings'

SWIFT_RINGS = {
    'account': '/etc/swift/account.builder',
    'container': '/etc/swift/container.builder',
    'object': '/etc/swift/object.builder'
}

SSL_CERT = '/etc/swift/cert.crt'
SSL_KEY = '/etc/swift/cert.key'

# Essex packages
BASE_PACKAGES = [
    'swift',
    'swift-proxy',
    'memcached',
    'apache2',
    'python-keystone',
]
# > Folsom specific packages
FOLSOM_PACKAGES = BASE_PACKAGES + ['swift-plugin-s3']

SWIFT_HA_RES = 'res_swift_vip'

TEMPLATES = 'templates/'

# Map config files to hook contexts and services that will be associated
# with file in restart_on_changes()'s service map.
CONFIG_FILES = OrderedDict([
    (SWIFT_CONF, {
        'hook_contexts': [swift_context.SwiftHashContext()],
        'services': ['swift-proxy'],
    }),
    (SWIFT_PROXY_CONF, {
        'hook_contexts': [swift_context.SwiftIdentityContext()],
        'services': ['swift-proxy'],
    }),
    (HAPROXY_CONF, {
        'hook_contexts': [context.HAProxyContext(),
                          swift_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
    (SWIFT_RINGS_CONF, {
        'hook_contexts': [swift_context.SwiftRingContext()],
        'services': ['apache2'],
    }),
    (SWIFT_RINGS_24_CONF, {
        'hook_contexts': [swift_context.SwiftRingContext()],
        'services': ['apache2'],
    }),
    (APACHE_SITE_CONF, {
        'hook_contexts': [swift_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_SITE_24_CONF, {
        'hook_contexts': [swift_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (MEMCACHED_CONF, {
        'hook_contexts': [swift_context.MemcachedContext()],
        'services': ['memcached'],
    }),
])


def register_configs():
    """
    Register config files with their respective contexts.
    Regstration of some configs may not be required depending on
    existing of certain relations.
    """
    # if called without anything installed (eg during install hook)
    # just default to earliest supported release. configs dont get touched
    # till post-install, anyway.
    release = openstack.get_os_codename_package('swift-proxy', fatal=False) \
        or 'essex'
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)

    confs = [SWIFT_CONF,
             SWIFT_PROXY_CONF,
             HAPROXY_CONF,
             MEMCACHED_CONF]

    for conf in confs:
        configs.register(conf, CONFIG_FILES[conf]['hook_contexts'])

    if os.path.exists('/etc/apache2/conf-available'):
        configs.register(SWIFT_RINGS_24_CONF,
                         CONFIG_FILES[SWIFT_RINGS_24_CONF]['hook_contexts'])
        configs.register(APACHE_SITE_24_CONF,
                         CONFIG_FILES[APACHE_SITE_24_CONF]['hook_contexts'])
    else:
        configs.register(SWIFT_RINGS_CONF,
                         CONFIG_FILES[SWIFT_RINGS_CONF]['hook_contexts'])
        configs.register(APACHE_SITE_CONF,
                         CONFIG_FILES[APACHE_SITE_CONF]['hook_contexts'])
    return configs


def restart_map():
    '''
    Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = []
    for f, ctxt in CONFIG_FILES.iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map.append((f, svcs))
    return OrderedDict(_map)


def swift_user(username='swift'):
    user = pwd.getpwnam(username)
    return (user.pw_uid, user.pw_gid)


def ensure_swift_dir(conf_dir=os.path.dirname(SWIFT_CONF)):
    if not os.path.isdir(conf_dir):
        os.mkdir(conf_dir, 0750)
    uid, gid = swift_user()
    os.chown(conf_dir, uid, gid)


def determine_packages(release):
    '''determine what packages are needed for a given OpenStack release'''
    if release == 'essex':
        return BASE_PACKAGES
    elif release == 'folsom':
        return FOLSOM_PACKAGES
    elif release == 'grizzly':
        return FOLSOM_PACKAGES
    else:
        return FOLSOM_PACKAGES


def write_rc_script():
    env_vars = {'OPENSTACK_SERVICE_SWIFT': 'proxy-server',
                'OPENSTACK_PORT_API': config('bind-port'),
                'OPENSTACK_PORT_MEMCACHED': 11211}
    openstack.save_script_rc(**env_vars)


def _load_builder(path):
    # lifted straight from /usr/bin/swift-ring-builder
    from swift.common.ring import RingBuilder
    import cPickle as pickle
    try:
        builder = pickle.load(open(path, 'rb'))
        if not hasattr(builder, 'devs'):
            builder_dict = builder
            builder = RingBuilder(1, 1, 1)
            builder.copy_from(builder_dict)
    except ImportError:  # Happens with really old builder pickles
        builder = RingBuilder(1, 1, 1)
        builder.copy_from(pickle.load(open(path, 'rb')))
    for dev in builder.devs:
        if dev and 'meta' not in dev:
            dev['meta'] = ''
    return builder


def _write_ring(ring, ring_path):
    import cPickle as pickle
    pickle.dump(ring.to_dict(), open(ring_path, 'wb'), protocol=2)


def ring_port(ring_path, node):
    '''determine correct port from relation settings for a given ring file.'''
    for name in ['account', 'object', 'container']:
        if name in ring_path:
            return node[('%s_port' % name)]


def initialize_ring(path, part_power, replicas, min_hours):
    '''Initialize a new swift ring with given parameters.'''
    from swift.common.ring import RingBuilder
    ring = RingBuilder(part_power, replicas, min_hours)
    _write_ring(ring, path)


def exists_in_ring(ring_path, node):
    ring = _load_builder(ring_path).to_dict()
    node['port'] = ring_port(ring_path, node)

    for dev in ring['devs']:
        d = [(i, dev[i]) for i in dev if i in node and i != 'zone']
        n = [(i, node[i]) for i in node if i in dev and i != 'zone']
        if sorted(d) == sorted(n):

            msg = 'Node already exists in ring (%s).' % ring_path
            log(msg)
            return True

    return False


def add_to_ring(ring_path, node):
    ring = _load_builder(ring_path)
    port = ring_port(ring_path, node)

    devs = ring.to_dict()['devs']
    next_id = 0
    if devs:
        next_id = len([d['id'] for d in devs])

    new_dev = {
        'id': next_id,
        'zone': node['zone'],
        'ip': node['ip'],
        'port': port,
        'device': node['device'],
        'weight': 100,
        'meta': '',
    }
    ring.add_dev(new_dev)
    _write_ring(ring, ring_path)
    msg = 'Added new device to ring %s: %s' %\
        (ring_path,
         [k for k in new_dev.iteritems()])
    log(msg)


def _get_zone(ring_builder):
    replicas = ring_builder.replicas
    zones = [d['zone'] for d in ring_builder.devs]
    if not zones:
        return 1
    if len(zones) < replicas:
        return sorted(zones).pop() + 1

    zone_distrib = {}
    for z in zones:
        zone_distrib[z] = zone_distrib.get(z, 0) + 1

    if len(set([total for total in zone_distrib.itervalues()])) == 1:
        # all zones are equal, start assigning to zone 1 again.
        return 1

    return sorted(zone_distrib, key=zone_distrib.get).pop(0)


def get_zone(assignment_policy):
    ''' Determine the appropriate zone depending on configured assignment
        policy.

        Manual assignment relies on each storage zone being deployed as a
        separate service unit with its desired zone set as a configuration
        option.

        Auto assignment distributes swift-storage machine units across a number
        of zones equal to the configured minimum replicas.  This allows for a
        single swift-storage service unit, with each 'add-unit'd machine unit
        being assigned to a different zone.
    '''
    if assignment_policy == 'manual':
        return relation_get('zone')
    elif assignment_policy == 'auto':
        potential_zones = []
        for ring in SWIFT_RINGS.itervalues():
            builder = _load_builder(ring)
            potential_zones.append(_get_zone(builder))
        return set(potential_zones).pop()
    else:
        log('Invalid zone assignment policy: %s' % assignment_policy,
            level=ERROR)
        sys.exit(1)


def balance_ring(ring_path):
    '''balance a ring.  return True if it needs redistribution'''
    # shell out to swift-ring-builder instead, since the balancing code there
    # does a bunch of un-importable validation.'''
    cmd = ['swift-ring-builder', ring_path, 'rebalance']
    p = subprocess.Popen(cmd)
    p.communicate()
    rc = p.returncode
    if rc == 0:
        return True
    elif rc == 1:
        # swift-ring-builder returns 1 on WARNING (ring didn't require balance)
        return False
    else:
        log('balance_ring: %s returned %s' % (cmd, rc), level=ERROR)
        sys.exit(1)


def should_balance(rings):
    '''Based on zones vs min. replicas, determine whether or not the rings
       should be balanaced during initial configuration.'''
    do_rebalance = True
    for ring in rings:
        zones = []
        r = _load_builder(ring).to_dict()
        replicas = r['replicas']
        zones = [d['zone'] for d in r['devs']]
        if len(set(zones)) < replicas:
            do_rebalance = False
    return do_rebalance


def do_openstack_upgrade(source, packages):
    openstack.configure_installation_source(source)
    apt_update(fatal=True)
    apt_install(options=['--option', 'Dpkg::Options::=--force-confnew'],
                packages=packages,
                fatal=True)

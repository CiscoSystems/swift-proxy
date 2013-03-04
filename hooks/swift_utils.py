import os
import pwd
import subprocess
import lib.openstack_common as openstack
import utils

# Various config files that are managed via templating.
SWIFT_HASH_FILE='/var/lib/juju/swift-hash-path.conf'
SWIFT_CONF = '/etc/swift/swift.conf'
SWIFT_PROXY_CONF = '/etc/swift/proxy-server.conf'
SWIFT_CONF_DIR = os.path.dirname(SWIFT_CONF)
MEMCACHED_CONF = '/etc/memcached.conf'
APACHE_CONF = '/etc/apache2/conf.d/swift-rings'

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

# Folsom-specific packages
FOLSOM_PACKAGES = BASE_PACKAGES + ['swift-plugin-s3']

def proxy_control(action):
    '''utility to work around swift-init's bad RCs.'''
    def _cmd(action):
        return ['swift-init', 'proxy-server', action]

    p = subprocess.Popen(_cmd('status'), stdout=subprocess.PIPE)
    p.communicate()
    status = p.returncode
    if action == 'stop':
        if status == 1:
            return
        elif status == 0:
            return subprocess.check_call(_cmd('stop'))

    # the proxy will not start unless there are balanced rings, gzip'd in /etc/swift
    missing=False
    for k in SWIFT_RINGS.keys():
        if not os.path.exists(os.path.join(SWIFT_CONF_DIR, '%s.ring.gz' % k)):
            missing = True
    if missing:
        utils.juju_log('INFO', 'Rings not balanced, skipping %s.' % action)
        return

    if action == 'start':
        if status == 0:
            return
        elif status == 1:
            return subprocess.check_call(_cmd('start'))
    elif action == 'restart':
        if status == 0:
            return subprocess.check_call(_cmd('restart'))
        elif status == 1:
            return subprocess.check_call(_cmd('start'))

def swift_user(username='swift'):
    user = pwd.getpwnam('swift')
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


def render_config(config_file, context):
    '''write out config using templates for a specific openstack release.'''
    os_release = openstack.get_os_codename_package('python-swift')
    # load os release-specific templates.
    cfile = os.path.basename(config_file)
    templates_dir = os.path.join(utils.TEMPLATES_DIR, os_release)
    context['os_release'] = os_release
    return utils.render_template(cfile, context, templates_dir)


def get_swift_hash():
    if os.path.isfile(SWIFT_HASH_FILE):
        with open(SWIFT_HASH_FILE, 'r') as hashfile:
            swift_hash = hashfile.read().strip()
    elif utils.config_get('swift-hash'):
        swift_hash = utils.config_get('swift-hash')
        with open(SWIFT_HASH_FILE, 'w') as hashfile:
            hashfile.write(swift_hash)
    else:
        cmd = ['od', '-t', 'x8', '-N', '8', '-A', 'n']
        rand = open('/dev/random', 'r')
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=rand)
        swift_hash = p.communicate()[0].strip()
        with open(SWIFT_HASH_FILE, 'w') as hashfile:
            hashfile.write(swift_hash)
    return swift_hash


def get_keystone_auth():
    '''return standard keystone auth credentials, either from config or the
       identity-service relation.  user-specified config is given priority
       over an existing relation.
    '''
    auth_type = utils.config_get('auth-type')
    auth_host = utils.config_get('keystone-auth-host')
    admin_user = utils.config_get('keystone-admin-user')
    admin_password = utils.config_get('keystone-admin-user')
    if (auth_type == 'keystone' and auth_host
        and admin_user and admin_password):
        utils.juju_log('INFO', 'Using user-specified Keystone configuration.')
        ks_auth = {
            'auth_type': 'keystone',
            'auth_protocol': utils.config_get('keystone-auth-protocol'),
            'keystone_host': auth_host,
            'auth_port': utils.config_get('keystone-auth-port'),
            'service_user': admin_user,
            'service_password': admin_password,
            'service_tenant': utils.config_get('keystone-admin-tenant-name')
        }
        return ks_auth

    for relid in utils.relation_ids('identity-service'):
        utils.juju_log('INFO',
                       'Using Keystone configuration from identity-service.')
        for unit in utils.relation_list(relid):
            ks_auth = {
                'auth_type': 'keystone',
                'auth_protocol': 'http',
                'keystone_host': utils.relation_get('auth_host',
                                                    unit, relid),
                'auth_port': utils.relation_get('auth_port', unit, relid),
                'service_user': utils.relation_get('service_username', unit, relid),
                'service_password': utils.relation_get('service_password', unit, relid),
                'service_tenant': utils.relation_get('service_tenant', unit, relid),
                'service_port': utils.relation_get('service_port', unit, relid),
                'admin_token': utils.relation_get('admin_token', unit, relid),
            }
            if None not in ks_auth.itervalues():
                return ks_auth
    return None


def write_proxy_config():

    bind_port = utils.config_get('bind-port')
    workers = utils.config_get('workers')
    if workers == '0':
        import multiprocessing
        workers = multiprocessing.cpu_count()

    ctxt = {
        'proxy_ip': utils.get_host_ip(),
        'bind_port': utils.determine_api_port(bind_port),
        'workers': workers,
        'operator_roles': utils.config_get('operator-roles')
    }

    ctxt['ssl'] = False

    ks_auth = get_keystone_auth()
    if ks_auth:
        utils.juju_log('INFO', 'Enabling Keystone authentication.')
        for k, v in ks_auth.iteritems():
            ctxt[k] = v

    with open(SWIFT_PROXY_CONF, 'w') as conf:
        conf.write(render_config(SWIFT_PROXY_CONF, ctxt))

    proxy_control('restart')
    subprocess.check_call(['open-port', str(bind_port)])

def configure_ssl():
    # this should be expanded to cover setting up user-specified certificates
    if (utils.config_get('use-https') == 'yes' and
        not os.path.isfile(SSL_CERT) and
        not os.path.isfile(SSL_KEY)):
        subj = '/C=%s/ST=%s/L=%s/CN=%s' %\
               (utils.config_get('country'), utils.config_get('state'),
                utils.config_get('locale'), utils.config_get('common-name'))
        cmd = ['openssl', 'req', '-new', '-x509', '-nodes',
               '-out', SSL_CERT, '-keyout', SSL_KEY,
               '-subj', subj]
        subprocess.check_call(cmd)


def _load_builder(path):
    # lifted straight from /usr/bin/swift-ring-builder
    from swift.common.ring import RingBuilder, Ring
    import cPickle as pickle
    try:
        builder = pickle.load(open(path, 'rb'))
        if not hasattr(builder, 'devs'):
            builder_dict = builder
            builder = RingBuilder(1, 1, 1)
            builder.copy_from(builder_dict)
    except ImportError:  # Happens with really old builder pickles
        modules['swift.ring_builder'] = \
            modules['swift.common.ring.builder']
        builder = RingBuilder(1, 1, 1)
        builder.copy_from(pickle.load(open(argv[1], 'rb')))
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
    from swift.common.ring import RingBuilder, Ring
    ring = _load_builder(ring_path).to_dict()
    node['port'] = ring_port(ring_path, node)

    for dev in ring['devs']:
        d = [(i, dev[i]) for i in dev if i in node and i != 'zone']
        n = [(i, node[i]) for i in node if i in dev and i != 'zone']
        if sorted(d) == sorted(n):

            msg = 'Node already exists in ring (%s).' % ring_path
            utils.juju_log('INFO', msg)
            return True

    return False


def add_to_ring(ring_path, node):
    from swift.common.ring import RingBuilder, Ring
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
    msg = 'Added new device to ring %s: %s' % (ring_path,
                                               [k for k in new_dev.iteritems()])
    utils.juju_log('INFO', msg)


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
        return utils.relation_get('zone')
    elif assignment_policy == 'auto':
        potential_zones = []
        for ring in SWIFT_RINGS.itervalues():
            builder = _load_builder(ring)
            potential_zones.append(_get_zone(builder))
        return set(potential_zones).pop()
    else:
        utils.juju_log('Invalid zone assignment policy: %s' %\
                       assignemnt_policy)
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
        utils.juju_log('balance_ring: %s returned %s' % (cmd, rc))
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


def write_apache_config():
    '''write out /etc/apache2/conf.d/swift-rings with a list of authenticated
       hosts'''
    utils.juju_log('INFO', 'Updating %s.' % APACHE_CONF)

    allowed_hosts = []
    for relid in utils.relation_ids('swift-storage'):
        for unit in utils.relation_list(relid):
            host = utils.relation_get('private-address', unit, relid)
            allowed_hosts.append(utils.get_host_ip(host))

    ctxt = { 'www_dir': WWW_DIR, 'allowed_hosts': allowed_hosts }
    with open(APACHE_CONF, 'w') as conf:
        conf.write(render_config(APACHE_CONF, ctxt))
    subprocess.check_call(['service', 'apache2', 'reload'])


def configure_haproxy():
    api_port = utils.config_get('bind-port')
    service_ports = {
        "swift": [
            utils.determine_haproxy_port(api_port),
            utils.determine_api_port(api_port)
            ]
        }
    write_proxy_config()
    utils.configure_haproxy(service_ports)


def configure_https():
    if utils.https():
        api_port = utils.config_get('bind-port')
        if (len(utils.peer_units()) > 0 or
            utils.is_clustered()):
            target_port = utils.determine_haproxy_port(api_port)
            configure_haproxy()
        else:
            target_port = utils.determine_api_port(api_port)
            write_proxy_config()
        utils.setup_https(namespace="swift",
                          port_maps={api_port: target_port})
    else:
        return False

from charmhelpers.core.hookenv import (
    config,
    log,
    relation_ids,
    related_units,
    relation_get,
    unit_get
)

from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    ApacheSSLContext as SSLContext,
    context_complete,
    CA_CERT_PATH
)

from charmhelpers.contrib.hahelpers.cluster import (
    determine_api_port,
    determine_haproxy_port,
)

from charmhelpers.contrib.openstack.utils import get_host_ip
import subprocess
import os


from charmhelpers.contrib.hahelpers.apache import (
    get_cert,
    get_ca_cert,
)

from base64 import b64decode, b64encode


class HAProxyContext(OSContextGenerator):
    interfaces = ['cluster']

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend cinder.conf context with correct api_listening_port
        '''
        haproxy_port = determine_haproxy_port(config('bind-port'))
        api_port = determine_api_port(config('bind-port'))

        ctxt = {
            'service_ports': {'swift_api': [haproxy_port, api_port]},
        }
        return ctxt


WWW_DIR = '/var/www/swift-rings'


def generate_cert():
    '''
    Generates a self signed certificate and key using the
    provided charm configuration data.

    returns: tuple of (cert, key)
    '''
    CERT = '/etc/swift/ssl.cert'
    KEY = '/etc/swift/ssl.key'
    if not os.path.exists(CERT) and not os.path.exists(KEY):
        subj = '/C=%s/ST=%s/L=%s/CN=%s' %\
            (config('country'), config('state'),
             config('locale'), config('common-name'))
        cmd = ['openssl', 'req', '-new', '-x509', '-nodes',
               '-out', CERT, '-keyout', KEY,
               '-subj', subj]
        subprocess.check_call(cmd)
        os.chmod(KEY, 0600)
    # Slurp as base64 encoded - makes handling easier up the stack
    with open(CERT, 'r') as cfile:
        ssl_cert = b64encode(cfile.read())
    with open(KEY, 'r') as kfile:
        ssl_key = b64encode(kfile.read())
    return (ssl_cert, ssl_key)


class ApacheSSLContext(SSLContext):
    interfaces = ['https']
    external_ports = [config('bind-port')]
    service_namespace = 'swift'

    def configure_cert(self):
        if not os.path.isdir('/etc/apache2/ssl'):
            os.mkdir('/etc/apache2/ssl')
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.service_namespace)
        if not os.path.isdir(ssl_dir):
            os.mkdir(ssl_dir)
        cert, key = get_cert()
        # Swift specific - generate a cert by default if not using
        # a) user supplied cert or b) keystone signed cert
        if None in [cert, key]:
            cert, key = generate_cert()
        with open(os.path.join(ssl_dir, 'cert'), 'w') as cert_out:
            cert_out.write(b64decode(cert))
        with open(os.path.join(ssl_dir, 'key'), 'w') as key_out:
            key_out.write(b64decode(key))
        ca_cert = get_ca_cert()
        if ca_cert:
            with open(CA_CERT_PATH, 'w') as ca_out:
                ca_out.write(b64decode(ca_cert))
            subprocess.check_call(['update-ca-certificates'])

    def __call__(self):
        return super(ApacheSSLContext, self).__call__()


class SwiftRingContext(OSContextGenerator):
    def __call__(self):
        allowed_hosts = []
        for relid in relation_ids('swift-storage'):
            for unit in related_units(relid):
                host = relation_get('private-address', unit, relid)
                allowed_hosts.append(get_host_ip(host))

        ctxt = {
            'www_dir': WWW_DIR,
            'allowed_hosts': allowed_hosts
        }
        return ctxt


class SwiftIdentityContext(OSContextGenerator):
    interfaces = ['identity-service']

    def __call__(self):
        bind_port = config('bind-port')
        workers = config('workers')
        if workers == '0':
            import multiprocessing
            workers = multiprocessing.cpu_count()
        ctxt = {
            'proxy_ip': get_host_ip(unit_get('private-address')),
            'bind_port': determine_api_port(bind_port),
            'workers': workers,
            'operator_roles': config('operator-roles'),
            'delay_auth_decision': config('delay-auth-decision')
        }

        ctxt['ssl'] = False

        auth_type = config('auth-type')
        auth_host = config('keystone-auth-host')
        admin_user = config('keystone-admin-user')
        admin_password = config('keystone-admin-user')
        if (auth_type == 'keystone' and auth_host
            and admin_user and admin_password):
            log('Using user-specified Keystone configuration.')
            ks_auth = {
                'auth_type': 'keystone',
                'auth_protocol': config('keystone-auth-protocol'),
                'keystone_host': auth_host,
                'auth_port': config('keystone-auth-port'),
                'service_user': admin_user,
                'service_password': admin_password,
                'service_tenant': config('keystone-admin-tenant-name')
            }
            ctxt.update(ks_auth)

        for relid in relation_ids('identity-service'):
            log('Using Keystone configuration from identity-service.')
            for unit in related_units(relid):
                ks_auth = {
                    'auth_type': 'keystone',
                    'auth_protocol': 'http',  # TODO: http hardcode
                    'keystone_host': relation_get('auth_host',
                                                  unit, relid),
                    'auth_port': relation_get('auth_port',
                                              unit, relid),
                    'service_user': relation_get('service_username',
                                                 unit, relid),
                    'service_password': relation_get('service_password',
                                                     unit, relid),
                    'service_tenant': relation_get('service_tenant',
                                                   unit, relid),
                    'service_port': relation_get('service_port',
                                                 unit, relid),
                    'admin_token': relation_get('admin_token',
                                                unit, relid),
                }
                if context_complete(ks_auth):
                    ctxt.update(ks_auth)
        return ctxt


class MemcachedContext(OSContextGenerator):
    def __call__(self):
        ctxt = {
            'proxy_ip': get_host_ip(unit_get('private-address'))
        }
        return ctxt

SWIFT_HASH_FILE = '/var/lib/juju/swift-hash-path.conf'


def get_swift_hash():
    if os.path.isfile(SWIFT_HASH_FILE):
        with open(SWIFT_HASH_FILE, 'r') as hashfile:
            swift_hash = hashfile.read().strip()
    elif config('swift-hash'):
        swift_hash = config('swift-hash')
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


class SwiftHashContext(OSContextGenerator):
    def __call__(self):
        ctxt = {
            'swift_hash': get_swift_hash()
        }
        return ctxt

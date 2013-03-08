
#
# Copyright 2012 Canonical Ltd.
#
# Authors:
#  James Page <james.page@ubuntu.com>
#  Paul Collins <paul.collins@canonical.com>
#

import json
import os
import subprocess
import socket
import sys
import base64
import tempfile


def do_hooks(hooks):
    hook = os.path.basename(sys.argv[0])

    try:
        hook_func = hooks[hook]
    except KeyError:
        juju_log('INFO',
                 "This charm doesn't know how to handle '{}'.".format(hook))
    else:
        hook_func()


def install(*pkgs):
    cmd = [
        'apt-get',
        '-y',
        'install'
          ]
    for pkg in pkgs:
        cmd.append(pkg)
    subprocess.check_call(cmd)

TEMPLATES_DIR = 'hooks/templates'

try:
    import jinja2
except ImportError:
    install('python-jinja2')
    import jinja2

try:
    import dns.resolver
    import dns.ipv4
except ImportError:
    install('python-dnspython')
    import dns.resolver
    import dns.ipv4


def render_template(template_name, context, template_dir=TEMPLATES_DIR):
    templates = jinja2.Environment(
                    loader=jinja2.FileSystemLoader(template_dir)
                    )
    template = templates.get_template(template_name)
    return template.render(context)

CLOUD_ARCHIVE = \
""" # Ubuntu Cloud Archive
deb http://ubuntu-cloud.archive.canonical.com/ubuntu {} main
"""

CLOUD_ARCHIVE_POCKETS = {
    'folsom': 'precise-updates/folsom',
    'folsom/updates': 'precise-updates/folsom',
    'folsom/proposed': 'precise-proposed/folsom'
    }


def configure_source():
    source = str(config_get('openstack-origin'))
    if not source:
        return
    if source.startswith('ppa:'):
        cmd = [
            'add-apt-repository',
            source
            ]
        subprocess.check_call(cmd)
    if source.startswith('cloud:'):
        install('ubuntu-cloud-keyring')
        pocket = source.split(':')[1]
        with open('/etc/apt/sources.list.d/cloud-archive.list', 'w') as apt:
            apt.write(CLOUD_ARCHIVE.format(CLOUD_ARCHIVE_POCKETS[pocket]))
    if source.startswith('deb'):
        l = len(source.split('|'))
        if l == 2:
            (apt_line, key) = source.split('|')
            cmd = [
                'apt-key',
                'adv', '--keyserver keyserver.ubuntu.com',
                '--recv-keys', key
                ]
            subprocess.check_call(cmd)
        elif l == 1:
            apt_line = source

        with open('/etc/apt/sources.list.d/quantum.list', 'w') as apt:
            apt.write(apt_line + "\n")
    cmd = [
        'apt-get',
        'update'
        ]
    subprocess.check_call(cmd)

# Protocols
TCP = 'TCP'
UDP = 'UDP'


def expose(port, protocol='TCP'):
    cmd = [
        'open-port',
        '{}/{}'.format(port, protocol)
        ]
    subprocess.check_call(cmd)


def juju_log(severity, message):
    cmd = [
        'juju-log',
        '--log-level', severity,
        message
        ]
    subprocess.check_call(cmd)


def relation_ids(relation):
    cmd = [
        'relation-ids',
        relation
        ]
    result = str(subprocess.check_output(cmd)).split()
    if result == "":
        return None
    else:
        return result


def relation_list(rid):
    cmd = [
        'relation-list',
        '-r', rid,
        ]
    result = str(subprocess.check_output(cmd)).split()
    if result == "":
        return None
    else:
        return result


def relation_get(attribute, unit=None, rid=None):
    cmd = [
        'relation-get',
        ]
    if rid:
        cmd.append('-r')
        cmd.append(rid)
    cmd.append(attribute)
    if unit:
        cmd.append(unit)
    value = subprocess.check_output(cmd).strip()  # IGNORE:E1103
    if value == "":
        return None
    else:
        return value


def relation_set(**kwargs):
    cmd = [
        'relation-set'
        ]
    args = []
    for k, v in kwargs.items():
        if k == 'rid':
            if v:
                cmd.append('-r')
                cmd.append(v)
        else:
            args.append('{}={}'.format(k, v))
    cmd += args
    subprocess.check_call(cmd)


def unit_get(attribute):
    cmd = [
        'unit-get',
        attribute
        ]
    value = subprocess.check_output(cmd).strip()  # IGNORE:E1103
    if value == "":
        return None
    else:
        return value


def config_get(attribute):
    cmd = [
        'config-get',
        '--format',
        'json',
        ]
    out = subprocess.check_output(cmd).strip()  # IGNORE:E1103
    cfg = json.loads(out)

    try:
        return cfg[attribute]
    except KeyError:
        return None


def get_unit_hostname():
    return socket.gethostname()


def get_host_ip(hostname=unit_get('private-address')):
    try:
        # Test to see if already an IPv4 address
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        answers = dns.resolver.query(hostname, 'A')
        if answers:
            return answers[0].address
    return None


def restart(*services):
    for service in services:
        subprocess.check_call(['service', service, 'restart'])


def stop(*services):
    for service in services:
        subprocess.check_call(['service', service, 'stop'])


def start(*services):
    for service in services:
        subprocess.check_call(['service', service, 'start'])


def reload(*services):
    for service in services:
        try:
            subprocess.check_call(['service', service, 'reload'])
        except subprocess.CalledProcessError:
            # Reload failed - either service does not support reload
            # or it was not running - restart will fixup most things
            subprocess.check_call(['service', service, 'restart'])


def is_clustered():
    for r_id in (relation_ids('ha') or []):
        for unit in (relation_list(r_id) or []):
            clustered = relation_get('clustered',
                                     rid=r_id,
                                     unit=unit)
            if clustered:
                return True
    return False


def is_leader():
    cmd = [
        "crm", "resource",
        "show", "res_swift_vip"
        ]
    try:
        status = subprocess.check_output(cmd)
    except subprocess.CalledProcessError:
        return False
    else:
        if get_unit_hostname() in status:
            return True
        else:
            return False


def peer_units():
    peers = []
    for r_id in (relation_ids('cluster') or []):
        for unit in (relation_list(r_id) or []):
            peers.append(unit)
    return peers


def oldest_peer(peers):
    local_unit_no = os.getenv('JUJU_UNIT_NAME').split('/')[1]
    for peer in peers:
        remote_unit_no = peer.split('/')[1]
        if remote_unit_no < local_unit_no:
            return False
    return True


def eligible_leader():
    if is_clustered():
        if not is_leader():
            juju_log('INFO', 'Deferring action to CRM leader.')
            return False
    else:
        peers = peer_units()
        if peers and not oldest_peer(peers):
            juju_log('INFO', 'Deferring action to oldest service unit.')
            return False
    return True


def https():
    '''
    Determines whether enough data has been provided in configuration
    or relation data to configure HTTPS
    .
    returns: boolean
    '''
    if config_get('use-https'):
        return True
    if config_get('ssl_cert') and config_get('ssl_key'):
        return True
    for r_id in relation_ids('identity-service'):
        for unit in relation_list(r_id):
            if (relation_get('https_keystone', rid=r_id, unit=unit) and
                relation_get('ssl_cert', rid=r_id, unit=unit) and
                relation_get('ssl_key', rid=r_id, unit=unit) and
                relation_get('ca_cert', rid=r_id, unit=unit)):
                return True
    return False


APACHE_SITE_DIR = "/etc/apache2/sites-available"
SITE_TEMPLATE = "apache2_site.tmpl"
RELOAD_CHECK = "To activate the new configuration"


def enable_https(port_maps, namespace):
    '''
    For a given number of port mappings, configures apache2
    HTTPs local reverse proxying using certficates and keys provided in
    either configuration data (preferred) or relation data.  Assumes ports
    are not in use (calling charm should ensure that).

    port_maps: dict: external to internal port mappings
    namespace: str: name of charm
    '''
    juju_log('INFO', "Enabling HTTPS for port mappings: {}".format(port_maps))
    http_restart = False
    # allow overriding of keystone provided certs with those set manually
    # in config.
    cert = config_get('ssl_cert')
    key = config_get('ssl_key')
    ca_cert = None
    if not (cert and key):
        juju_log('INFO',
                 "Inspecting identity-service relations for SSL certificate.")
        cert = key = ca_cert = None
        for r_id in relation_ids('identity-service'):
            for unit in relation_list(r_id):
                if not cert:
                    cert = relation_get('ssl_cert', rid=r_id, unit=unit)
                if not key:
                    key = relation_get('ssl_key', rid=r_id, unit=unit)
                if not ca_cert:
                    ca_cert = relation_get('ca_cert', rid=r_id, unit=unit)
        if (not (cert and key and ca_cert) and
            config_get('use-https')):
            juju_log('INFO',
                     "Using self-signed SSL certificate.")
            (cert, key) = generate_cert()
    else:
        juju_log('INFO',
                 "Using SSL certificate provided in service config.")

    if cert:
        cert = base64.b64decode(cert)
    if key:
        key = base64.b64decode(key)
    if ca_cert:
        ca_cert = base64.b64decode(ca_cert)

    if not cert and not key:
        juju_log('ERROR',
                 "Expected but could not find SSL certificate data, not "
                 "configuring HTTPS!")
        return False

    install('apache2')
    if RELOAD_CHECK in subprocess.check_output(['a2enmod', 'ssl',
                                                'proxy', 'proxy_http']):
        http_restart = True

    ssl_dir = os.path.join('/etc/apache2/ssl', namespace)
    if not os.path.exists(ssl_dir):
        os.makedirs(ssl_dir)
    with open(os.path.join(ssl_dir, 'cert'), 'w') as fcert:
        fcert.write(cert)
    with open(os.path.join(ssl_dir, 'key'), 'w') as fkey:
        fkey.write(key)
    if ca_cert:
        with open('/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt',
                  'w') as crt:
            crt.write(ca_cert)
        subprocess.check_call(['update-ca-certificates', '--fresh'])

    sites_dir = '/etc/apache2/sites-available'
    for ext_port, int_port in port_maps.items():
        juju_log('INFO',
                 'Creating apache2 reverse proxy vhost'
                 ' for {}:{}'.format(ext_port,
                                     int_port))
        site = "{}_{}".format(namespace, ext_port)
        site_path = os.path.join(sites_dir, site)
        with open(site_path, 'w') as fsite:
            context = {
                "ext": ext_port,
                "int": int_port,
                "namespace": namespace,
                "private_address": get_host_ip()
                }
            fsite.write(render_template(SITE_TEMPLATE,
                                        context))

        if RELOAD_CHECK in subprocess.check_output(['a2ensite', site]):
            http_restart = True

    if http_restart:
        restart('apache2')

    return True


def disable_https(port_maps, namespace):
    '''
    Ensure HTTPS reverse proxying is disables for given port mappings

    port_maps: dict: of ext -> int port mappings
    namespace: str: name of chamr
    '''
    juju_log('INFO', 'Ensuring HTTPS disabled for {}'.format(port_maps))

    if (not os.path.exists('/etc/apache2') or
        not os.path.exists(os.path.join('/etc/apache2/ssl', namespace))):
        return

    http_restart = False
    for ext_port in port_maps.keys():
        if os.path.exists(os.path.join(APACHE_SITE_DIR,
                                       "{}_{}".format(namespace,
                                                      ext_port))):
            juju_log('INFO',
                     "Disabling HTTPS reverse proxy"
                     " for {} {}.".format(namespace,
                                          ext_port))
            if (RELOAD_CHECK in
                subprocess.check_output(['a2dissite',
                                         '{}_{}'.format(namespace,
                                                        ext_port)])):
                http_restart = True

    if http_restart:
        restart(['apache2'])


def setup_https(port_maps, namespace):
    '''
    Ensures HTTPS is either enabled or disabled for given port
    mapping.

    port_maps: dict: of ext -> int port mappings
    namespace: str: name of charm
    '''
    if not https:
        disable_https(port_maps, namespace)
    else:
        enable_https(port_maps, namespace)


def generate_cert():
    '''
    Generates a self signed certificate and key using the
    provided charm configuration data.

    returns: tuple of (cert, key)
    '''
    CERT = '/etc/swift/ssl.cert'
    KEY = '/etc/swift/ssl.key'
    if (not os.path.exists(CERT) and
        not os.path.exists(KEY)):
        subj = '/C=%s/ST=%s/L=%s/CN=%s' %\
            (config_get('country'), config_get('state'),
             config_get('locale'), config_get('common-name'))
        cmd = ['openssl', 'req', '-new', '-x509', '-nodes',
               '-out', CERT, '-keyout', KEY,
               '-subj', subj]
        subprocess.check_call(cmd)
    # Slurp as base64 encoded - makes handling easier up the stack
    with open(CERT, 'r') as cfile:
        ssl_cert = base64.b64encode(cfile.read())
    with open(KEY, 'r') as kfile:
        ssl_key = base64.b64encode(kfile.read())
    return (ssl_cert, ssl_key)


def determine_api_port(public_port):
    '''
    Determine correct API server listening port based on
    existence of HTTPS reverse proxy and/or haproxy.

    public_port: int: standard public port for given service

    returns: int: the correct listening port for the API service
    '''
    i = 0
    if len(peer_units()) > 0 or is_clustered():
        i += 1
    if https():
        i += 1
    return public_port - (i * 10)


def determine_haproxy_port(public_port):
    '''
    Description: Determine correct proxy listening port based on public IP +
    existence of HTTPS reverse proxy.

    public_port: int: standard public port for given service

    returns: int: the correct listening port for the HAProxy service
    '''
    i = 0
    if https():
        i += 1
    return public_port - (i * 10)


HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
HAPROXY_DEFAULT = '/etc/default/haproxy'


def configure_haproxy(service_ports):
    '''
    Configure HAProxy based on the current peers in the service
    cluster using the provided port map:

        "swift": [ 8080, 8070 ]

    HAproxy will also be reloaded/started if required

    service_ports: dict: dict of lists of [ frontend, backend ]
    '''
    cluster_hosts = {}
    cluster_hosts[os.getenv('JUJU_UNIT_NAME').replace('/', '-')] = \
        unit_get('private-address')
    for r_id in relation_ids('cluster'):
        for unit in relation_list(r_id):
            cluster_hosts[unit.replace('/', '-')] = \
                relation_get(attribute='private-address',
                             rid=r_id,
                             unit=unit)
    context = {
        'units': cluster_hosts,
        'service_ports': service_ports
        }
    with open(HAPROXY_CONF, 'w') as f:
        f.write(render_template(os.path.basename(HAPROXY_CONF),
                                context))
    with open(HAPROXY_DEFAULT, 'w') as f:
        f.write('ENABLED=1')

    reload('haproxy')

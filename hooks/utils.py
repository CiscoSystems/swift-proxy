
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
    return subprocess.check_output(cmd).split()  # IGNORE:E1103


def relation_list(rid):
    cmd = [
        'relation-list',
        '-r', rid,
        ]
    return subprocess.check_output(cmd).split()  # IGNORE:E1103


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
        try:
            answers = dns.resolver.query(hostname, 'A')
            if answers:
                return answers[0].address
        except dns.resolver.NXDOMAIN:
            pass
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
        subprocess.check_call(['service', service, 'reload'])


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

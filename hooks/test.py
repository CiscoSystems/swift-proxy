#!/usr/bin/python
import lib.openstack_common as openstack
pkg = 'swift-proxy'
print openstack.get_os_codename_package(pkg)

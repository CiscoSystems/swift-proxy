import mock
import unittest

from jinja2 import Environment

from charmhelpers.contrib.openstack.templating import get_loader

class ProxyServerTemplateTestCase(unittest.TestCase):

    @mock.patch('charmhelpers.contrib.openstack.templating.log')
    def get_template_for_release(self, os_release, mock_log):
        loader = get_loader('./templates', 'essex')
        env = Environment(loader=loader)

        return env.get_template('proxy-server.conf')

    def test_essex_keystone_includes_correct_egg(self):
        """Regression test for bug 1251551."""
        template = self.get_template_for_release('essex')

        result = template.render(auth_type='keystone')

        self.assertIn("use = egg:swift#swift3", result)

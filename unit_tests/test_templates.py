import mock
import unittest

from jinja2 import Environment

from charmhelpers.contrib.openstack.templating import get_loader

class ProxyServerTemplateTestCase(unittest.TestCase):

    @mock.patch('charmhelpers.contrib.openstack.templating.log')
    def get_template_for_release(self, os_release, mock_log):
        loader = get_loader('./templates', os_release)
        env = Environment(loader=loader)

        return env.get_template('proxy-server.conf')

    def test_essex_keystone_includes_correct_egg(self):
        """Regression test for bug 1251551."""
        template = self.get_template_for_release('essex')

        result = template.render(auth_type='keystone')

        self.assertIn("use = egg:swift#swift3", result)

    def test_essex_keystone_includes_correct_delay_auth_true(self):
        """Regression test for bug 1251551."""
        template = self.get_template_for_release('essex')

        result = template.render(auth_type='keystone',
                                 delay_auth_decision='true')

        self.assertIn("delay_auth_decision = 1", result)

    def test_essex_keystone_includes_correct_delay_auth_false(self):
        """Regression test for bug 1251551."""
        template = self.get_template_for_release('essex')

        result = template.render(auth_type='keystone',
                                 delay_auth_decision='anything')

        self.assertIn("delay_auth_decision = 0", result)

    def test_os_release_not_in_templates(self):
        """Regression test for bug 1251551.

        The os_release is no longer provided as context to the templates.
        """
        for release in ('essex', 'grizzly', 'havana'):
            template = self.get_template_for_release(release)
            with open(template.filename, 'r') as template_orig:
                self.assertNotIn('os_release', template_orig.read())

    def test_config_renders_for_all_releases(self):
        """The configs render without syntax error."""
        for release in ('essex', 'grizzly', 'havana'):
            template = self.get_template_for_release(release)

            result = template.render()

            self.assertTrue(result.startswith("[DEFAULT]"))

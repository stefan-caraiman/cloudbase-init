from cloudbaseinit.plugins.windows import displayidletimeout
from cloudbaseinit.tests import testutils

import mock
import unittest


class DisplayIdleTimeoutConfigPluginTests(unittest.TestCase):
	def setUp(self):
		module_path = 'cloudbaseinit.plugins.windows.displayidletimeout'
		self._displayplugin = displayidletimeout.DisplayIdleTimeoutConfigPlugin()
		self.snatcher = testutils.LogSnatcher(module_path)

	def test_get_os_requirements(self):
		result = self._displayplugin.get_os_requirements()
		self.assertEqual(result, ('win32', (6, 2)))

	@mock.patch('cloudbaseinit.utils.windows.powercfg.set_display_idle_timeout')
	def test_execute(self, mock_set_display):
		expected_logging = [
			"Setting display idle timeout: %s" % 
			displayidletimeout.CONF.display_idle_timeout
		]

		with self.snatcher:
			result = self._displayplugin.execute(mock.sentinel, mock.sentinel)
		self.assertEqual(self.snatcher.output, expected_logging)
		self.assertEqual(result, 
			(displayidletimeout.base.PLUGIN_EXECUTION_DONE, False))
		mock_set_display.assert_called_once_with(
			displayidletimeout.CONF.display_idle_timeout)

from cloudbaseinit.plugins.common import trim
from cloudbaseinit.tests import testutils

import mock
import unittest

CONF = trim.CONF


class TrimConfigPluginTest(unittest.TestCase):
	def setUp(self):
		module_path = "cloudbaseinit.plugins.common.trim"
		self._trim = trim.TrimConfigPlugin()
		self.snatcher = testutils.LogSnatcher(module_path)

	def test_get_os_requirements(self):
		result = self._trim.get_os_requirements()
		self.assertEqual(result, ('win32', (6, 1)))

	@testutils.ConfPatcher('trim_enabled', True)
	@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
	def test_execute(self, mock_get_osutils):
		mock_osutils = mock.Mock()
		mock_get_osutils.return_value = mock_osutils
		mock_osutils.enable_trim.return_value = None

		expected_logging = [
			"TRIM enabled: %s" % CONF.trim_enabled
		]

		with self.snatcher:
			result = self._trim.execute(None, None)
		mock_osutils.enable_trim.assert_called_once_with(True)
		self.assertEqual(result, (trim.plugin_base.PLUGIN_EXECUTION_DONE, False))
		self.assertEqual(self.snatcher.output, expected_logging)


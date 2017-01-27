from cloudbaseinit.tests import testutils
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.windows import bootconfig


import mock
import unittest


class BootConfigPluginTests(unittest.TestCase):
	@mock.patch('cloudbaseinit.plugins.windows.bootconfig.base.BasePlugin')
	def setUp(self, _):
		module_path = 'cloudbaseinit.plugins.windows.bootconfig'
		self._bootconfig = bootconfig.BootConfigPlugin()
		self.snatcher = testutils.LogSnatcher(module_path)


	@mock.patch('cloudbaseinit.plugins.windows.bootconfig.disk.Disk')
	def test_set_unique_disk_id(self, mock_disk):
		phys_disk_path = "fake path"
		expected_logging = [
			"Setting unique id on disk: %s" % phys_disk_path
		]
		with self.snatcher:
			bootconfig.BootConfigPlugin._set_unique_disk_id(phys_disk_path)
		self.assertEqual(expected_logging, self.snatcher.output)
		mock_disk.assert_called_once_with(phys_disk_path, allow_write=True)
	
	def test_get_os_requirements(self):
		result = self._bootconfig.get_os_requirements()
		self.assertEqual(result, ('win32', (6, 0)))

	@mock.patch('cloudbaseinit.utils.windows.bootconfig.enable_auto_recovery')
	@mock.patch('cloudbaseinit.utils.windows.bootconfig.set_current_bcd_device_to_boot_partition')
	@mock.patch('cloudbaseinit.utils.windows.bootconfig.set_boot_status_policy')
	@mock.patch('cloudbaseinit.utils.windows.bootconfig.get_boot_system_devices')
	def _test_execute(self, mock_get_devices, mock_set_policy, mock_set_partition,
					  auto_recovery, boot_policy=True, unique_id=True, devices_no=1):
		bootconfig.CONF.bcd_boot_status_policy = boot_policy
		bootconfig.CONF.set_unique_boot_disk_id = unique_id
		expected_logging = []
		if boot_policy:
			expected_logging.append("Configure boot policy: %s" % boot_policy)
		if unique_id:
			mock_get_devices.return_value = [mock.sentinel] * devices_no
			if devices_no == 1:
				expected_logging.append("Configuring boot device")
			self._bootconfig._set_unique_disk_id = mock.Mock()

		with self.snatcher:
			result = self._bootconfig.execute(mock.sentinel, mock.sentinel)

		self.assertEqual(expected_logging, self.snatcher.output)
		self.assertEqual(result, (base.PLUGIN_EXECUTION_DONE, False))

		if boot_policy:
			mock_set_policy.assert_called_once_with(boot_policy)
		else:
			self.assertEqual(0, mock_set_policy.call_count)
		if unique_id:
			if devices_no == 1:
				mock_set_partition.assert_called_once_with()
				self._bootconfig._set_unique_disk_id.assert_called_once_with(
					u"\\\\.\\PHYSICALDRIVE0")
			else:
				self.assertEqual(0, mock_set_partition.call_count)
				self.assertEqual(0, self._bootconfig._set_unique_disk_id.call_count)
		else:
			self.assertEquals(mock_get_devices.call_count, 0)

		auto_recovery.assert_called_once_with(bootconfig.CONF.bcd_enable_auto_recovery)

	def test_execute(self):
		self._test_execute()

	def test_execute_no_boot_policy(self):
		self._test_execute(boot_policy=None)

	def test_execute_no_unique_id(self):
		self._test_execute(unique_id=False)

	def test_execute_more_boot_system_devices(self):
		self._test_execute(devices_no=5)

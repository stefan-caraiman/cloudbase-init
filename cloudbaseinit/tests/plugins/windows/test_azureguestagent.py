from cloudbaseinit import exception
from cloudbaseinit.tests import testutils
from cloudbaseinit.plugins.windows import azureguestagent

import datetime
import importlib
import mock
import traceback
import unittest




class AzureGuestAgentPluginTests(unittest.TestCase):
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'os.path.exists')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os.path.join')
	def setUp(self, mock_join, mock_exists):
		self.mock_exists = mock_exists
		self.mock_join = mock_join
		module_path = "cloudbaseinit.plugins.windows.azureguestagent"
		self._azure_agent = azureguestagent.AzureGuestAgentPlugin()
		self.snatcher = testutils.LogSnatcher(module_path)

	def _test_check_delete_service(self, service_exists=True,
								   service_stop=True):
		mock_osutils = mock.Mock()
		mock_service_name = mock.sentinel
		mock_osutils.check_service_exists.return_value = service_exists
		mock_osutils.SERVICE_STATUS_STOPPED = True
		mock_osutils.get_service_status.return_value = not service_stop
		azureguestagent.AzureGuestAgentPlugin._check_delete_service(mock_osutils, mock_service_name)

		
		mock_osutils.check_service_exists.assert_called_once_with(mock_service_name)
		
		
		if service_exists:
			mock_osutils.get_service_status.assert_called_once_with(mock_service_name)
			if service_stop:
				mock_osutils.stop_service.assert_called_once_with(mock_service_name, wait=True)
			else:
				self.assertEqual(mock_osutils.stop_service.call_count, 0)
			mock_osutils.delete_service.assert_called_once_with(mock_service_name)
		else:
			self.assertEquals(mock_osutils.get_service_status.call_count, 0)
			self.assertEquals(mock_osutils.delete_service.call_count, 0)

	def test_check_delete_service(self):
		self._test_check_delete_service()

	def test_check_delete_service_no_exists(self):
		self._test_check_delete_service(service_exists=False)


	def test_check_delete_service_stopped(self):
		self._test_check_delete_service(service_stop=True)

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._check_delete_service')
	def test_remove_agent_services(self, mock_check_delete):
		mock_osutils = mock.Mock()
		expected_output = [
			"Stopping and removing any existing Azure guest agent "
            "services"
		]
		with self.snatcher:
			azureguestagent.AzureGuestAgentPlugin._remove_agent_services(mock_osutils)
		self.assertEquals(mock_check_delete.call_count, 3)
		self.assertEqual(self.snatcher.output, expected_output)

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.shutil.rmtree')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os')
	def test_remove_azure_dirs(self, mock_os, mock_rmtree):
		mock_path = mock.Mock()
		mock_os.path = mock_path
		mock_path.join.side_effect = ["fake folder 1", "fake folder 2"]
		mock_path.exists.side_effect = [
			True, True
		]
		ex = Exception("fake exception")
		mock_rmtree.side_effect = [
			mock.sentinel,
			ex
		]
		expected_logging = [
			"Removing folder: %s" % "fake folder 1",
			"Removing folder: %s" % "fake folder 2",
			"Failed to remove path: %s" % "fake folder 2",
		]

		with testutils.LogSnatcher("cloudbaseinit.plugins.windows."
                                   "azureguestagent") as snatcher:
			azureguestagent.AzureGuestAgentPlugin._remove_azure_dirs()
		# self.assertEqual(snatcher.output, expected_logging)
		self.assertEqual(mock_path.join.call_count, 2)
		self.assertEqual(mock_path.exists.call_count, 2)
		self.assertEqual(mock_rmtree.call_count, 2)

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.REG_SZ')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.HKEY_LOCAL_MACHINE')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.SetValueEx')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.CreateKey')
	def test_set_registry_vm_type(self, mock_createkey, mock_setvalue, mock_HKLM,
								  mock_reg):
		azureguestagent.AzureGuestAgentPlugin._set_registry_vm_type()
		mock_createkey.assert_called_once_with(mock_HKLM, 
			"SOFTWARE\\Microsoft\\Windows Azure")
		mock_setvalue(mock_createkey.return_value, "VMType", 0, mock_reg, "IAAS")

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.REG_SZ')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.HKEY_LOCAL_MACHINE')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.SetValueEx')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.winreg.CreateKey')
	def test_set_registry_ga_params(self, mock_createkey, mock_setvalue, mock_HKLM,
								  mock_reg):
		mock_install_timestamp = mock.Mock()
		azureguestagent.AzureGuestAgentPlugin._set_registry_ga_params(
			('f', 'a', 'k', 'e'), mock_install_timestamp
			)
		mock_createkey.assert_called_once_with(mock_HKLM, 
			"SOFTWARE\\Microsoft\\GuestAgent")
		self.assertEquals(mock_setvalue.call_count, 2)
		mock_install_timestamp.strftime.assert_called_once_with('%m/%d/%Y %I:%M:%S %p')


	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._set_registry_ga_params')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._set_registry_vm_type')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.datetime.datetime', side_effect=mock.sentinel)
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os.path.join')
	def test_configure_rd_agent(self, mock_join, mock_datetime, mock_vm_type, mock_set_registry):
		mock_join.side_effect = join_sideeffect = [ mock.sentinel, mock.sentinel ] 
		mock_osutils = mock.Mock()
		mock_osutils.SERVICE_START_MODE_MANUAL = mock.sentinel
		mock_osutils.get_file_version.return_value = mock.sentinel
		ga_target_path = mock.sentinel
		mock_datetime.now.return_value = mock.sentinel

		azureguestagent.AzureGuestAgentPlugin._configure_rd_agent(mock_osutils, ga_target_path)

		self.assertEqual(mock_join.call_count, 2)
		mock_osutils.create_service.assert_called_once_with(
			azureguestagent.SERVICE_NAME_RDAGENT, azureguestagent.SERVICE_NAME_RDAGENT,
			join_sideeffect[0], mock_osutils.SERVICE_START_MODE_MANUAL
			)
		mock_osutils.get_file_version(join_sideeffect[1])
		mock_datetime.now.assert_called_once_with()
		mock_vm_type.assert_called_once_with()
		mock_set_registry.assert_called_once_with(
			mock_osutils.get_file_version.return_value,
			mock_datetime.now.return_value
			)

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._run_logman')
	def _test_event_trace(self, mock_logman, action, func, mock_etcs=None):
		mock_osutils = mock.Mock()
		mock_name = mock.sentinel
		
		if mock_etcs is None:
			func(mock_osutils, mock_name)
			mock_logman.assert_called_once_with(mock_osutils, action, mock_name)
		else:
			func(mock_osutils, mock_name, mock_etcs)
			mock_logman.assert_called_once_with(mock_osutils, action, mock_name, mock_etcs)

	def test_stop_event_trace(self):
		self._test_event_trace(
			action="stop", 
			func=azureguestagent.AzureGuestAgentPlugin._stop_event_trace,
			mock_etcs=mock.sentinel)

	def test_delete_event_trace(self):
		self._test_event_trace(
			action="delete",
			func=azureguestagent.AzureGuestAgentPlugin._delete_event_trace)

	def _test_run_logman(self, ets=False, error=True):
		mock_osutils = mock.Mock()
		action, name = "fake action", "fake name"
		out, err = "fake output", "fake error"
		ret_val = 0
		if error:
			ret_val = 1

		mock_osutils.execute_system32_process.return_value = (out, err, ret_val)
		expected_logging = []
		if error:
			expected_logging = [
				'logman failed.\nExit code: {ret_val}\n'
                'Output: {out}\nError: {err}'.format(
                ret_val=hex(ret_val), out=out, err=err)
			]
		with self.snatcher:
			azureguestagent.AzureGuestAgentPlugin._run_logman(
				mock_osutils, action, name, ets)
		self.assertEqual(expected_logging, self.snatcher.output)
		args = ["logman.exe"]
		if ets:
			args += ["-ets"]
		args += [action, name]
		mock_osutils.execute_system32_process.assert_called_once_with(args)

	def test_run_logman(self):
		self._test_run_logman()

	def test_run_logman_ets(self):
		self._test_run_logman(ets=True)

	def test_run_logman_no_error(self):
		self._test_run_logman(error=False)

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._stop_event_trace')
	def _test_ga_event_traces(self, mock_stop_trace, calls, expected_logging, func):
		mock_osutils = mock.Mock()
		with self.snatcher:
			func(mock_osutils)
		self.assertEqual(expected_logging, self.snatcher.output)
		self.assertEqual(calls, mock_stop_trace.call_count)

	def test_stop_ga_event_traces(self):
		func = azureguestagent.AzureGuestAgentPlugin._stop_ga_event_traces
		expected_logging = [
			"Stopping Azure guest agent event traces"
		]
		self._test_ga_event_traces(
			calls=4, expected_logging=expected_logging, func=func)

	def test_delete_ga_event_traces(self):
		func = azureguestagent.AzureGuestAgentPlugin._delete_ga_event_traces
		expected_logging = [
			"Deleting Azure guest agent event traces"
		]
		self._test_ga_event_traces(
			calls=2, expected_logging=expected_logging, func=func)
	
	def test_get_os_requirements(self):
		result = self._azure_agent.get_os_requirements()
		self.assertEqual(result, ('win32', (6, 1)))

	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os.path.exists')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os.path.join')
	def _test_get_guest_agent_source_path(self, mock_join, mock_exists, path_exists=True):
		mock_osutils = mock.Mock()
		count = 3
		mock_osutils.get_logical_drives.return_value = [mock.sentinel] * count
		mock_join.return_value = "fake path"
		if not path_exists:
			mock_exists.side_effect = [False] * count
		else:
			mock_exists.side_effect = [False] * (count - 1) + [True]

		if not path_exists:
			with self.assertRaises(exception.CloudbaseInitException) as exc:
				azureguestagent.AzureGuestAgentPlugin._get_guest_agent_source_path(mock_osutils)
			self.assertEqual(
				str(exc.exception), 
				"Azure guest agent source folder not found")
		else:
			result = azureguestagent.AzureGuestAgentPlugin._get_guest_agent_source_path(mock_osutils)

	def test_get_guest_agent_source_path_extists(self):
		self._test_get_guest_agent_source_path()

	def test_get_guest_agent_source_path_not_extists(self):
		self._test_get_guest_agent_source_path(path_exists=False)


	@mock.patch('shutil.rmtree')
	@mock.patch('zipfile.ZipFile')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._configure_rd_agent')
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._delete_ga_event_traces')	
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._stop_ga_event_traces')	
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.os')	
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._remove_azure_dirs')	
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._remove_agent_services')		
	@mock.patch('cloudbaseinit.plugins.windows.azureguestagent.'
				'AzureGuestAgentPlugin._get_guest_agent_source_path')
	@mock.patch('cloudbaseinit.osutils.factory')
	def _test_execute(self, mock_osutils_factory, mock_get_sourcepath,
					  mock_remove_agent, mock_remove_dirs, mock_os,
					  mock_stop_traces, mock_delete_traces, mock_rd_agent,
					  mock_zip_file, mock_rmtree,
					  provisioning_data=None, ga_zip_path_exists=True,
					  ga_target_path_exists=True, dotnet_installed=True):
		mock_path = mock.Mock()
		mock_os.path.return_value = mock_path
		ga_zip_path = "fake ga_zip_path"
		ga_target_path = "fake ga_target_path"
		mock_path.join.side_effect = [
			ga_zip_path,
			ga_target_path
		]
		executed = False
		mock_service = mock.Mock()
		mock_service.get_vm_agent_package_provisioning_data.return_value = \
				 provisioning_data
		if provisioning_data is None:
			expected_logging = [
				"Azure guest agent provisioning data not present"
			]
		elif not provisioning_data.get("provision"):
			expected_logging = [
				"Skipping Azure guest agent provisioning as by metadata "
                "request"
			]
		else:
			mock_osutils = mock.Mock()
			mock_osutils_factory.get_os_utils = mock_osutils
			mock_osutils.set_service_start_mode = mock.Mock()
			mock_osutils.start_service = mock.Mock()
			mock_osutils.SERVICE_START_MODE_AUTOMATIC = "fake mode"

			ga_package_name = provisioning_data.get("package_name")
			if not ga_package_name:
				ex = exception.ItemNotFoundException(
                    "Azure guest agent package_name not found in metadata")
				with self.assertRaises(exception.ItemNotFoundException) as exc:
					self._azure_agent.execute(mock_service, None)
					executed = True
				self.assertEqual(str(ex), str(exc.exception))
				return
			else:
				expected_logging = [
					"Azure guest agent package name: %s" % ga_package_name
				]

				mock_path.exists.return_value = ga_zip_path_exists
				if not ga_zip_path_exists:
					ex = exception.CloudbaseInitException(
	                    "Azure guest agent package file not found: %s" %
	                    ga_zip_path)
					with self.assertRaises(exception.CloudbaseInitException) as exc:
						self._azure_agent.execute(mock_service, mock.sentinel)
						executed = True
					self.assertEqual(str(ex), str(exc.exception))
				else:
					if not dotnet_installed:
						expected_logging += [
							"The .Net framework 4.5 is required by the Azure "
							"guest agent"
						]
		if not executed:
			with self.snatcher:
				result = self._azure_agent.execute(mock_service, None)
		
		self.assertEqual(self.snatcher.output, expected_logging)
		mock_service.get_vm_agent_package_provisioning_data.assert_called_once_with()

		if provisioning_data is not None and \
			provisioning_data.get("provision") is not None:
			mock_osutils_factory.get_os_utils.assert_called_once_with()
			mock_get_sourcepath.assert_called_once_with(mock_osutils)
			mock_remove_agent.assert_called_once_with(mock_osutils)
			mock_remove_dirs.assert_called_once_with()
			if ga_package_name is not None:
				if not ga_zip_path_exists:
					self.assertEqual(mock_osutils.join.call_count, 1)
				else:
					self.assertEqual(mock_osutils.join.call_count, 2)
					mock_stop_traces.assert_called_once_with(mock_osutils)
					mock_delete_traces.assert_called_once_with(mock_osutils)
					if ga_target_path_exists:
						mock_rmtree.assert_called_once_with(ga_target_path)
					mock_os.makedirs.assert_called_once_with(ga_target_path)
					mock_zip_file.assert_called_once_with()
					mock_zip_file.extract_all.assert_called_once_with(ga_target_path)
					mock_rd_agent.assert_called_once_with(mock_osutils, ga_target_path)
					if dotnet_installed:
						mock_osutils.set_service_start_mode.assert_called_once_with(
							azureguestagent.SERVICE_NAME_RDAGENT,
							mock_osutils.SERVICE_START_MODE_AUTOMATIC
							)
						mock_osutils.start_service.assert_called_once_with(
							azureguestagent.SERVICE_NAME_RDAGENT)


# provisioning_data=None, ga_zip_path_exists=True,
# 					  ga_target_path_exists=True, dotnet_installed=True


	def test_execute_provisioning_data_not_present(self):
		self._test_execute()

	def test_execute_skip_provisioning(self):
		self._test_execute(provisioning_data={"fake": "fake"})

	def test_execute_no_ga_package_name(self):
		self._test_execute(
			provisioning_data={
				"provision": "fake",
				"package_name": None
			}
		)

	def ztest_execute_ga_zip_path_not_exists(self):
		self._test_execute(
			provisioning_data={
				"provision": "fake",
				"package_name": "fake package name"
			},
			# ga_zip_path_exists=False
		)

	def ztest_execute_ga_zip_path_not_exists(self):
		self._test_execute(
			provisioning_data={
				"provision": "fake",
				"package_name": "fake package name"
			},
			dotnet_installed=False
		)



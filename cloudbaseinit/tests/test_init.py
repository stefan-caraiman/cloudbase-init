# Copyright 2013 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sys
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import init
from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class TestInitManager(unittest.TestCase):

    def setUp(self):
        self._win32com_mock = mock.MagicMock()
        self._comtypes_mock = mock.MagicMock()
        self._pywintypes_mock = mock.MagicMock()
        self._ctypes_mock = mock.MagicMock()
        self._ctypes_util_mock = mock.MagicMock()

        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'ctypes.util': self._ctypes_util_mock,
             'win32com': self._win32com_mock,
             'comtypes': self._comtypes_mock,
             'pywintypes': self._pywintypes_mock,
             'ctypes': self._ctypes_mock})

        self._module_patcher.start()

        self.osutils = mock.MagicMock()
        self.plugin = mock.MagicMock()

        self._init = init.InitManager()

    def tearDown(self):
        self._module_patcher.stop()

    def _test_get_plugin_section(self, instance_id):
        response = self._init._get_plugins_section(instance_id=instance_id)
        if not instance_id:
            self.assertEqual(self._init._PLUGINS_CONFIG_SECTION, response)
        else:
            self.assertEqual(
                instance_id + "/" + self._init._PLUGINS_CONFIG_SECTION,
                response)

    @mock.patch('cloudbaseinit.init.InitManager._get_plugins_section')
    def test_get_plugin_status(self, mock_get_plugins_section):
        self.osutils.get_config_value.return_value = 1
        response = self._init._get_plugin_status(self.osutils, 'fake id',
                                                 'fake plugin')
        mock_get_plugins_section.assert_called_once_with('fake id')
        self.osutils.get_config_value.assert_called_once_with(
            'fake plugin', mock_get_plugins_section())
        self.assertTrue(response == 1)

    @mock.patch('cloudbaseinit.init.InitManager._get_plugins_section')
    def test_set_plugin_status(self, mock_get_plugins_section):
        self._init._set_plugin_status(self.osutils, 'fake id',
                                      'fake plugin', 'status')
        mock_get_plugins_section.assert_called_once_with('fake id')
        self.osutils.set_config_value.assert_called_once_with(
            'fake plugin', 'status', mock_get_plugins_section())

    @mock.patch('cloudbaseinit.init.InitManager._get_plugin_status')
    @mock.patch('cloudbaseinit.init.InitManager._set_plugin_status')
    def _test_exec_plugin(self, status, mock_set_plugin_status,
                          mock_get_plugin_status):
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        self.plugin.execute.return_value = (status, True)
        mock_get_plugin_status.return_value = status

        response = self._init._exec_plugin(osutils=self.osutils,
                                           service='fake service',
                                           plugin=self.plugin,
                                           instance_id='fake id',
                                           shared_data='shared data')

        mock_get_plugin_status.assert_called_once_with(self.osutils,
                                                       'fake id',
                                                       fake_name)
        if status is base.PLUGIN_EXECUTE_ON_NEXT_BOOT:
            self.plugin.execute.assert_called_once_with('fake service',
                                                        'shared data')
            mock_set_plugin_status.assert_called_once_with(self.osutils,
                                                           'fake id',
                                                           fake_name, status)
            self.assertTrue(response)

    def test_exec_plugin_execution_done(self):
        self._test_exec_plugin(base.PLUGIN_EXECUTION_DONE)

    def test_exec_plugin(self):
        self._test_exec_plugin(base.PLUGIN_EXECUTE_ON_NEXT_BOOT)

    def _test_check_plugin_os_requirements(self, requirements):
        sys.platform = 'win32'
        fake_name = 'fake name'
        self.plugin.get_name.return_value = fake_name
        self.plugin.get_os_requirements.return_value = requirements

        response = self._init._check_plugin_os_requirements(self.osutils,
                                                            self.plugin)

        self.plugin.get_name.assert_called_once_with()
        self.plugin.get_os_requirements.assert_called_once_with()
        if requirements[0] == 'win32':
            self.assertTrue(response)
        else:
            self.assertFalse(response)

    def test_check_plugin_os_requirements(self):
        self._test_check_plugin_os_requirements(('win32', (5, 2)))

    def test_check_plugin_os_requirements_other_requirenments(self):
        self._test_check_plugin_os_requirements(('linux', (5, 2)))

    @mock.patch('cloudbaseinit.init.InitManager._check_latest_version')
    @mock.patch.object(init, 'engine')
    def _test_run_stages(self, mock_engine, mock_check_latest_version,
                         side_effects, expected_calls):
        engine = mock_engine.ExecutionEngine.return_value
        engine.run_stage.side_effect = side_effects

        result = self._init._run_stages()

        mock_check_latest_version.assert_called_once_with()
        mock_engine.ExecutionEngine.assert_called_once_with(
            self._init)
        exec_engine = mock_engine.ExecutionEngine.return_value
        self.assertEqual(expected_calls, exec_engine.run_stage.mock_calls)
        self.assertTrue(result)
        exec_engine.terminate.assert_called_once_with()
        if len(side_effects) == 3:
            exec_engine.start_async_service_search.assert_called_once_with()
        else:
            self.assertFalse(exec_engine.called)

    def test_run_stages_pre_networking(self):
        side_effects = [True]
        expected_calls = [mock.call(base.PLUGIN_STAGE_PRE_NETWORKING)]
        self._test_run_stages(side_effects=side_effects,
                              expected_calls=expected_calls)

    def test_run_stages_pre_metadata_discover(self):
        side_effects = [False, True]
        expected_calls = [
            mock.call(base.PLUGIN_STAGE_PRE_NETWORKING),
            mock.call(base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY),
        ]
        self._test_run_stages(side_effects=side_effects,
                              expected_calls=expected_calls)

    def test_run_stages_main(self):
        side_effects = [False, False, True]
        expected_calls = [
            mock.call(base.PLUGIN_STAGE_PRE_NETWORKING),
            mock.call(base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY),
            mock.call(base.PLUGIN_STAGE_MAIN),
        ]
        self._test_run_stages(side_effects=side_effects,
                              expected_calls=expected_calls)

    @mock.patch('cloudbaseinit.init.InitManager._run_stages')
    @mock.patch('cloudbaseinit.version.get_version')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_configure_host(self, mock_get_os_utils,
                             mock_get_version, mock_run_stages,
                             expected_logging,
                             version, reboot=True):

        mock_get_version.return_value = version
        mock_get_os_utils.return_value = self.osutils

        with testutils.LogSnatcher('cloudbaseinit.init') as snatcher:
            self._init.configure_host()
        self.assertEqual(expected_logging, snatcher.output)
        self.osutils.wait_for_boot_completion.assert_called_once_with()

        if reboot:
            self.osutils.reboot.assert_called_once_with()
        else:
            self.assertFalse(self.osutils.reboot.called)
        mock_run_stages.assert_called_once_with()

    def _test_configure_host_with_logging(self, extra_logging, reboot=True):
        version = 'version'
        expected_logging = [
            'Cloudbase-Init version: %s' % version,
        ]
        self._test_configure_host(
            expected_logging=expected_logging + extra_logging,
            version=version, reboot=reboot)

    @testutils.ConfPatcher('allow_reboot', False)
    @testutils.ConfPatcher('stop_service_on_exit', False)
    def test_configure_host_no_reboot_no_service_stopping(self):
        self._test_configure_host_with_logging(
            reboot=False,
            extra_logging=['Plugins execution done'])

    @testutils.ConfPatcher('allow_reboot', False)
    @testutils.ConfPatcher('stop_service_on_exit', True)
    def test_configure_host_no_reboot_allow_service_stopping(self):
        self._test_configure_host_with_logging(
            reboot=False,
            extra_logging=['Plugins execution done',
                           'Stopping Cloudbase-Init service'])
        self.osutils.terminate.assert_called_once_with()

    @testutils.ConfPatcher('allow_reboot', True)
    def test_configure_host_reboot(self):
        self._test_configure_host_with_logging(
            extra_logging=['Rebooting'])

    @testutils.ConfPatcher('check_latest_version', False)
    @mock.patch('cloudbaseinit.version.check_latest_version')
    def test_configure_host(self, mock_check_last_version):
        self._init._check_latest_version()

        self.assertFalse(mock_check_last_version.called)

    @testutils.ConfPatcher('check_latest_version', True)
    @mock.patch('functools.partial')
    @mock.patch('cloudbaseinit.version.check_latest_version')
    def test_configure_host_with_version_check(self, mock_check_last_version,
                                               mock_partial):
        self._init._check_latest_version()

        mock_check_last_version.assert_called_once_with(
            mock_partial.return_value)
        mock_partial.assert_called_once_with(
            init.LOG.info, 'Found new version of cloudbase-init %s')

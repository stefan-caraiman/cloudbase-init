# Copyright 2014 Cloudbase Solutions Srl
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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common import base
from cloudbaseinit.tests import testutils


MODPATH = "cloudbaseinit.plugins.windows.licensing"


class WindowsLicensingPluginTests(unittest.TestCase):

    def setUp(self):
        self._wmi_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                'wmi': self._wmi_mock})
        self.snatcher = testutils.LogSnatcher(MODPATH)
        self._module_patcher.start()
        licensing = importlib.import_module(MODPATH)
        self._licensing = licensing.WindowsLicensingPlugin()

    def tearDown(self):
        self._module_patcher.stop()

    @testutils.ConfPatcher('set_kms_product_key', True)
    @testutils.ConfPatcher('set_avma_product_key', True)
    @mock.patch("cloudbaseinit.utils.windows.licensing.set_product_key")
    @mock.patch("cloudbaseinit.utils.windows.licensing."
                "get_volume_activation_product_key")
    @mock.patch("cloudbaseinit.utils.windows.licensing.get_kms_product")
    def _test_set_product_key(self, mock_get_kms_product,
                              mock_get_volume_activation_product_key,
                              mock_set_product_key, description=None,
                              license_family=None, is_current=None):
        mock_service = mock.Mock()
        fake_key = mock.sentinel.key
        mock_service.get_use_avma_licensing.return_value = None
        mock_get_kms_product.return_value = (description, license_family,
                                             is_current)
        mock_get_volume_activation_product_key.return_value = fake_key
        with self.snatcher:
            self._licensing._set_product_key(mock_service)
        mock_get_kms_product.assert_called_once_with()
        if is_current:
            expected_logs = ['Product "%s" is already the current one, '
                             'no need to set a product key' % description]
            self.assertEqual(self.snatcher.output, expected_logs)
            return
        else:
            mock_service.get_use_avma_licensing.assert_called_once_with()
            mock_get_volume_activation_product_key.assert_called_once_with(
                None, 'AVMA')
            mock_set_product_key.assert_called_once_with(fake_key)

    def test_set_product_key(self):
        self._test_set_product_key()

    def test_set_product_key_is_current(self):
        self._test_set_product_key(is_current=True)

    @mock.patch("cloudbaseinit.utils.windows.licensing.set_kms_host")
    def test_set_kms_host(self, mock_set_kms_host):
        mock_service = mock.Mock()
        mock_host = mock.Mock()
        mock_service.get_kms_host.return_value = mock_host
        expected_logs = ["Setting KMS host: %s" % mock_host]
        with self.snatcher:
            self._licensing._set_kms_host(mock_service)
        self.assertEqual(self.snatcher.output, expected_logs)
        mock_set_kms_host.assert_called_once_with(mock_host)

    @mock.patch("cloudbaseinit.utils.windows.licensing.activate_windows")
    def test_activate_windows(self, mock_activate_windows):
        activate_result = mock.Mock()
        mock_service = mock.Mock()
        mock_activate_windows.return_value = activate_result
        expected_logs = [
            "Activating Windows",
            "Activation result:\n%s" % activate_result]
        with testutils.ConfPatcher('activate_windows', True):
            with self.snatcher:
                self._licensing._activate_windows(mock_service)
        self.assertEqual(self.snatcher.output, expected_logs)

    @mock.patch(MODPATH + ".WindowsLicensingPlugin._activate_windows")
    @mock.patch(MODPATH + ".WindowsLicensingPlugin._set_kms_host")
    @mock.patch(MODPATH + ".WindowsLicensingPlugin._set_product_key")
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.windows.licensing'
                '.get_licensing_info')
    @mock.patch('cloudbaseinit.utils.windows.licensing'
                '.is_eval')
    def _test_execute(self, mock_is_eval,
                      mock_get_licensing_info,
                      mock_get_os_utils,
                      mock_set_product_key,
                      mock_set_kms_host,
                      mock_activate_windows,
                      nano=False, is_eval=True):
        mock_service = mock.Mock()
        mock_osutils = mock.MagicMock()
        mock_osutils.is_nano_server.return_value = nano
        mock_get_os_utils.return_value = mock_osutils
        mock_is_eval.return_value = is_eval
        mock_get_licensing_info.return_value = "fake"
        expected_logs = []
        with self.snatcher:
            response = self._licensing.execute(service=mock_service,
                                               shared_data=None)

        mock_get_os_utils.assert_called_once_with()
        if nano:
            expected_logs = ["Licensing info and activation are "
                             "not available on Nano Server"]
            self.assertEqual(self.snatcher.output, expected_logs)
            return    # no activation available
        else:
            if not is_eval:
                mock_set_product_key.assert_called_once_with(mock_service)
                mock_set_kms_host.assert_called_once_with(mock_service)
                mock_activate_windows.assert_called_once_with(mock_service)
            else:
                expected_logs.append("Evaluation license, skipping activation"
                                     ". Evaluation end date: %s" % is_eval)
            expected_logs.append('Microsoft Windows license info:\nfake')
            mock_get_licensing_info.assert_called_once_with()

        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)
        self.assertEqual(self.snatcher.output, expected_logs)

    def test_execute_nano(self):
        self._test_execute(nano=True)

    def test_execute_is_evaluated(self):
        self._test_execute()

    def test_execute(self):
        self._test_execute(is_eval=False)

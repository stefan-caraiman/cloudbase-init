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

import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.windows import licensing
from cloudbaseinit.tests import testutils


class WindowsLicensingPluginTests(unittest.TestCase):

    def setUp(self):
        module_path = 'cloudbaseinit.plugins.windows.licensing'
        self._licensing = licensing.WindowsLicensingPlugin()
        self.snatcher = testutils.LogSnatcher(module_path)

    @testutils.ConfPatcher('set_avma_product_key', "fake product_key")
    @mock.patch('cloudbaseinit.utils.windows.licensing.set_product_key')
    @mock.patch('cloudbaseinit.utils.windows.licensing.get_volume_activation_product_key')    
    @mock.patch('cloudbaseinit.utils.windows.licensing.get_kms_product')
    def _test_set_product_key(self, mock_get_kms_product,
                              mock_get_volume_activation_product_key,
                              mock_set_product_key,
                              is_current=False,
                              use_avma="fake avma",
                              product_key="fake product key",
                              set_kms_product_key="fake kms key"):
        mock_service = mock.Mock()
        expected_logging = []
        description = "fake description"
        mock_get_kms_product.return_value =  (description, None, is_current)
        if is_current:
            expected_logging += [
                'Product "%s" is already the current one, no need to set '
                'a product key' % description
            ]
        else:
            mock_service.get_use_avma_licensing.return_value = use_avma
            if use_avma is None:
                use_avma = licensing.CONF.set_avma_product_key

            expected_logging += [
                "Use AVMA: %s" % use_avma
            ]
            if use_avma:
                mock_get_volume_activation_product_key.return_value = \
                    product_key
                if not product_key:
                    expected_logging += [
                        "AVMA product key not found for this OS"
                    ]
            if not product_key and set_kms_product_key:
                mock_get_volume_activation_product_key.side_effect = \
                    [None, product_key]
                expected_logging += [
                    "KMS product key not found for this OS"
                ]
            
            if not product_key and set_kms_product_key:
                mock_get_volume_activation_product_key.return_value = \
                    product_key
                expected_logging += [
                    "KMS product key not found for this OS"
                ]
            if product_key:
                expected_logging += [
                    "Setting product key: %s" % product_key
                ]
        with testutils.ConfPatcher('set_avma_product_key', set_kms_product_key):
            with self.snatcher:
                self._licensing._set_product_key(mock_service)
            self.assertEqual(self.snatcher.output, expected_logging)


    def test_set_product_key_already_used(self):
        self._test_set_product_key(is_current=True)

    def test_run_slmgr_not_sysnative(self):
        self._test_set_product_key()

    def test_run_slmgr_exit_code(self):
        self._test_set_product_key(use_avma=None)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('cloudbaseinit.utils.windows.licensing'
                '.get_licensing_info')
    @mock.patch('cloudbaseinit.utils.windows.licensing'
                '.is_eval')
    def _test_execute(self, mock_is_eval, mock_get_licensing_info,
                      mock_get_os_utils, eval_end_date="fake date", nano=False):
        mock_osutils = mock.MagicMock()
        mock_osutils.is_nano_server.return_value = nano
        mock_get_os_utils.return_value = mock_osutils
       

        expected_logging = []
        if nano:
            expected_logging = [
                "Licensing info and activation are not available on "
                "Nano Server"
            ]
        else:
            if eval_end_date:
                mock_is_eval.return_value = eval_end_date
                expected_logging = [
                    "Evaluation license, skipping activation. "
                    "Evaluation end date: %s" % eval_end_date
                ]
            else:
                mock_is_eval.return_value = None
                self._licensing._set_product_key = mock.Mock()
                self._licensing._set_kms_host = mock.Mock()
                self._licensing._activate_windows = mock.Mock()

            mock_get_licensing_info.return_value = "fake info"
            expected_logging += ['Microsoft Windows license info:\n%s' % 
                                mock_get_licensing_info.return_value]

        with self.snatcher:
            response = self._licensing.execute(service=None, shared_data=None)

        mock_get_os_utils.assert_called_once_with()
        if nano:
            pass
        else:
            mock_is_eval.assert_called_once_with()
            if eval_end_date:
                pass
            else:
                self._licensing._set_product_key.assert_called_once_with(None)
                self._licensing._set_kms_host.assert_called_once_with(None)
                self._licensing._activate_windows.assert_called_once_with(None)
            mock_get_licensing_info.assert_called_once_with()
        
        self.assertEqual(self.snatcher.output, expected_logging)
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

    def test_execute_nano(self):
        self._test_execute(nano=True)

    def test_execute_licence_end_date(self):
        self._test_execute()

    def test_execute_activate_windows_nano(self):
        self._test_execute(eval_end_date=None)

    @mock.patch('cloudbaseinit.utils.windows.licensing.activate_windows')
    def _test_activate_windows(self, mock_activate, activate=True):
        expected_logging = []
        if activate:
            mock_activate.return_value = "fake result"
            expected_logging += [
                "Activating Windows",
                "Activation result:\n%s" % 
                mock_activate.return_value
            ]
        with testutils.ConfPatcher('activate_windows', activate):
            with self.snatcher:
                self._licensing._activate_windows(None)
        self.assertEqual(self.snatcher.output, expected_logging)

    def test_not_activate_windows(self):
        self._test_activate_windows(activate=False)

    def test_activate_windows(self):
        self._test_activate_windows()

    @mock.patch('cloudbaseinit.utils.windows.licensing.set_kms_host')
    def _test_set_kms_host(self, mock_set_kms_host, kms_host="fake host"):
        expected_logging = []
        mock_service = mock.Mock()
        mock_service.get_kms_host.return_value = kms_host
        if kms_host:
            expected_logging = ["Setting KMS host: %s" % kms_host]
        with self.snatcher:
            self._licensing._set_kms_host(mock_service)
        if kms_host:
            mock_set_kms_host.assert_called_once_with(kms_host)
        self.assertEqual(expected_logging, self.snatcher.output)

    def test_set_kms_host(self):
        self._test_set_kms_host()

    def test_set_no_kms_host(self):
        self._test_set_kms_host(kms_host=None)



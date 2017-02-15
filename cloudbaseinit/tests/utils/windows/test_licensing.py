# Copyright (c) 2017 Cloudbase Solutions Srl
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

import six
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


MODPATH = "cloudbaseinit.utils.windows.licensing"


class LicensingTest(unittest.TestCase):

    def setUp(self):
        self._wmi_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules', {
                'wmi': self._wmi_mock})
        self.snatcher = testutils.LogSnatcher(MODPATH)
        self._module_patcher.start()
        self.licensing = importlib.import_module(MODPATH)

    def tearDown(self):
        self._module_patcher.stop()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_run_slmgr(self, mock_get_os_utils, ret_val=0,
                        sysnative=True):
        mock_args = [mock.sentinel.args]
        mock_outval = six.text_type(mock.sentinel.out_val)
        mock_cscriptdir = r"fake\cscript\dir"
        mock_osutils = mock.Mock()
        mock_osutils.get_sysnative_dir.return_value = mock_cscriptdir
        mock_osutils.get_system32_dir.return_value = mock_cscriptdir
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_system32_dir.return_value = r"fakedir"
        mock_osutils.check_sysnative_dir_exists.return_value = sysnative
        mock_osutils.execute_process.return_value = (
            mock_outval, mock.sentinel.err, ret_val)

        if ret_val:
            self.assertRaises(exception.CloudbaseInitException,
                              self.licensing._run_slmgr, mock_args)
        else:
            res_out = self.licensing._run_slmgr(mock_args)
            self.assertEqual(res_out, mock_outval)
        self.assertEqual(mock_osutils.execute_process.call_count, 1)

    def test_run_slmgr_sys_native(self):
        self._test_run_slmgr()

    def test_run_slmgr_system32(self):
        self._test_run_slmgr(sysnative=False)

    def test_run_slmgr_fail(self):
        self._test_run_slmgr(ret_val=1)

    @mock.patch(MODPATH + "._run_slmgr")
    def test_get_licensing_info(self, mock_run_slmgr):
        mock_out = mock.sentinel.out_val
        mock_run_slmgr.return_value = mock_out
        res = self.licensing.get_licensing_info()
        mock_run_slmgr.assert_called_once_with(['/dlv'])
        self.assertEqual(res, mock_out)

    @mock.patch(MODPATH + "._run_slmgr")
    def test_activate_windows(self, mock_run_slmgr):
        mock_out = mock.sentinel.out_val
        mock_run_slmgr.return_value = mock_out
        res = self.licensing.activate_windows()
        mock_run_slmgr.assert_called_once_with(['/ato'])
        self.assertEqual(res, mock_out)

    @mock.patch(MODPATH + "._run_slmgr")
    def test_set_kms_host(self, mock_run_slmgr):
        mock_out = mock.sentinel.out_val
        mock_kms = mock.sentinel.kms_host
        mock_run_slmgr.return_value = mock_out
        res = self.licensing.set_kms_host(mock_kms)
        mock_run_slmgr.assert_called_once_with(['/skms', mock_kms])
        self.assertEqual(res, mock_out)

    @mock.patch(MODPATH + "._run_slmgr")
    def test_set_kms_auto_discovery(self, mock_run_slmgr):
        mock_out = mock.sentinel.out_val
        mock_run_slmgr.return_value = mock_out
        res = self.licensing.set_kms_auto_discovery()
        mock_run_slmgr.assert_called_once_with(['/ckms'])
        self.assertEqual(res, mock_out)

    @mock.patch(MODPATH + "._run_slmgr")
    def test_set_product_key(self, mock_run_slmgr):
        mock_out = mock.sentinel.out_val
        mock_product_key = mock.sentinel.product_key
        mock_run_slmgr.return_value = mock_out
        res = self.licensing.set_product_key(mock_product_key)
        mock_run_slmgr.assert_called_once_with(['/ipk', mock_product_key])
        self.assertEqual(res, mock_out)

    def test_is_current_product(self):
        mock_product = mock.Mock()
        mock_product.PartialProductKey = "fake-key"
        res = self.licensing._is_current_product(mock_product)
        self.assertTrue(res)

    def test_get_products(self):
        mock_license_product = mock.Mock()
        conn = self._wmi_mock.WMI
        conn.return_value = mock_license_product
        res = self.licensing._get_products()
        self.assertIsNotNone(res)
        mock_license_product.SoftwareLicensingProduct.assert_called_once_with(
            LicenseIsAddon=False)

    @mock.patch(MODPATH + "._get_products")
    def test_is_eval(self, mock_get_products):
        mock_product = mock.Mock()
        mock_product.ApplicationId = self.licensing.WINDOWS_APP_ID
        mock_product.Description = u"TIMEBASED_EVAL"
        mock_product.EvaluationEndDate = "fake"
        mock_get_products.return_value = [mock_product]
        res = self.licensing.is_eval()
        self.assertEqual(res, "fake")

    @mock.patch(MODPATH + "._get_products")
    def _test_get_kms_product(self, mock_get_products, products=()):
        mock_get_products.return_value = products
        if not products:
            self.assertRaises(exception.ItemNotFoundException,
                              self.licensing.get_kms_product)
            return
        res = self.licensing.get_kms_product()
        self.assertIsNotNone(res)

    def test_get_kms_product_no_keys(self):
        self._test_get_kms_product()

    def test_get_kms_product(self):
        mock_product = mock.Mock()
        mock_product.ApplicationId = self.licensing.WINDOWS_APP_ID
        mock_product.Description = u"VOLUME_KMSCLIENT"
        self._test_get_kms_product(products=[mock_product])

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_get_volume_activation_product_key(self, mock_get_os_utils):
        mock_os_version = {'major_version': 10, 'minor_version': 0}
        expected_key = "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY"
        mock_osutils = mock.Mock()
        mock_get_os_utils.return_value = mock_osutils
        mock_osutils.get_os_version.return_value = mock_os_version
        res = self.licensing.get_volume_activation_product_key(
            license_family="ServerStandard")
        self.assertEqual(res, expected_key)

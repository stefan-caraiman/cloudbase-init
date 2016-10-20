# Copyright 2016 Cloudbase Solutions Srl
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

import unittest

import requests
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import bigstepservice
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
BASEMODPATH = "cloudbaseinit.metadata.services.base.BaseHTTPMetadataService"
MODPATH = "cloudbaseinit.metadata.services.bigstepservice"


class BigstepServiceTest(unittest.TestCase):

    def setUp(self):
        self._service = bigstepservice.BigstepService()
        self._service._raw_data["metadata"] = {}
        self.snatcher = testutils.LogSnatcher(MODPATH)

    def test_can_update_password(self):
        self.assertTrue(self._service.can_update_password)

    def test_can_post_password(self):
        self.assertTrue(self._service.can_post_password)

    def test__set_base_url(self):
        fake_url = r"fake/url"
        with mock.patch('six.moves.builtins.open',
                        mock.mock_open(read_data=fake_url), create=True):
            self._service._set_base_url()
        self.assertEqual(self._service._base_url, fake_url)

    def test__set_base_url_failed(self):
        exception = IOError
        expected_logging = ["Failed to get the metadata URL: %s" % exception]
        with mock.patch('six.moves.builtins.open') as mocked_open:
            mocked_open.side_effect = exception()
            with self.snatcher:
                with self.assertRaises(exception):
                    self._service._set_base_url()
                    self.assertEqual(expected_logging, self.snatcher.output)

    @mock.patch("json.loads")
    @mock.patch(MODPATH + ".BigstepService._set_base_url")
    @mock.patch(BASEMODPATH + "._http_request")
    @mock.patch(BASEMODPATH + "._exec_with_retry")
    def _test_load(self, mock_exec_with_retry, mock_http_request,
                   mock_set_base_url, mock_json_loads,
                   exception=None, expected_logging=[]):
        if exception:
            if exception is requests.RequestException:
                mock_exec_with_retry.side_effect = [None, exception]
            else:
                mock_json_loads.side_effect = exception
            with self.snatcher:
                load_res = self._service.load()
            self.assertFalse(load_res)
            self.assertEqual(self.snatcher.output, expected_logging)
            return
        else:
            load_res = self._service.load()
            self.assertTrue(load_res)

    def test_load_no_metadata(self):
        exc = requests.RequestException
        expected_logging = [
            "Metadata not found at URL %(url)r: %(reason)r" %
            {"url": self._service._base_url, "reason": exc()}]
        self._test_load(exception=exc, expected_logging=expected_logging)

    def test_load_failed_to_load(self):
        exc = ValueError
        expected_logging = ["Failed to load metadata: %s" % exc()]
        self._test_load(exception=exc, expected_logging=expected_logging)

    def test_load(self):
        self._test_load()

    def test_get_instance_id_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_instance_id)

    def test_get_instance_id(self):
        instance_id = b"fake-id"
        self._service._raw_data["metadata"]["instance-id"] = instance_id
        res_instance_id = self._service.get_instance_id()
        self.assertEqual(str(instance_id), res_instance_id)

    def test_get_host_name(self):
        hostname = "fake-hostname"
        self._service._raw_data["metadata"]["hostname"] = hostname
        self.assertEqual(self._service.get_host_name(), hostname)

    def test_get_host_name_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_host_name)

    def test_get_admin_password(self):
        password = "fake-password"
        (self._service._raw_data["metadata"]
         ["password-plaintext-unsafe"]) = password
        plain_password = self._service.get_admin_password()
        self.assertEqual(plain_password, password)

    def test_get_admin_password_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_admin_password)

    def test_get_public_keys(self):
        keys = ["fake-keys"]
        self._service._raw_data["metadata"]["public-keys"] = keys
        public_keys = self._service.get_public_keys()
        self.assertEqual(public_keys, keys)

    def test_get_public_keys_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_public_keys)

    def test_get_user_data(self):
        userdata = b"fake-userdata"
        self._service._raw_data["metadata"]["userdata"] = userdata
        res_userdata = self._service.get_user_data()
        self.assertEqual(res_userdata, userdata)

    def test_get_user_data_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_user_data)

    def test_is_password_changed(self):
        self.assertFalse(self._service.is_password_changed())
        self._service._raw_data["metadata"]["password-changed"] = True
        self.assertTrue(self._service.is_password_changed())

    @mock.patch(BASEMODPATH + "._http_request")
    @mock.patch(BASEMODPATH + "._exec_with_retry")
    def test_post_password(self, _, __):
        password = b"fake"
        self._service._raw_data["metadata"]["user_password_set_url"] = password
        self.assertTrue(self._service.post_password(password))

    def test_post_password_failed_endpoint(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.post_password, b'fake')

    @mock.patch(BASEMODPATH + "._http_request")
    @mock.patch(BASEMODPATH + "._exec_with_retry")
    def test_post_password_failed_post(self, mock_exec_with_retry,
                                       mock_http_request):
        exc = requests.HTTPError
        passwd = b"fake"
        mock_exec_with_retry.side_effect = exc
        self._service._raw_data["metadata"]["user_password_set_url"] = passwd
        expected_logging = [
            "Failed to post the password to the metadata service: "]
        with self.snatcher:
            with self.assertRaises(exc):
                self._service.post_password(passwd)
        self.assertEqual(self.snatcher.output, expected_logging)

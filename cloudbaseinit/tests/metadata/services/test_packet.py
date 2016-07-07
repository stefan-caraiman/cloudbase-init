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
from cloudbaseinit.metadata.services import packet
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
BASEMODPATH = "cloudbaseinit.metadata.services.base.BaseHTTPMetadataService"
MODPATH = "cloudbaseinit.metadata.services.packet"


class PacketServiceTest(unittest.TestCase):

    def setUp(self):
        self._service = packet.PacketService()
        self._service._raw_data["metadata"] = {}
        self.snatcher = testutils.LogSnatcher(MODPATH)

    def test_can_post_password(self):
        self.assertTrue(self._service.can_post_password)

    @mock.patch("json.loads")
    @mock.patch(BASEMODPATH + "._exec_with_retry")
    @mock.patch(BASEMODPATH + "._http_request")
    def _test_load(self, mock_http_request,
                   mock_exec_with_retry, mock_json_loads,
                   exception=None, expected_logging=[]):
        if exception:
            if exception is requests.RequestException:
                mock_exec_with_retry.side_effect = [None, exception]
            else:
                mock_json_loads.side_effect = exception
            with self.snatcher:
                load_res = self._service.load()
            self.assertEqual(self.snatcher.output, expected_logging)
            return
        else:
            load_res = self._service.load()
            self.assertTrue(load_res)

    def test_load_no_userdata(self):
        exc = requests.RequestException
        url = requests.compat.urljoin(self._service._base_url, "userdata")
        expected_logging = [
            "Userdata not found at URL %(url)r: %(reason)r" %
            {"url": url, "reason": exc()}]
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
        instance_id = "fake-id"
        self._service._raw_data["metadata"]["id"] = instance_id
        res_instance_id = self._service.get_instance_id()
        self.assertEqual(str(instance_id), res_instance_id)

    def test_get_host_name(self):
        hostname = "fake-hostname"
        self._service._raw_data["metadata"]["hostname"] = hostname
        self.assertEqual(self._service.get_host_name(), hostname)

    def test_get_host_name_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_host_name)

    def test_get_public_keys(self):
        keys = ["fake-keys"]
        self._service._raw_data["metadata"]["ssh_keys"] = keys
        public_keys = self._service.get_public_keys()
        self.assertEqual(public_keys, keys)

    def test_get_public_keys_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_public_keys)

    def test_get_user_data(self):
        self._service._raw_data['userdata'] = True
        self.assertTrue(self._service.get_user_data())

    def test_get_encryption_public_key_failed(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.get_encryption_public_key)

    @mock.patch(BASEMODPATH + "._exec_with_retry")
    @mock.patch(BASEMODPATH + "._http_request")
    def test_get_encryption_public_key_no_data(self, mock_http_request,
                                               mock_exec_with_retry):
        request_exc = requests.RequestException
        self._service._raw_data["metadata"]['phone_home_url'] = "fake"
        mock_exec_with_retry.side_effect = request_exc
        url = requests.compat.urljoin('{}/'.format("fake"), "key")
        expected_logging = [
            "Data not found at URL %(url)r: %(reason)r" %
            {"url": url, "reason": request_exc()}]
        with self.snatcher:
            key_data = self._service.get_encryption_public_key()
            self.assertFalse(key_data)
            self.assertEqual(self.snatcher.output, expected_logging)

    @mock.patch(BASEMODPATH + "._exec_with_retry")
    @mock.patch(BASEMODPATH + "._http_request")
    def test_get_encryption_public_key(self, mock_http_request,
                                       mock_exec_with_retry):
        self._service._raw_data["metadata"]['phone_home_url'] = "fake"
        mock_http_request.return_value = "fake_data"
        self.assertTrue(self._service.get_encryption_public_key())

    def test_post_password_failed_get(self):
        self.assertRaises(base.NotExistingMetadataException,
                          self._service.post_password, "fake")

    @mock.patch(BASEMODPATH + "._exec_with_retry")
    @mock.patch(BASEMODPATH + "._http_request")
    def test_post_password(self, mock_http_request, mock_exec_with_retry):
        self._service._raw_data["metadata"]['phone_home_url'] = "fake"
        mock_exec_with_retry.return_value = mock_http_request()
        post_result = self._service.post_password(b"fake")
        self.assertTrue(post_result)
        self.assertEqual(mock_exec_with_retry.call_count, 1)
        self.assertEqual(mock_http_request.call_count, 1)

    @mock.patch(BASEMODPATH + "._exec_with_retry")
    @mock.patch(BASEMODPATH + "._http_request")
    def test_post_password_fail(self, mock_http_request,
                                mock_exec_with_retry):
        self._service._raw_data["metadata"]['phone_home_url'] = "fake"
        exc = requests.HTTPError
        mock_exec_with_retry.side_effect = exc
        expected_logging = [
            "Failed to post password to the metadata service: %s" % exc()]
        with self.snatcher:
            with self.assertRaises(exc):
                self._service.post_password(b"fake")
        self.assertEqual(self.snatcher.output, expected_logging)

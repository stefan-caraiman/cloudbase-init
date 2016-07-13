# Copyright 2015 Cloudbase Solutions Srl
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

import mock
import requests
import unittest

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base


class FakeService(base.BaseMetadataService):
    def _get_data(self):
        return (b'\x1f\x8b\x08\x00\x93\x90\xf2U\x02'
                b'\xff\xcbOSH\xce/-*NU\xc8,Q(\xcf/\xca.'
                b'\x06\x00\x12:\xf6a\x12\x00\x00\x00')

    def get_user_data(self):
        return self._get_data()


class TestBase(unittest.TestCase):

    def setUp(self):
        self._service = FakeService()

    def test_get_decoded_user_data(self):
        userdata = self._service.get_decoded_user_data()
        self.assertEqual(b"of course it works", userdata)


class TestBaseHTTPMetadataService(unittest.TestCase):

    def _test_verify_https_request(self, is_secure):
        fake_base_url = mock.Mock()
        http_service = base.BaseHTTPMetadataService(fake_base_url)
        if is_secure:
            fake_https_ca_bundle = 'fake_https_ca_bundle'
            http_service = (base.BaseHTTPMetadataService(fake_base_url,
                            https_ca_bundle=fake_https_ca_bundle))
            response = fake_https_ca_bundle
        else:
            response = False
        result = http_service._verify_https_request()
        self.assertEqual(result, response)

    def test_verify_https_request_secure(self):
        self._test_verify_https_request(is_secure=True)

    def test_verify_https_request_insecure(self):
        self._test_verify_https_request(is_secure=False)

    @mock.patch('requests.post')
    @mock.patch('requests.get')
    def _test_http_request(self, mock_get, mock_post, data_exists):
        fake_base_url = mock.Mock()
        http_service = base.BaseHTTPMetadataService(fake_base_url)
        url = 'some_url'
        fake_response = mock.Mock()
        if data_exists:
            data = 'some_data'
            fake_response.content = None
            mock_post.return_value = fake_response
            raise_for_status = mock_post.return_value.raise_for_status
        else:
            data = None
            fake_response.content = 'some_data'
            mock_get.return_value = fake_response
            raise_for_status = mock_get.return_value.raise_for_status

        result = http_service._http_request(url, data)
        raise_for_status.assert_called_once_with()
        self.assertNotEqual(data, result)

    def test_http_request_with_data(self):
        self._test_http_request(data_exists=True)

    def test_http_request_without_data(self):
        self._test_http_request(data_exists=False)

    @mock.patch('requests.compat.urljoin')
    @mock.patch("cloudbaseinit.metadata.services.base."
                "BaseHTTPMetadataService._http_request")
    def _test_get_data(self, mock_http_request, mock_urljoin,
                       expected_response, expected_value):
        fake_base_url = mock.Mock()
        http_service = base.BaseHTTPMetadataService(fake_base_url)
        mock_request = mock.Mock()
        mock_urljoin.return_value = 'some_url'
        mock_http_request.side_effect = [expected_response]
        if expected_value:
            self.assertRaises(expected_value, http_service._get_data,
                              mock_request)
        else:
            response = http_service._get_data(mock_request)
            self.assertEqual(expected_response, response)

    def test_get_response(self):
        self._test_get_data(expected_response='fake response',
                            expected_value=False)

    def test_get_response_not_found(self):
        fake_response = mock.Mock()
        fake_response.status_code = 404
        http_error = requests.HTTPError()
        http_error.response = fake_response
        http_error.message = mock.Mock()
        self._test_get_data(expected_response=http_error,
                            expected_value=base.NotExistingMetadataException)

    def test_get_response_http_error(self):
        fake_response = mock.Mock()
        fake_response.status_code = 400
        http_error = requests.HTTPError()
        http_error.response = fake_response
        self._test_get_data(expected_response=http_error,
                            expected_value=requests.HTTPError)

    def test_get_response_ssl_error(self):
        ssl_error = requests.exceptions.SSLError()
        self._test_get_data(expected_response=ssl_error,
                            expected_value=exception.CertificateVerifyFailed)

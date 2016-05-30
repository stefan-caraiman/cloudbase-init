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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo_config import cfg

from cloudbaseinit import constants
from cloudbaseinit.metadata.services import maasservice
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import x509constants


CONF = cfg.CONF


class Test_NetworkDetailsBuilder(unittest.TestCase):

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def setUp(self, _):
        fake_network_data = {}
        self._builder = maasservice._NetworkDetailsBuilder(
            service=maasservice.MaaSHttpService,
            network_data=fake_network_data)

    @mock.patch("cloudbaseinit.metadata.services.basenetworkservice."
                "NetworkDetailsBuilder._get_fields")
    def _test_process_network(self, mock_get_fields, static=True):
        mock_network = {}
        mock_raw_subnet = {mock.sentinel.key: mock.sentinel.subnet}
        if static:
            mock_network[constants.ID] = mock.sentinel.id
            mock_network[constants.TYPE] = self._builder.STATIC
            mock_get_fields.return_value = mock_network
            res = self._builder._process_network(mock_raw_subnet)
            self.assertTrue(res)
        else:
            mock_network[constants.TYPE] = self._builder.MANUAL
            mock_get_fields.return_value = mock_network
            res = self._builder._process_network(mock_raw_subnet)
            self.assertFalse(res)

    def test_process_network_static(self):
        self._test_process_network()

    def test_process_network_manual(self):
        self._test_process_network(static=False)


class MaaSHttpServiceTest(unittest.TestCase):

    def setUp(self):
        self._maasservice = maasservice.MaaSHttpService()

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def _test_load(self, mock_get_cache_data, ip, cache_data_fails=False):
        if cache_data_fails:
            mock_get_cache_data.side_effect = Exception

        with testutils.ConfPatcher('metadata_base_url', ip, "maas"):
            with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                       'maasservice') as snatcher:
                response = self._maasservice.load()

            if ip is not None:
                if not cache_data_fails:
                    mock_get_cache_data.assert_called_once_with(
                        '%s/meta-data/' % self._maasservice._metadata_version)
                    self.assertTrue(response)
                else:
                    expected_logging = 'Metadata not found at URL \'%s\'' % ip
                    self.assertEqual(expected_logging, snatcher.output[-1])
            else:
                self.assertFalse(response)

    def test_load(self):
        self._test_load(ip='196.254.196.254')

    def test_load_no_ip(self):
        self._test_load(ip=None)

    def test_load_get_cache_data_fails(self):
        self._test_load(ip='196.254.196.254', cache_data_fails=True)

    @testutils.ConfPatcher('oauth_consumer_key', 'consumer_key', "maas")
    @testutils.ConfPatcher('oauth_consumer_secret', 'consumer_secret', "maas")
    @testutils.ConfPatcher('oauth_token_key', 'token_key', "maas")
    @testutils.ConfPatcher('oauth_token_secret', 'token_secret', "maas")
    def test_get_oauth_headers(self):
        response = self._maasservice._get_oauth_headers(url='196.254.196.254')
        self.assertIsInstance(response, dict)
        self.assertIn('Authorization', response)

        auth = response['Authorization']
        self.assertTrue(auth.startswith('OAuth'))

        auth = auth[6:]
        parts = [item.strip() for item in auth.split(",")]
        auth_parts = dict(part.split("=") for part in parts)

        required_headers = {
            'oauth_token',
            'oauth_consumer_key',
            'oauth_signature',
        }
        self.assertTrue(required_headers.issubset(set(auth_parts)))
        self.assertEqual('"token_key"', auth_parts['oauth_token'])
        self.assertEqual('"consumer_key"', auth_parts['oauth_consumer_key'])
        self.assertEqual('"consumer_secret%26token_secret"',
                         auth_parts['oauth_signature'])

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_host_name(self, mock_get_cache_data):
        response = self._maasservice.get_host_name()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/local-hostname' %
            self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_instance_id(self, mock_get_cache_data):
        response = self._maasservice.get_instance_id()
        mock_get_cache_data.assert_called_once_with(
            '%s/meta-data/instance-id' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_public_keys(self, mock_get_cache_data):
        public_keys = [
            "fake key 1",
            "fake key 2"
        ]
        public_key = "\n".join(public_keys) + "\n"
        mock_get_cache_data.return_value = public_key
        response = self._maasservice.get_public_keys()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/public-keys' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(public_keys, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_client_auth_certs(self, mock_get_cache_data):
        certs = [
            "{begin}\n{cert}\n{end}".format(
                begin=x509constants.PEM_HEADER,
                end=x509constants.PEM_FOOTER,
                cert=cert)
            for cert in ("first cert", "second cert")
        ]
        mock_get_cache_data.return_value = "\n".join(certs) + "\n"
        response = self._maasservice.get_client_auth_certs()
        mock_get_cache_data.assert_called_with(
            '%s/meta-data/x509' % self._maasservice._metadata_version,
            decode=True)
        self.assertEqual(certs, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._maasservice.get_user_data()
        mock_get_cache_data.assert_called_once_with(
            '%s/user-data' %
            self._maasservice._metadata_version)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_network_details_builder_no_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = None
        expected_output = ["'network_data.json' not found."]
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'maasservice') as snatcher:
            response = self._maasservice._get_network_details_builder()
        mock_get_cache_data.assert_called_once_with('latest/network_data.json',
                                                    decode=True)
        self.assertIsNone(response)
        self.assertEqual(snatcher.output, expected_output)

    @mock.patch('json.loads')
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_network_details_builder_fail_json(self, mock_get_cache_data,
                                                   mock_loads):
        mock_loads.side_effect = ValueError
        expected_output = ['Failed to load json data: ValueError()']
        with testutils.LogSnatcher('cloudbaseinit.metadata.services.'
                                   'maasservice') as snatcher:
            response = self._maasservice._get_network_details_builder()
        mock_get_cache_data.assert_called_once_with('latest/network_data.json',
                                                    decode=True)
        self.assertIsNone(response)
        self.assertEqual(snatcher.output, expected_output)

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    @mock.patch('json.loads')
    @mock.patch("cloudbaseinit.metadata.services.maasservice.MaaSHttpService"
                "._get_cache_data")
    def test_get_network_details(self, mock_get_cache_data, mock_loads,
                                 mock_get_os_utils):
        response = self._maasservice._get_network_details_builder()
        self.assertIsInstance(response, maasservice._NetworkDetailsBuilder)

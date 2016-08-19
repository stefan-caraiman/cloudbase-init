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


import posixpath
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo_config import cfg


from cloudbaseinit import constants
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import network as network_utils
from cloudbaseinit.utils import x509constants

CONF = cfg.CONF

MODPATH = "cloudbaseinit.metadata.services.baseopenstackservice"


class FinalBaseOpenStackService(baseopenstackservice.BaseOpenStackService):

    def _get_data(self):
        pass


class TestBaseOpenStackService(unittest.TestCase):

    def setUp(self):
        CONF.set_override("retry_count_interval", 0)
        self._service = FinalBaseOpenStackService()
        date = "2013-04-04"
        fake_metadata = fake_json_response.get_fake_metadata_json(date)
        self._fake_network_config = fake_metadata["network_config"]
        self._fake_content = self._fake_network_config["debian_config"]
        self._fake_public_keys = fake_metadata["public_keys"]
        self._fake_keys = fake_metadata["keys"]
        self._fake_links = {
            fake_json_response.NAME0: {
                constants.NAME: fake_json_response.NAME0,
                constants.MAC_ADDRESS: fake_json_response.MAC0.upper()
            },
            fake_json_response.NAME1: {
                constants.NAME: fake_json_response.NAME1,
                constants.MAC_ADDRESS: None
            },
        }
        self._fake_networks = {}
        networks = [
            {
                constants.IP_ADDRESS: fake_json_response.ADDRESS0,
                constants.NETMASK: fake_json_response.NETMASK0,
                constants.BROADCAST: fake_json_response.BROADCAST0,
                constants.GATEWAY: fake_json_response.GATEWAY0,
                constants.DNS: fake_json_response.DNSNS0.split()
            },
            {
                constants.IP_ADDRESS: fake_json_response.ADDRESS60,
                constants.NETMASK: fake_json_response.NETMASK60,
                constants.GATEWAY: fake_json_response.GATEWAY60,
            },
            {
                constants.IP_ADDRESS: fake_json_response.ADDRESS1,
                constants.BROADCAST: fake_json_response.BROADCAST1,
                constants.GATEWAY: fake_json_response.GATEWAY1,
                constants.NETMASK: fake_json_response.NETMASK1,
                constants.DNS: None
            },
            {
                constants.IP_ADDRESS: fake_json_response.ADDRESS61,
                constants.NETMASK: fake_json_response.NETMASK61,
                constants.GATEWAY: fake_json_response.GATEWAY61,
            },
        ]
        for network in networks:
            network.update(network_utils.process_interface(
                ip_address=network[constants.IP_ADDRESS],
                netmask=network.get(constants.NETMASK, None)))
            self._fake_networks[network[constants.IP_ADDRESS]] = network

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_content(self, mock_get_cache_data):
        response = self._service.get_content('fake name')
        path = posixpath.join('openstack', 'content', 'fake name')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_user_data(self, mock_get_cache_data):
        response = self._service.get_user_data()
        path = posixpath.join('openstack', 'latest', 'user_data')
        mock_get_cache_data.assert_called_once_with(path)
        self.assertEqual(mock_get_cache_data.return_value, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_cache_data")
    def test_get_meta_data(self, mock_get_cache_data):
        mock_get_cache_data.return_value = '{"fake": "data"}'
        response = self._service._get_meta_data(
            version='fake version')
        path = posixpath.join('openstack', 'fake version', 'meta_data.json')
        mock_get_cache_data.assert_called_with(path, decode=True)
        self.assertEqual({"fake": "data"}, response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_instance_id(self, mock_get_meta_data):
        response = self._service.get_instance_id()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('uuid')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_host_name(self, mock_get_meta_data):
        response = self._service.get_host_name()
        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data().get.assert_called_once_with('hostname')
        self.assertEqual(mock_get_meta_data.return_value.get.return_value,
                         response)

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def test_get_public_keys(self, mock_get_meta_data):
        mock_get_meta_data.return_value.get.side_effect = \
            [self._fake_public_keys, self._fake_keys]
        response = self._service.get_public_keys()

        mock_get_meta_data.assert_called_once_with()
        mock_get_meta_data.return_value.get.assert_any_call("public_keys")
        mock_get_meta_data.return_value.get.assert_any_call("keys")

        public_keys = (list(self._fake_public_keys.values()) +
                       [key["data"] for key in self._fake_keys
                        if key["type"] == "ssh"])
        public_keys = [key.strip() for key in public_keys]

        self.assertEqual(sorted(list(set(public_keys))),
                         sorted(response))

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def _test_get_admin_password(self, mock_get_meta_data, meta_data):
        mock_get_meta_data.return_value = meta_data
        response = self._service.get_admin_password()
        mock_get_meta_data.assert_called_once_with()
        if meta_data and 'admin_pass' in meta_data:
            self.assertEqual(meta_data['admin_pass'], response)
        elif meta_data and 'admin_pass' in meta_data.get('meta'):
            self.assertEqual(meta_data.get('meta')['admin_pass'], response)
        else:
            self.assertIsNone(response)

    def test_get_admin_pass(self):
        self._test_get_admin_password(meta_data={'admin_pass': 'fake pass'})

    def test_get_admin_pass_in_meta(self):
        self._test_get_admin_password(
            meta_data={'meta': {'admin_pass': 'fake pass'}})

    def test_get_admin_pass_no_pass(self):
        self._test_get_admin_password(meta_data={})

    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    @mock.patch(MODPATH +
                ".BaseOpenStackService.get_user_data")
    def _test_get_client_auth_certs(self, mock_get_user_data,
                                    mock_get_meta_data, meta_data,
                                    ret_value=None):
        mock_get_meta_data.return_value = meta_data
        mock_get_user_data.side_effect = [ret_value]
        response = self._service.get_client_auth_certs()
        mock_get_meta_data.assert_called_once_with()
        if isinstance(ret_value, bytes) and ret_value.startswith(
                x509constants.PEM_HEADER.encode()):
            mock_get_user_data.assert_called_once_with()
            self.assertEqual([ret_value.decode()], response)
        elif ret_value is base.NotExistingMetadataException:
            self.assertFalse(response)
        else:
            expected = []
            expectation = {
                "meta": 'fake cert',
                "keys": [key["data"].strip() for key in self._fake_keys
                         if key["type"] == "x509"]
            }
            for field, value in expectation.items():
                if field in meta_data:
                    expected.extend(value if isinstance(value, list)
                                    else [value])
            self.assertEqual(sorted(list(set(expected))), sorted(response))

    def test_get_client_auth_certs(self):
        self._test_get_client_auth_certs(
            meta_data={'meta': {'admin_cert0': 'fake ',
                                'admin_cert1': 'cert'},
                       "keys": self._fake_keys})

    def test_get_client_auth_certs_no_cert_data(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=x509constants.PEM_HEADER.encode())

    def test_get_client_auth_certs_no_cert_data_exception(self):
        self._test_get_client_auth_certs(
            meta_data={}, ret_value=base.NotExistingMetadataException)

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    @mock.patch(MODPATH +
                ".BaseOpenStackService.get_content")
    @mock.patch(MODPATH +
                ".BaseOpenStackService._get_meta_data")
    def _test_get_network_details_builder(self, mock_get_meta_data,
                                          mock_get_content,
                                          mock_osutils,
                                          network_config=None,
                                          search_fail=False):
        mock_get_meta_data().get.return_value = network_config
        if not network_config or search_fail:
            result = self._service._get_network_details_builder()
            self.assertIsNone(result)
            return
        if not self._service._network_details_builder:
            result = self._service._get_network_details_builder()
            self.assertIsInstance(result,
                                  baseopenstackservice._NetworkDetailsBuilder)

    def test_get_network_details_builder_no_config(self):
        self._test_get_network_details_builder()

    def test_get_network_details_builder_no_path(self):
        self._test_get_network_details_builder(network_config="fake_config",
                                               search_fail=True)

    def test_get_network_details_builder(self):
        network_config = {"content_path": "fake_content"}
        self._test_get_network_details_builder(network_config=network_config)


class Test_NetworkDetailsBuilder(unittest.TestCase):

    def setUp(self):
        date = "2013-04-04"
        fake_metadata = fake_json_response.get_fake_metadata_json(date)
        self._fake_network_config = fake_metadata["network_config"]
        self._fake_content = self._fake_network_config["debian_config"]
        self._builder = baseopenstackservice._NetworkDetailsBuilder(
            service=baseopenstackservice.BaseOpenStackService,
            content=self._fake_content)
        self.mock_raw_data = {
            constants.ID: mock.sentinel.id,
            debiface.ADDRESS6: fake_json_response.ADDRESS60,
            debiface.NETMASK6: fake_json_response.NETMASK60,
            debiface.GATEWAY6: fake_json_response.GATEWAY60,
            constants.ASSIGNED_TO: mock.sentinel.assigned_to
        }

    def test_process_link_networks(self):
        link = {constants.ID: mock.sentinel.id}
        res = self._builder._process_link_networks(link,
                                                   self.mock_raw_data)
        self.assertTrue(res)

    def test_process(self):
        self._builder._process()
        self.assertIsNotNone(self._builder._links)

    @mock.patch("cloudbaseinit.metadata.services.basenetworkservice."
                "NetworkDetailsBuilder._get_fields")
    def test_process_invalid(self, mock_get_fields):
        mock_get_fields.return_value = None
        with testutils.LogSnatcher('cloudbaseinit.metadata.services'
                                   '.baseopenstackservice'):
            self._builder._process()

    @mock.patch("cloudbaseinit.utils.debiface.parse")
    def test_process_not_all_fields(self, mock_debiface):
        expected_output = []
        with testutils.LogSnatcher('cloudbaseinit.metadata.services'
                                   '.baseopenstackservice') as snatcher:
            self._builder._process()
        self.assertEqual(expected_output, snatcher.output)

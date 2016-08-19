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
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import constants
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import basenetworkservice as base_ns
from cloudbaseinit.tests.metadata import fake_json_response

MODPATH = "cloudbaseinit.metadata.services.basenetworkservice"


MOCK_RAW_LINK = {
    constants.ID: mock.sentinel.link_id,
    constants.NAME: mock.sentinel.name,
    constants.TYPE: mock.sentinel.type,
    constants.NEUTRON_PORT_ID: mock.sentinel.port_id,
    constants.MAC_ADDRESS: fake_json_response.MAC0,
    constants.MTU: mock.sentinel.mtu,
    constants.BOND_LINKS: mock.sentinel.bondlinks,
    constants.BOND_MODE: mock.sentinel.bondmode,
    constants.BOND_MIIMON: mock.sentinel.miimon,
    constants.BOND_HASH_POLICY: mock.sentinel.hash,
    constants.VIF_ID: mock.sentinel.vif_id,
    constants.VLAN_ID: mock.sentinel.vlan_id,
    constants.VLAN_LINK: mock.sentinel.vlan_link,
    constants.PRIORITY: mock.sentinel.priority}
MOCK_RAW_NETWORK = {
    constants.ID: mock.sentinel.network_id,
    constants.IP_ADDRESS: fake_json_response.ADDRESS0,
    constants.VERSION: mock.sentinel.version,
    constants.NETMASK: fake_json_response.NETMASK0,
    constants.GATEWAY: mock.sentinel.gateway,
    constants.DNS: mock.sentinel.dns_namservers,
    constants.BROADCAST: mock.sentinel.broadcast,
    constants.ASSIGNED_TO: mock.sentinel.assigned_to,
    constants.NEUTRON_NETWORK_ID: mock.sentinel.network_id,
    constants.PRIORITY: mock.sentinel.priority}
MOCK_RAW_ROUTE = {
    constants.ID: mock.sentinel.route_id,
    constants.NETWORK: mock.sentinel.network,
    constants.GATEWAY: mock.sentinel.gateway,
    constants.NETMASK: mock.sentinel.netmask,
    constants.ASSIGNED_TO: mock.sentinel.assigned_to}


class FakeNetworkDetailsBuilder(base_ns.NetworkDetailsBuilder):

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def __init__(self, mock_get_os_utils):
        mock_osutils = mock.MagicMock()
        mock_get_os_utils.return_value = mock_osutils
        service = mock.sentinel.service
        super(FakeNetworkDetailsBuilder, self).__init__(service=service)

    def _process(self):
        pass


class FakeBaseNetworkMetadataService(base_ns.BaseNetworkMetadataService):

    def __init__(self):
        super(FakeBaseNetworkMetadataService, self).__init__()

    def _get_data(self):
        pass

    def _get_network_details_builder(self):
        result_network = mock.MagicMock()
        result_network.get_network_details.return_value = True
        return result_network


class TestNetworkDetails(unittest.TestCase):

    def setUp(self):
        mock_link_value = base_ns.Link(**MOCK_RAW_LINK)
        mock_network_value = base_ns.Network(**MOCK_RAW_NETWORK)
        mock_route_value = base_ns.Route(**MOCK_RAW_ROUTE)
        mock_raw_links = {mock.sentinel.link_id: mock_link_value}
        mock_raw_routes = {mock.sentinel.route_id: mock_route_value}
        mock_raw_networks = {mock.sentinel.network_id:
                             mock_network_value}

        mock_raw_references = {mock.sentinel.link_id:
                               [mock.sentinel.network_id],
                               mock.sentinel.network_id:
                               [mock.sentinel.route_id]}
        self._network_details = base_ns.NetworkDetails(
            links=mock_raw_links,
            networks=mock_raw_networks,
            references=mock_raw_references,
            routes=mock_raw_routes)

    def test_get_links(self):
        result_links = self._network_details.get_links()
        self.assertIsInstance(result_links[0], base_ns.Link)

    def test_get_link_networks(self):
        result_link_ids = self._network_details.get_link_networks(
            mock.sentinel.link_id)
        self.assertIsInstance(result_link_ids[0], base_ns.Network)

    def test_get_network_routes(self):
        result_network_routes = self._network_details.get_network_routes(
            mock.sentinel.network_id)
        self.assertIsInstance(result_network_routes[0], base_ns.Route)


class TestNetworkDetailsBuilder(unittest.TestCase):

    def setUp(self):
        self._network_builder = FakeNetworkDetailsBuilder()

    def test_get_field_missing(self):
        field_name = constants.IP_ADDRESS
        mock_field = self._network_builder._Field(name=field_name,
                                                  alias="ip")
        res = self._network_builder._get_field(mock_field, {})
        self.assertEqual(res, (field_name, None))

    def test_get_field_not_required(self):
        field = base_ns.NetworkDetailsBuilder._Field(name=constants.IP_ADDRESS)
        res = self._network_builder._get_field(field, {})
        self.assertEqual(res, (constants.IP_ADDRESS, None))
        # Cover for a callable default
        mock_callable_default = mock.MagicMock(return_value=None)
        field = (self._network_builder._Field(name=constants.IP_ADDRESS,
                                              default=mock_callable_default))
        res = self._network_builder._get_field(field, {})
        self.assertEqual(res, (constants.IP_ADDRESS, None))

    def test_get_field(self):
        mock_field = self._network_builder._Field(name=constants.IP_ADDRESS,
                                                  alias=["ip", "IP"])
        mock_raw_data = {constants.IP_ADDRESS: mock.sentinel.ip}
        res = self._network_builder._get_field(mock_field, mock_raw_data)
        expected_fields = (constants.IP_ADDRESS, mock.sentinel.ip)
        self.assertEqual(res, expected_fields)

    @mock.patch(MODPATH + '.NetworkDetailsBuilder._get_field')
    def test_get_fields(self, mock_get_field):
        mock_get_field.return_value = (mock.sentinel.field,
                                       mock.sentinel.value)
        expected_data = {mock.sentinel.field: mock.sentinel.value}
        mock_field = mock.MagicMock()
        mock_field.on_error.return_value = True
        mock_fields = (mock_field,)
        result_fields = self._network_builder._get_fields(mock_fields,
                                                          raw_data=None)
        self.assertEqual(result_fields, expected_data)

    def test_process_links(self):
        self._network_builder._links = {mock.sentinel.link_id: MOCK_RAW_LINK}
        result_links = self._network_builder._process_links()
        self.assertIsNotNone(result_links)

    def test_process_links_invalid_links(self):
        self._network_builder._links = {mock.sentinel.link: {
            constants.IP_ADDRESS: mock.sentinel.values,
            constants.MAC_ADDRESS: fake_json_response.MAC0
        }
        }
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_builder._process_links)

    def test_process_networks(self):
        self._network_builder._networks = {mock.sentinel.id: MOCK_RAW_NETWORK}
        result_networks = self._network_builder._process_networks()
        self.assertIsNotNone(result_networks)

    @mock.patch('cloudbaseinit.utils.network.process_interface')
    def test_process_networks_invalid(self, mock_process_interface):
        self._network_builder._networks = {mock.sentinel.link: {
            constants.IP_ADDRESS: mock.sentinel.ip,
            constants.NETMASK: mock.sentinel.netmask
        }
        }
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_builder._process_networks)

    def test_process_routes(self):
        references = {}
        routes = {mock.sentinel.id: MOCK_RAW_ROUTE}
        self._network_builder._routes = routes
        result_routes = self._network_builder._process_routes(references)
        self.assertIsInstance(result_routes[mock.sentinel.route_id],
                              base_ns.Route)

    def test_process_routes_invalid(self):
        mock_refrences = mock.Mock
        mock_raw_route = {
            constants.ID: mock.sentinel.route_id,
            constants.NETWORK: mock.sentinel.network,
        }
        self._network_builder._routes = {mock.sentinel.id: mock_raw_route}
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_builder._process_routes,
                          mock_refrences)

    @mock.patch(MODPATH + '.NetworkDetailsBuilder._process_networks')
    @mock.patch(MODPATH + '.NetworkDetailsBuilder._process_links')
    def test_get_network_details(self, mock_process_links,
                                 mock_process_network):
        mock_process_links.return_value = mock.sentinel.link
        mock_process_network.return_value = (mock.sentinel.networks,
                                             mock.sentinel.references)
        result_network = self._network_builder.get_network_details()
        self.assertIsInstance(result_network, base_ns.NetworkDetails)


class TestBaseNetworkMetadataService(unittest.TestCase):

    def setUp(self):
        self._metadata_service = FakeBaseNetworkMetadataService()

    @mock.patch(MODPATH +
                '.BaseNetworkMetadataService._get_network_details_builder')
    def test_get_network_details(self, mock_network_builder):
        result = self._metadata_service.get_network_details()
        self.assertTrue(result)

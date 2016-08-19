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

# pylint: disable=missing-docstring, protected-access, too-few-public-methods

import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import basenetworkservice as base_ns
from cloudbaseinit import model as network_model
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils

MODPATH = "cloudbaseinit.metadata.services.basenetworkservice"


_MOCK_RAW_LINK = {
    constant.LINK_ID: mock.sentinel.link_id,
    constant.NAME: mock.sentinel.name,
    constant.MAC_ADDRESS: fake_json_response.MAC0,
    constant.MTU: mock.sentinel.mtu,
    constant.LINK_TYPE: mock.sentinel.link_type,
    constant.PRIORITY: mock.sentinel.priority}
_MOCK_RAW_NETWORK = {
    constant.SUBNET_ID: mock.sentinel.network_id,
    constant.NETWORK_TYPE: mock.sentinel.network_type,
    constant.ASSIGNED_TO: mock.sentinel.link_id,
    constant.PRIORITY: mock.sentinel.priority}
_MOCK_RAW_ROUTE = {
    constant.ROUTE_ID: mock.sentinel.route_id,
    constant.NETWORK: mock.sentinel.network,
    constant.GATEWAY: mock.sentinel.gateway,
    constant.NETMASK: mock.sentinel.netmask,
    constant.ASSIGNED_TO: mock.sentinel.network_id}


class _DataModel(network_model.Model):

    name = network_model.Field(name=constant.NAME, allow_none=False)
    mac_address = network_model.Field(name=constant.MAC_ADDRESS)
    mtu = network_model.Field(name=constant.MTU)


class _NetworkDetailsBuilder(base_ns.NetworkDetailsBuilder):

    _SUPPORTED_MODELS = (base_ns.NetworkDetailsBuilder._SUPPORTED_MODELS +
                         (_DataModel, ))

    def __init__(self):
        service = mock.sentinel.service
        super(_NetworkDetailsBuilder, self).__init__(service)

    def _process(self):
        pass


class TestNetworkDetails(unittest.TestCase):

    def setUp(self):
        mock_link = network_model.Link(**_MOCK_RAW_LINK)
        mock_network = network_model.Subnetwork(**_MOCK_RAW_NETWORK)
        mock_route = network_model.Route(**_MOCK_RAW_ROUTE)

        self._network_details = base_ns.NetworkDetails(
            links={mock.sentinel.link_id: mock_link},
            networks={mock.sentinel.network_id: mock_network},
            routes={mock.sentinel.route_id: mock_route})

    def test_get_link(self):
        link_id = mock.sentinel.link_id
        result_link = self._network_details.get_link(link_id)
        self.assertEqual(result_link, self._network_details._links[link_id])

    def test_get_links(self):
        result_links = self._network_details.get_links()
        self.assertIsInstance(result_links[0], network_model.Link)

    def test_get_link_networks(self):
        result_link_ids = self._network_details.get_link_networks(
            mock.sentinel.link_id)
        self.assertIsInstance(result_link_ids[0], network_model.Subnetwork)

    def test_get_network_routes(self):
        result_network_routes = self._network_details.get_network_routes(
            mock.sentinel.network_id)
        self.assertIsInstance(result_network_routes[0], network_model.Route)


class TestBaseNetworkMetadataService(unittest.TestCase):

    def setUp(self):

        class _BaseNetworkMetadataService(base_ns.BaseNetworkMetadataService):

            def _get_network_details_builder(self):
                builder = mock.Mock()
                mock_builder = mock.sentinel.builder
                builder.get_network_details.return_value = mock_builder
                return builder

            def _get_data(self, path):
                return path

        self._network_service = _BaseNetworkMetadataService()

    def test_get_network_details(self):
        result_details = self._network_service.get_network_details()
        self.assertIs(result_details, mock.sentinel.builder)


class TestNetworkDetailsBuilder(unittest.TestCase):

    def setUp(self):
        self._network_builder = _NetworkDetailsBuilder()
        self._alias = self._network_builder.Alias

    def test_apply_mapping(self):
        aliases = (self._alias(field="field1_", name="_field1"),
                   self._alias(field="field2_", name="_field2"))
        raw_data = {"_field1": mock.sentinel.field1,
                    "_field2": mock.sentinel.field2}
        expected = {"field1_": mock.sentinel.field1,
                    "field2_": mock.sentinel.field2}

        result = self._network_builder._apply_mapping(raw_data, aliases)

        self.assertEqual(result, expected)

    def test_get_model(self):
        link_fields = _MOCK_RAW_LINK.keys()
        models = self._network_builder._SUPPORTED_MODELS

        model = self._network_builder._get_model(link_fields, models)
        self.assertEqual(model, network_model.Link)

    def test_add_link(self):
        expected_logging = [
            'Adding %s %r to NetworkDetails object.' %
            (network_model.Link(), mock.sentinel.link_id)
        ]
        with testutils.LogSnatcher(MODPATH) as snatcher:
            link = self._network_builder._add_link(_MOCK_RAW_LINK)

        self.assertIsInstance(link, network_model.Link)
        self.assertEqual(snatcher.output, expected_logging)

    def test_add_subnetwork(self):
        expected_logging = [
            'Adding %s %r assigned to %s to NetworkDetails object.' %
            (network_model.Subnetwork(), mock.sentinel.network_id,
             mock.sentinel.link_id)
        ]
        with testutils.LogSnatcher(MODPATH) as snatcher:
            network = self._network_builder._add_subnetwork(_MOCK_RAW_NETWORK)

        self.assertIsInstance(network, network_model.Subnetwork)
        self.assertEqual(snatcher.output, expected_logging)

    def test_add_route(self):
        expected_logging = [
            'Adding %s %r assigned to %s to NetworkDetails object.' %
            (network_model.Route(), mock.sentinel.route_id,
             mock.sentinel.network_id)
        ]
        with testutils.LogSnatcher(MODPATH) as snatcher:
            route = self._network_builder._add_route(_MOCK_RAW_ROUTE)

        self.assertIsInstance(route, network_model.Route)
        self.assertEqual(snatcher.output, expected_logging)

    def test_create_entity(self):
        mock_models = self._network_builder._SUPPORTED_MODELS
        link = self._network_builder._create_entity(_MOCK_RAW_LINK,
                                                    mock_models)

        self.assertIsInstance(link, network_model.Link)

    def test_create_entity_no_model(self):
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_builder._create_entity, {})

    def test_create_entity_fail(self):
        mock_raw_data = {constant.MAC_ADDRESS: 1, constant.MTU: 1}
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_builder._create_entity,
                          raw_data=mock_raw_data, models=(_DataModel, ))

    def test_get_network_details(self):
        expected_logging = ['Processing available network information.']
        with testutils.LogSnatcher(MODPATH) as snatcher:
            res = self._network_builder.get_network_details()
        self.assertEqual(snatcher.output, expected_logging)
        self.assertIsInstance(res, base_ns.NetworkDetails)

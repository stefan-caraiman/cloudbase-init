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

import six
import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.metadata.services import base


class FakeService(base.BaseMetadataService):

    def _get_data(self):
        return (b'\x1f\x8b\x08\x00\x93\x90\xf2U\x02'
                b'\xff\xcbOSH\xce/-*NU\xc8,Q(\xcf/\xca.'
                b'\x06\x00\x12:\xf6a\x12\x00\x00\x00')

    def get_user_data(self):
        return self._get_data()


class FakeAdaptor(base.BaseNetworkAdapter):

    def __init__(self, service):
        super(FakeAdaptor, self).__init__(service=service)
        self._fields = {}
        mro = type(self).mro()
        while mro:
            parent = mro.pop()
            try:
                fields = getattr(parent, "FIELDS")
                self._fields.update(fields)
            except AttributeError:
                pass
        self._links = {
            mock.sentinel.link1: {
                base.NAME: mock.sentinel.name,
                base.MAC_ADDRESS: mock.sentinel.mac,
            },
            mock.sentinel.link2: {
                base.NAME: mock.sentinel.name,
                base.MAC_ADDRESS: mock.sentinel.mac,
            },
        }
        self._networks = {
            mock.sentinel.net1: {
                base.NAME: mock.sentinel.net1,
                base.IP_ADDRESS: mock.sentinel.address4,
                base.VERSION: 4,
            },
            mock.sentinel.net2: {
                base.NAME: mock.sentinel.net2,
                base.IP_ADDRESS: mock.sentinel.address6,
                base.VERSION: 6,
            }
        }

    def get_fake_link(self):
        link = {base.NAME: mock.sentinel.name,
                base.MAC_ADDRESS: mock.sentinel.mac}
        return link

    def get_fake_network(self):
        network = {base.NAME: mock.sentinel.net1,
                   base.IP_ADDRESS: mock.sentinel.address4,
                   base.VERSION: 4}
        return network

    def fake_networks(self):
        link = (self.get_fake_link())
        network = (self.get_fake_network())
        yield link, network

    def get_digested_network(self):
        return {
            mock.sentinel.name: {
                'name': mock.sentinel.name,
                'mac_address': mock.sentinel.mac,
                'network': {
                    4: {'version': 4,
                        'ip_address': mock.sentinel.address4,
                        'name': mock.sentinel.net1
                        }
                }
            }
        }

    def get_link(self, name):
        """Return all the information related to the link."""
        return self._links[name]

    def get_links(self):
        """Return a list with the names of the available links."""
        return self._links.keys()

    def get_network(self, link, name):
        """Return all the information related to the network."""
        return self._networks[name]

    def get_networks(self, link):
        """Returns all the network names bound by the required link."""
        return self._networks.keys()


class TestBase(unittest.TestCase):

    def setUp(self):
        self._service = FakeService()

    def test_get_decoded_user_data(self):
        userdata = self._service.get_decoded_user_data()
        self.assertEqual(b"of course it works", userdata)

    def test_get_name(self):
        class_name = self._service.get_name()
        self.assertEqual(class_name, 'FakeService')

    def test_load(self):
        service_cache = self._service._cache
        self._service.load()
        self.assertEqual(service_cache, {})

    def test_get_network_details_none(self):
        self.assertIsNone(self._service.get_network_details())

    def test_get_network_details(self):
        self._service._network_adapter = mock.Mock()
        self._service._network_config = (mock.Mock(
                                         return_value=base.NetworkConfig))
        mock_network = self._service.get_network_details()
        mock_network.get_network_details.return_value = []
        result = mock_network.get_network_details()
        self.assertEqual([], result)


class TestAdaptor(unittest.TestCase):

    def setUp(self):
        self._adaptor = FakeAdaptor(mock.sentinel.service)

    def test_digest_interface(self):
        address_ip4 = u'192.168.0.1'
        address_ip6 = u'2001:db8::1'
        expected_interface4 = {
            'broadcast': '192.168.0.1',
            'netmask': '255.255.255.255',
            'version': 4,
            'ip_address': '192.168.0.1'}
        expected_interface6 = {
            'broadcast': '2001:db8::1',
            'netmask': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            'version': 6,
            'ip_address': '2001:db8::1'}
        result_interface4 = self._adaptor._digest_interface(address_ip4)
        result_interface6 = self._adaptor._digest_interface(address_ip6)
        self.assertEqual(result_interface4, expected_interface4)
        self.assertEqual(result_interface6, expected_interface6)

    def test_get_field(self):
        mock_field = (base.Field(name='type', alias=None,
                      default=None, required=True))
        result = self._adaptor._get_field(mock_field, "")
        self.assertRaises(result)

    @mock.patch("cloudbaseinit.metadata.services.base.BaseNetworkAdapter"
                "._get_field")
    def test_get_fields_fail(self, mock_field):
        mock_field.side_effect = ValueError
        self.assertRaises(ValueError, self._adaptor._get_field, mock_field)
        fields = [mock.sentinel.fields]
        result_data = self._adaptor.get_fields(fields, None)
        self.assertEqual(result_data, None)

    @mock.patch("cloudbaseinit.metadata.services.base.BaseNetworkAdapter"
                "._get_field")
    def test_get_fields(self, mock_field):
        mock_field.return_value = (mock.sentinel.name, mock.sentinel.field)
        mock_fields = [mock.sentinel.field]
        raw_data = mock.sentinel.data
        result = self._adaptor.get_fields(mock_fields, raw_data)
        expected_result = {mock.sentinel.name: mock.sentinel.field}
        self.assertEqual(result, expected_result)

    def test_get_link(self):
        mock_link_name = mock.sentinel.link1
        mock_link = self._adaptor.get_fake_link()
        result_link = self._adaptor.get_link(mock_link_name)
        self.assertEqual(mock_link, result_link)

    def test_get_links(self):
        mock_links = self._adaptor._links.keys()
        result_links = self._adaptor.get_links()
        self.assertEqual(result_links, mock_links)

    def test_get_network(self):
        mock_network_name = mock.sentinel.net1
        mock_link_name = base.NAME
        result_network = (self._adaptor.get_network(mock_link_name,
                          mock_network_name))
        expected_result = self._adaptor.get_fake_network()
        self.assertEqual(result_network, expected_result)

    def test_get_networks(self):
        mock_networks = self._adaptor._networks.keys()
        mock_link = mock.sentinel.link
        mock_networks_result = self._adaptor.get_networks(mock_link)
        self.assertEqual(mock_networks, mock_networks_result)


class TestNetworkConfig(unittest.TestCase):

    def setUp(self):
        self._adaptor = FakeAdaptor(mock.sentinel.service)
        self._config = base.NetworkConfig(self._adaptor)

    def test_digest(self):
        mock_get_networks = mock.MagicMock()
        self._config._get_networks = mock_get_networks
        networks = self._adaptor.fake_networks()
        mock_get_networks.return_value = networks
        digested_network = self._adaptor.get_digested_network()
        self.assertEqual(self._config._digest(), digested_network)

    def test_get_networks(self):
        fake_networks = self._adaptor.fake_networks()
        fake_networks = six.next(fake_networks)
        network = self._config._get_networks()
        network = six.next(network)
        self.assertEqual(network, fake_networks)

    def test_get_network_details(self):
        mock_networks = self._config._networks = mock.MagicMock()
        self.assertEqual(mock_networks, self._config.get_network_details())

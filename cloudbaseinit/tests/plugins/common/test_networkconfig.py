# Copyright 2013 Cloudbase Solutions Srl
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
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.plugins.common import networkconfig
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils


MODPATH = "cloudbaseinit.plugins.common.networkconfig"


class FakeNetworkConfigPlugin(networkconfig.NetworkConfigPlugin):

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def __init__(self, mock_get_os_utils):
        mock_osutils = mock.MagicMock()
        mock_get_os_utils.return_value = mock_osutils
        super(FakeNetworkConfigPlugin, self).__init__()


class TestNetworkConfigPlugin(unittest.TestCase):

    def setUp(self):
        self._network_plugin = FakeNetworkConfigPlugin()

    def test_update_link(self):
        attribs = {k: k for k in service_base.LINK_FIELDS}
        mock_link = mock.Mock(**attribs)
        res = (self._network_plugin._update_link(
               mock_link, {service_base.LINK_FIELDS[0]: "fake_id"}))
        self.assertEqual(res.id, 'fake_id')

    def test_validate_link(self):
        mock_link = mock.Mock
        mock_link.mac_address = fake_json_response.MAC0
        res = self._network_plugin._validate_link(mock_link)
        self.assertEqual(res, mock_link)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._on_mac_not_found')
    def test_validate_link_missing_mac(self, mock_mac_not_found):
        mock_link = mock.MagicMock()
        mock_link.mac_address = None
        mock_mac_not_found.return_value = None
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_plugin._validate_link, mock_link)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._update_link')
    @mock.patch(MODPATH + '.NetworkConfigPlugin._on_mac_not_found')
    def test_validate_link_new_link(self, mock_mac_not_found,
                                    mock_update_link):
        mock_link = mock.Mock
        mock_update_link.return_value = "fake_link"
        mock_link.mac_address = None
        mock_mac_not_found.return_value = fake_json_response.MAC0
        res = self._network_plugin._validate_link(mock_link)
        self.assertEqual(res, 'fake_link')

    def test_update_network(self):
        attribs = {k: k for k in service_base.NETWORK_FIELDS}
        mock_link = mock.Mock(**attribs)
        res = (self._network_plugin._update_network(
               mock_link, {service_base.NETWORK_FIELDS[0]: "fake_id"}))
        self.assertEqual(res.id, 'fake_id')

    def test_validate_network(self):
        fake_ip = fake_json_response.ADDRESS0 + "/24"
        mock_network = mock.Mock(netmask=None, gateway=None,
                                 ip_address=fake_ip)
        mock_route = mock.Mock(network=fake_json_response.ADDRESS0,
                               gateway=fake_json_response.GATEWAY0,
                               netmask='32')
        mock_routes = [mock_route]
        res = self._network_plugin._validate_network(mock_network, mock_routes)
        self.assertIsInstance(res, service_base.Network)

    def test_validate_network_netmask_missing(self):
        mock_route = mock_network = mock.Mock()
        mock_network.netmask = None
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_plugin._validate_network,
                          mock_network, mock_route)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._on_gateway_not_found')
    def test_validate_network_gateway_missing(self, mock_gateway_not_found):
        mock_route = mock.Mock()
        mock_network = mock.Mock(netmask=fake_json_response.NETMASK60,
                                 gateway=None)
        mock_gateway_not_found.return_value = None
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_plugin._validate_network, mock_network,
                          mock_route)

    def test_on_mac_not_found_fail(self):
        mock_link = mock.Mock
        mock_link.name = None
        res = self._network_plugin._on_mac_not_found(mock_link)
        self.assertIsNone(res)

    def test_on_mac_not_found_found(self):
        mock_link = mock.Mock
        mock_link.name = "fake_name"
        self._network_plugin._adapters = [(mock.sentinel.name,
                                           mock.sentinel.mac)]
        res = self._network_plugin._on_mac_not_found(mock_link)
        self.assertIsNone(res)

    def test_on_mac_not_found(self):
        mock_link = mock.Mock
        mock_link.name = "fake_name"
        self._network_plugin._adapters = [("fake_name",
                                           fake_json_response.MAC0)]
        res = self._network_plugin._on_mac_not_found(mock_link)
        self.assertEqual(res, fake_json_response.MAC0.upper())

    def _test_on_netmask_not_found(self, network):
        if not network.ip_address:
            res = self._network_plugin._on_netmask_not_found(network)
            self.assertIsNone(res)
            return
        if "/" not in network.ip_address:
            res = self._network_plugin._on_netmask_not_found(network)
            self.assertIsNone(res)
            return
        else:
            res = self._network_plugin._on_netmask_not_found(network)
            self.assertIsNotNone(res)

    def test_on_netmask_not_found_no_ip(self):
        mock_network = mock.Mock(ip_address=None)
        self._test_on_netmask_not_found(mock_network)

    def test_on_netmask_not_found(self):
        ip_address = fake_json_response.ADDRESS0
        netmask = '/24'
        mock_ip_address = ip_address + netmask
        mock_network = mock.Mock(ip_address=mock_ip_address)
        self._test_on_netmask_not_found(mock_network)

    def test_on_netmask_not_found_fail(self):
        mock_network = mock.Mock(ip_address=fake_json_response.ADDRESS0)
        self._test_on_netmask_not_found(mock_network)

    def test_on_gateway_not_found_incomplete(self):
        mock_route = mock.Mock(network=fake_json_response.ADDRESS0,
                               gateway=fake_json_response.GATEWAY0,
                               netmask=None)
        routes = [mock_route]
        expected_output = ["The route {} does not contains all the "
                           "required fields.".format(mock_route),
                           "No extra information regarding gateway available."]
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'common.networkconfig') as snatcher:
            self._network_plugin._on_gateway_not_found(routes)
        self.assertEqual(snatcher.output, expected_output)

    def test_on_gateway_not_found(self):
        mock_route = mock.Mock(network=fake_json_response.ADDRESS0,
                               gateway=fake_json_response.GATEWAY0,
                               netmask='32')
        routes = [mock_route]
        res = self._network_plugin._on_gateway_not_found(routes)
        self.assertEqual(res, fake_json_response.GATEWAY0)

    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def test_set_static_network_config_v4(self, mock_get_os_utils):
        mock_network = mock.MagicMock()
        mock_link = mock.MagicMock()
        (mock_network.ip_address, mock_network.netmask, mock_network.gateway,
         mock_network.broadcast, mock_network.dns_nameservers) = (
            mock.sentinel.ip_address, mock.sentinel.netmask,
            mock.sentinel.gateway, mock.sentinel.broadcast,
            mock.sentinel.dns_nameservers)
        mock_link.mac_address = mock.sentinel.mac_address
        result_config = (self._network_plugin._set_static_network_config_v4(
            mock_link, mock_network))
        self.assertTrue(result_config)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._validate_network')
    def test_configure_phy_fail(self, mock_validate_network):
        mock_link = mock.Mock
        mock_net_details = mock.Mock()
        self._network_plugin._network_details = mock_net_details
        mock_net_details.get_link_networks.return_value = [mock_link]
        mock_net_details.get_network_routes.return_value = "fake_route"
        mock_link.mac_address = fake_json_response.MAC0
        mock_link.id = mock.sentinel.id
        mock_validate_network.side_effect = exception.NetworkDetailsError
        res = self._network_plugin._configure_phy(mock_link)
        self.assertFalse(res)

    def test_configure_phy(self):
        mock_net_details = mock_network = mock_link = mock.MagicMock()
        self._network_plugin._network_details = mock_net_details
        mock_net_details.get_link_networks.return_value = (mock_network,)
        mock_network.version = constants.IPV6
        mock_link.id = mock.sentinel.id
        result_config = self._network_plugin._configure_phy(mock_link)
        self.assertFalse(result_config)
        mock_network.version = constants.IPV4
        result_config = self._network_plugin._configure_phy(mock_link)
        self.assertIsNotNone(result_config)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._configure_phy')
    def test_configure_interface(self, mock_config_phy):
        mock_link = mock.MagicMock(mac_address=None, name=None, type=None)
        self.assertRaises(exception.NetworkDetailsError,
                          self._network_plugin._configure_interface, mock_link)
        mock_link.type = constants.PHY
        mock_link.name = "fake_name"
        mock_link.mac_address = fake_json_response.MAC0
        res = self._network_plugin._configure_interface(mock_link)
        self.assertTrue(res)

    @mock.patch(MODPATH + '.NetworkConfigPlugin._configure_interface')
    def _test_execute(self, mock_conf_interface, details, conf_error=False,
                      expected_output=None):
        mock_service = mock.MagicMock()
        mock_link = mock.MagicMock()
        mock_shared_data = mock.Mock()
        mock_service.get_network_details.return_value = details
        expected_result = (1, False)
        if not details:
            ret = self._network_plugin.execute(mock_service, mock_shared_data)
            self.assertEqual(ret, expected_result)
        if not isinstance(details, service_base.NetworkDetails) and details:
            exc = exception.CloudbaseInitException
            self.assertRaises(exc, self._network_plugin.execute,
                              mock_service, mock_shared_data)
        elif isinstance(details, service_base.NetworkDetails):
            details.get_links.return_value = [mock_link]
            mock_link.mac_address = fake_json_response.MAC0
            if conf_error:
                exc = exception.NetworkDetailsError("error")
                mock_conf_interface.side_effect = [exc]
                with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                           'common.networkconfig') as snatcher:
                    ret = self._network_plugin.execute(mock_service,
                                                       mock_shared_data)
                self.assertEqual(expected_output, snatcher.output[-2::])
                self.assertEqual(ret, expected_result)
            else:
                expected_result = (1, True)
                mock_conf_interface.return_value = True
                ret = self._network_plugin.execute(mock_service,
                                                   mock_shared_data)
                self.assertEqual(ret, expected_result)

    def test_execute_information_not_available(self):
        self._test_execute(details=None)

    def test_execute_invalid_network_details(self):
        mock_details = mock.MagicMock()
        self._test_execute(details=mock_details)

    def test_execute_failed_to_configure(self):
        mock_details = mock.MagicMock()
        mock_details.__class__ = service_base.NetworkDetails
        output = [
            ("Failed to configure the interface %r: %s" %
                (fake_json_response.MAC0, 'error')),
            'No adapters were configured']
        self._test_execute(details=mock_details, conf_error=True,
                           expected_output=output)

    def test_execute_reboot(self):
        mock_details = mock.MagicMock()
        mock_details.__class__ = service_base.NetworkDetails
        self._test_execute(details=mock_details)

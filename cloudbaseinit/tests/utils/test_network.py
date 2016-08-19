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

import six
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import network


CONF = cloudbaseinit_conf.CONF


class NetworkUtilsTest(unittest.TestCase):

    @mock.patch('sys.platform', new='win32')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('six.moves.urllib.parse.urlparse')
    def _test_check_metadata_ip_route(self, mock_urlparse, mock_get_os_utils,
                                      side_effect):
        mock_utils = mock.MagicMock()
        mock_split = mock.MagicMock()
        mock_get_os_utils.return_value = mock_utils
        mock_utils.check_os_version.return_value = True
        mock_urlparse().netloc.split.return_value = mock_split
        mock_split[0].startswith.return_value = True
        mock_utils.check_static_route_exists.return_value = False
        mock_utils.get_default_gateway.return_value = (1, '0.0.0.0')
        mock_utils.add_static_route.side_effect = [side_effect]
        network.check_metadata_ip_route('196.254.196.254')
        mock_utils.check_os_version.assert_called_once_with(6, 0)
        mock_urlparse.assert_called_with('196.254.196.254')
        mock_split[0].startswith.assert_called_once_with("169.254.")
        mock_utils.check_static_route_exists.assert_called_once_with(
            mock_split[0])
        mock_utils.get_default_gateway.assert_called_once_with()
        mock_utils.add_static_route.assert_called_once_with(
            mock_split[0], "255.255.255.255", '0.0.0.0', 1, 10)

    def test_test_check_metadata_ip_route(self):
        self._test_check_metadata_ip_route(side_effect=None)

    def test_test_check_metadata_ip_route_fail(self):
        with testutils.LogSnatcher('cloudbaseinit.utils.network') as snatcher:
            self._test_check_metadata_ip_route(side_effect=ValueError)

        self.assertIn('ValueError', snatcher.output[-1])

    def test_address6_to_4_truncate(self):
        address_map = {
            "0:0:0:0:0:ffff:c0a8:f": "192.168.0.15",
            "::ffff:c0a8:e": "192.168.0.14",
            "::1": "0.0.0.1",
            "1:2:3:4:5::8": "0.0.0.8",
            "::": "0.0.0.0",
            "::7f00:1": "127.0.0.1"
        }
        for v6, v4 in address_map.items():
            self.assertEqual(v4, network.address6_to_4_truncate(v6))

    def test_netmask6_to_4_truncate(self):
        netmask_map = {
            "128": "255.255.255.255",
            "96": "255.255.255.0",
            "0": "0.0.0.0",
            "100": "255.255.255.128"
        }
        for v6, v4 in netmask_map.items():
            self.assertEqual(v4, network.netmask6_to_4_truncate(v6))

    def _test_netmask_to_int(self, mock_netmask):
        if mock_netmask is None:
            res = network.netmask_to_int(mock_netmask)
            self.assertIsNone(res)
            return
        if isinstance(mock_netmask, six.string_types) and (mock_netmask.
                                                           isdigit()):
            res = network.netmask_to_int(mock_netmask)
            self.assertIsInstance(res, int)
            return
        else:
            res = network.netmask_to_int(mock_netmask)
            self.assertIsInstance(res, int)

    def test_netmask_to_int_netmask_none(self):
        mock_netmask = None
        self._test_netmask_to_int(mock_netmask)

    def test_netmask_to_int_digit_netmask(self):
        mock_netmask = fake_json_response.NETMASK60
        self._test_netmask_to_int(mock_netmask)

    def test_netmask_to_int(self):
        mock_netmask = six.u(fake_json_response.NETMASK0)
        self._test_netmask_to_int(mock_netmask)

    def test_digest_interface(self):
        mock_address = six.u(fake_json_response.ADDRESS0)
        mock_netmask = fake_json_response.NETMASK1
        expected_interface = {
            constant.BROADCAST: fake_json_response.BROADCAST0,
            constant.NETMASK: 24,
            constant.VERSION: constant.IPV4,
            constant.IP_ADDRESS: fake_json_response.ADDRESS0}
        result_interface = (network.process_interface(mock_address,
                                                      mock_netmask))
        self.assertEqual(result_interface, expected_interface)
        # Cover for ip_address with port given
        mock_address += "/24"
        result_interface = (network.process_interface(mock_address))
        self.assertEqual(result_interface, expected_interface)

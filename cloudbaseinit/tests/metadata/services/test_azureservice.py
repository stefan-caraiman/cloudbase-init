# Copyright 2017 Cloudbase Solutions Srl
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

import os
import unittest

import six
try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import azureservice
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF
MODPATH = "cloudbaseinit.metadata.services.azureservice.AzureService"


class AzureServiceTest(unittest.TestCase):

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def setUp(self, mock_osutils):
        self._azureservice = azureservice.AzureService()
        self._logsnatcher = testutils.LogSnatcher("cloudbaseinit.metadata"
                                                  ".services.azureservice")

    @mock.patch('time.sleep')
    @mock.patch('socket.inet_ntoa')
    @mock.patch('cloudbaseinit.utils.dhcp.get_dhcp_options')
    def _test_get_wire_server_endpoint_address(self, mock_dhcp,
                                               mock_inet_ntoa,
                                               mock_time_sleep,
                                               dhcp_option=None):
        mock_dhcp.return_value = dhcp_option
        if not dhcp_option:
            self.assertRaises(exception.MetadaNotFoundException,
                              (self._azureservice.
                               _get_wire_server_endpoint_address))
        else:
            mock_inet_ntoa.return_value = mock.sentinel.endpoint
            res = self._azureservice._get_wire_server_endpoint_address()
            self.assertEqual(res, mock.sentinel.endpoint)

    def test_get_wire_server_endpoint_address_no_endpoint(self):
        self._test_get_wire_server_endpoint_address()

    def test_get_wire_server_endpoint_address(self):
        dhcp_option = {
            azureservice.WIRESERVER_DHCP_OPTION: 'mock.sentinel.endpoint'}
        self._test_get_wire_server_endpoint_address(dhcp_option=dhcp_option)

    @mock.patch('cloudbaseinit.metadata.services.base.'
                'BaseHTTPMetadataService._http_request')
    def _test_wire_server_request(self,
                                  mock_http_request, mock_base_url=None,
                                  path=None, data_xml=None, headers=None,
                                  parse_xml=True):
        self._azureservice._base_url = mock_base_url
        if not mock_base_url:
            self.assertRaises(exception.CloudbaseInitException,
                              self._azureservice._wire_server_request, path)
            return
        if headers and data_xml:
            expected_headers = self._azureservice._headers.copy()
            expected_headers["Content-Type"] = "text/xml; charset=utf-8"
            expected_headers.update(headers)
            self._azureservice._wire_server_request(path, data_xml, headers,
                                                    parse_xml)
            mock_http_request.assert_called_once_with(path, data_xml,
                                                      headers=expected_headers)
            return
        mock_http_request.return_value = mock.sentinel.data
        res = self._azureservice._wire_server_request(path, data_xml,
                                                      headers, parse_xml)
        self.assertEqual(mock_http_request.call_count, 1)
        self.assertEqual(res, mock.sentinel.data)

    def test_wire_server_request_url_not_set(self):
        self._test_wire_server_request()

    def test_wire_server_request_url_set_no_parse(self):
        mock_base_url = "fake-url"
        self._test_wire_server_request(mock_base_url=mock_base_url,
                                       parse_xml=False)

    def test_wire_server_request_url_set_with_headers(self):
        mock_base_url = "fake-url"
        self._test_wire_server_request(mock_base_url=mock_base_url,
                                       parse_xml=False,
                                       headers={"fake-header": "fake-value"},
                                       data_xml="fake-data")

    def test_encode_xml(self):
        fake_root_xml = azureservice.ElementTree.Element("faketag")
        expected_encoded_xml = ("<?xml version='1.0' encoding='utf-8'?>"
                                "\n<faketag />").encode()
        self.assertEqual(self._azureservice._encode_xml(fake_root_xml),
                         expected_encoded_xml)

    @mock.patch(MODPATH + "._get_role_instance_id")
    @mock.patch(MODPATH + "._get_container_id")
    @mock.patch(MODPATH + "._get_incarnation")
    def test__get_health_report_xml(self, mock_get_incarnation,
                                    mock_get_container_id,
                                    mock_get_role_instance_id):
        mock_state = 'FakeState'
        mock_substatus = 'FakeStatus'
        mock_description = 'FakeDescription'
        mock_get_incarnation.return_value = "fake"
        mock_get_container_id.return_value = "fakeid"
        mock_get_role_instance_id.return_value ="fakeroleid"
        x = self._azureservice._get_health_report_xml(mock_state,
                                                      mock_substatus,
                                                      mock_description)
        pass
        # To do

    @mock.patch(MODPATH + "._wire_server_request")
    def test_get_goal_state(self, mock_wire_server_request):
        mock_goalstate = mock.Mock()
        mock_wire_server_request.return_value = mock_goalstate
        self.assertRaises(exception.CloudbaseInitException,
                          self._azureservice._get_goal_state)
        mock_wire_server_request.assert_called_once_with(
            "machine?comp=goalstate")
        # to do

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_incarnation(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Incarnation.cdata = mock.sentinel.cdata

        res = self._azureservice._get_incarnation()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_container_id(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.ContainerId.cdata = mock.sentinel.cdata

        res = self._azureservice._get_container_id()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_role_instance_config(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_role = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.RoleInstanceList.RoleInstance = mock_role
        mock_role.Configuration = mock.sentinel.config_role

        res = self._azureservice._get_role_instance_config()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.config_role)

    @mock.patch(MODPATH + "._get_goal_state")
    def test__get_role_instance_id(self, mock_get_goal_state):
        mock_goal_state = mock.Mock()
        mock_role = mock.Mock()
        mock_get_goal_state.return_value = mock_goal_state
        mock_goal_state.Container.RoleInstanceList.RoleInstance = mock_role
        mock_role.InstanceId.cdata = mock.sentinel.config_role

        res = self._azureservice._get_role_instance_id()
        mock_get_goal_state.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.config_role)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_health_report_xml")
    def test__post_health_status(self, mock_get_health_report_xml,
                                 mock_wire_server_request):
        mock_get_health_report_xml.return_value = mock.sentinel.report_xml
        mock_state = mock.sentinel.state
        expected_logging = ["Health data: %s" % mock.sentinel.report_xml]
        with self._logsnatcher:
            self._azureservice._post_health_status(state=mock_state)
        self.assertEqual(self._logsnatcher.output, expected_logging)
        mock_get_health_report_xml.assert_called_once_with(mock_state,
                                                           None, None)
        mock_wire_server_request.assert_called_once_with(
            "machine?comp=health", mock.sentinel.report_xml, parse_xml=False)

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_started(self, mock_post_health_status):
        self._azureservice.provisioning_started()
        mock_post_health_status.assert_called_once_with(
            azureservice.HEALTH_STATE_NOT_READY,
            azureservice.HEALTH_SUBSTATE_PROVISIONING,
            "Cloudbase-Init is preparing your computer for first use...")

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_completed(self, mock_post_health_status):
        self._azureservice.provisioning_completed()
        mock_post_health_status.assert_called_once_with(
            azureservice.HEALTH_STATE_READY)

    @mock.patch(MODPATH + "._post_health_status")
    def test_provisioning_failed(self, mock_post_health_status):
        self._azureservice.provisioning_failed()
        mock_post_health_status.assert_called_once_with(
            azureservice.HEALTH_STATE_NOT_READY,
            azureservice.HEALTH_SUBSTATE_PROVISIONING_FAILED,
            "Provisioning failed")

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_properties_xml")
    def test__post_role_properties(self, mock_get_role_properties_xml,
                                   mock_wire_server_request):
        mock_properties = mock.sentinel.properties
        mock_get_role_properties_xml.return_value = mock_properties
        expected_logging = ["Role properties data: %s" % mock_properties]
        with self._logsnatcher:
            self._azureservice._post_role_properties(mock_properties)
        self.assertEqual(self._logsnatcher.output, expected_logging)
        mock_get_role_properties_xml.assert_called_once_with(mock_properties)
        mock_wire_server_request.assert_called_once_with(
            "machine?comp=roleProperties", mock_properties, parse_xml=False)

    def test_can_post_rdp_cert_thumbprint(self):
        self.assertTrue(self._azureservice.can_post_rdp_cert_thumbprint)

    @mock.patch(MODPATH + "._post_role_properties")
    def test_post_rdp_cert_thumbprint(self, mock_post_role_properties):
        mock_thumbprint = mock.sentinel.thumbprint
        self._azureservice.post_rdp_cert_thumbprint(mock_thumbprint)
        expected_props = {
            azureservice.ROLE_PROPERTY_CERT_THUMB: mock_thumbprint}
        mock_post_role_properties.assert_called_once_with(expected_props)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_hosting_environment(self, mock_get_role_instance_config,
                                      mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.HostingEnvironmentConfig.cdata = mock.sentinel.data

        self._azureservice._get_hosting_environment()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_shared_config(self, mock_get_role_instance_config,
                                mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.SharedConfig.cdata = mock.sentinel.data

        self._azureservice._get_shared_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_extensions_config(self, mock_get_role_instance_config,
                                    mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.ExtensionsConfig.cdata = mock.sentinel.data

        self._azureservice._get_extensions_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @mock.patch(MODPATH + "._wire_server_request")
    @mock.patch(MODPATH + "._get_role_instance_config")
    def test__get_full_config(self, mock_get_role_instance_config,
                              mock_wire_server_request):
        mock_config = mock.Mock()
        mock_get_role_instance_config.return_value = mock_config
        mock_config.FullConfig.cdata = mock.sentinel.data

        self._azureservice._get_full_config()
        mock_get_role_instance_config.assert_called_once_with()
        mock_wire_server_request.assert_called_once_with(mock.sentinel.data)

    @testutils.ConfPatcher('transport_cert_store_name', 'fake_name', "azure")
    def test__create_transport_cert(self):
        mock_cert_mgr = mock.Mock()
        expected_certs = (mock.sentinel.thumbprint, mock.sentinel.cert)

        mock_cert_mgr.create_self_signed_cert.return_value = (
            mock.sentinel.thumbprint, mock.sentinel.cert)
        with self._azureservice._create_transport_cert(mock_cert_mgr) as res:
            self.assertEqual(res, expected_certs)
        (mock_cert_mgr.create_self_signed_cert.
            assert_called_once_with("CN=Cloudbase-Init AzureService Transport",
                                    machine_keyset=True,
                                    store_name="fake_name"))
        (mock_cert_mgr.delete_certificate_from_store.
            assert_called_once_with(mock.sentinel.thumbprint,
                                    machine_keyset=True,
                                    store_name="fake_name"))

    @mock.patch(MODPATH + "._wire_server_request")
    def test__get_encoded_cert(self, mock_wire_server_request):
        mock_cert_config = mock.Mock()
        mock_transport_cert = mock.Mock()
        mock_cert_url = mock.sentinel.cert_url

        mock_transport_cert.replace.return_value = mock.sentinel.transport_cert
        mock_wire_server_request.return_value = mock_cert_config
        mock_cert_config.CertificateFile.Data.cdata = mock.sentinel.cert_data
        mock_cert_config.CertificateFile.Format.cdata = mock.sentinel.cert_fmt

        expected_headers = {
            "x-ms-guest-agent-public-x509-cert": mock.sentinel.transport_cert}
        expected_result = (mock.sentinel.cert_data, mock.sentinel.cert_fmt)
        res = self._azureservice._get_encoded_cert(mock_cert_url,
                                                   mock_transport_cert)
        (mock_wire_server_request.
            assert_called_once_with(mock_cert_url, headers=expected_headers))
        self.assertEqual(res, expected_result)

    @mock.patch(MODPATH + "._get_versions")
    def _test__check_version_header(self, mock_get_versions, version):
        mock_version = mock.Mock()
        mock_get_versions.return_value = mock_version
        mock_version.Versions.Supported.Version = [version]
        if azureservice.WIRE_SERVER_VERSION is not version:
            self.assertRaises(exception.MetadaNotFoundException,
                              self._azureservice._check_version_header)
        else:
            self._azureservice._check_version_header()
            self.assertEqual(self._azureservice._headers["x-ms-version"],
                             version)

    def test_check_version_header_unsupported_version(self):
        version = "fake-version"
        self._test__check_version_header(version=version)

    def test_check_version_header_supported(self):
        version = azureservice.WIRE_SERVER_VERSION
        self._test__check_version_header(version=version)

    @mock.patch(MODPATH + "._wire_server_request")
    def test__get_versions(self, mock_server_request):
        mock_server_request.return_value = mock.sentinel.version
        res = self._azureservice._get_versions()
        mock_server_request.assert_called_once_with("?comp=Versions")
        self.assertEqual(res, mock.sentinel.version)

    @mock.patch(MODPATH + "._get_role_instance_id")
    def test_get_instance_id(self, mock_get_role_instance_id):
        mock_get_role_instance_id.return_value = mock.sentinel.id
        self.assertEqual(self._azureservice.get_instance_id(),
                         mock.sentinel.id)

    def _test__get_ovf_env_path(self, mock_drives):
        mock_get_drives = mock.Mock()
        mock_get_drives.return_value = mock_drives
        self._azureservice._osutils.get_logical_drives = mock_get_drives
        self.assertRaises(exception.CloudbaseInitException,
                          self._azureservice._get_ovf_env_path)

    def test_get_ovf_env_path(self):
        self._test__get_ovf_env_path(mock_drives=[])

    @mock.patch(MODPATH + "._get_ovf_env_path")
    def test_get_ovf_env(self, mock_get_ovf_env_path):
        fake_xml = '<?xml version="1.0"?><root><child name="fake"/></root>'
        mock_get_ovf_env_path.return_value = fake_xml
        res = self._azureservice._get_ovf_env()
        self.assertIsNotNone(res)
        mock_get_ovf_env_path.assert_called_once_with()

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_username(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.AdminUsername.cdata = mock.sentinel.cdata
        res = self._azureservice.get_admin_username()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_admin_password(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.AdminPassword.cdata = mock.sentinel.cdata
        res = self._azureservice.get_admin_password()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_host_name(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.ComputerName.cdata = mock.sentinel.cdata
        res = self._azureservice.get_host_name()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, mock.sentinel.cdata)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_enable_automatic_updates(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        res = self._azureservice.get_enable_automatic_updates()
        mock_get_ovf_env.assert_called_once_with()
        self.assertFalse(res)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_winrm_listeners_configuration(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_prov_section = mock.Mock()
        mock_win_prov = mock.Mock()
        mock_listener = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        mock_ovf_env.Environment.wa_ProvisioningSection = mock_prov_section
        mock_prov_section.WindowsProvisioningConfigurationSet = mock_win_prov
        mock_win_prov.WinRM.Listeners.Listener = [mock_listener]
        mock_listener.Protocol.cdata = mock.sentinel.fake_protocol
        (mock_listener.CertificateThumbprint.
            cdata) = mock.sentinel.fake_thumbprint

        expected_result = [
            {
                'certificate_thumbprint': mock.sentinel.fake_thumbprint,
                'protocol': mock.sentinel.fake_protocol,
            }]
        res = self._azureservice.get_winrm_listeners_configuration()
        mock_get_ovf_env.assert_called_once_with()
        self.assertEqual(res, expected_result)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_vm_agent_package_provisioning_data(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_package_name = mock.sentinel.package_name
        mock_get_ovf_env.return_value = mock_ovf_env
        (mock_ovf_env.Environment.wa_PlatformSettingsSection.
            PlatformSettings.GuestAgentPackageName.cdata) = mock_package_name
        res = self._azureservice.get_vm_agent_package_provisioning_data()
        expected_provisioning_data = {
            'provision': False, 'package_name': mock_package_name}
        self.assertEqual(res, expected_provisioning_data)

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_kms_host(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        self.assertTrue(self._azureservice.get_kms_host())

    @mock.patch(MODPATH + "._get_ovf_env")
    def test_get_use_avma_licensing(self, mock_get_ovf_env):
        mock_ovf_env = mock.Mock()
        mock_get_ovf_env.return_value = mock_ovf_env
        self.assertFalse(self._azureservice.get_use_avma_licensing())
        mock_get_ovf_env.assert_called_once_with()

    @mock.patch(MODPATH + "._get_ovf_env")
    @mock.patch(MODPATH + "._check_version_header")
    @mock.patch(MODPATH + "._get_wire_server_endpoint_address")
    def _test_load(self, mock_get_endpoint_address,
                   mock_check_version_header, mock_get_ovf_env,
                   endpoint_side_effect=None, load_side_effect=None):
        if endpoint_side_effect:
            mock_get_endpoint_address.side_effect = endpoint_side_effect
            expected_logging = ["Azure WireServer endpoint not found"]
            with self._logsnatcher:
                res = self._azureservice.load()
                self.assertFalse(res)
            self.assertEqual(self._logsnatcher.output, expected_logging)
            mock_get_endpoint_address.assert_called_once_with()
            return

        mock_endpoint = mock.sentinel.endpoint
        mock_get_endpoint_address.return_value = mock_endpoint
        if load_side_effect:
            mock_check_version_header.side_effect = load_side_effect
            res = self._azureservice.load()
            self.assertFalse(res)
            return
        else:
            res = self._azureservice.load()
            self.assertTrue(res)
            self.assertIn(str(mock_endpoint), self._azureservice._base_url)
            mock_check_version_header.assert_called_once_with()
            mock_get_ovf_env.assert_called_once_with()
            return

    def test_load_no_endpoint(self):
        self._test_load(endpoint_side_effect=Exception)

    def test_load_exception(self):
        exc = Exception("Fake exception")
        self._test_load(load_side_effect=exc)

    def test_load(self):
        self._test_load()

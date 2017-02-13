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

import contextlib
import os
import socket
import time
from xml.etree import ElementTree

from oslo_log import log as oslo_logging
import six
import untangle

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import dhcp
from cloudbaseinit.utils.windows import x509

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

WIRESERVER_DHCP_OPTION = 245
WIRE_SERVER_VERSION = '2015-04-05'

GOAL_STATE_STARTED = "Started"

HEALTH_STATE_READY = "Ready"
HEALTH_STATE_NOT_READY = "NotReady"
HEALTH_SUBSTATE_PROVISIONING = "Provisioning"
HEALTH_SUBSTATE_PROVISIONING_FAILED = "ProvisioningFailed"

ROLE_PROPERTY_CERT_THUMB = "CertificateThumbprint"

OVF_ENV_DRIVE_TAG = "E6DA6616-8EC4-48E0-BE93-58CE6ACE3CFB.tag"
OVF_ENV_FILENAME = "ovf-env.xml"


class AzureService(base.BaseHTTPMetadataService):

    def __init__(self):
        super(AzureService, self).__init__(base_url=None)
        self._enable_retry = True
        self._goal_state = None
        self._ovf_env = None
        self._headers = {"x-ms-guest-agent-name": "cloudbase-init"}
        self._osutils = osutils_factory.get_os_utils()

    def _get_wire_server_endpoint_address(self):
        total_time = 300
        poll_time = 5
        retries = total_time / poll_time

        while True:
            try:
                options = dhcp.get_dhcp_options()
                endpoint = (options or {}).get(WIRESERVER_DHCP_OPTION)
                if not endpoint:
                    raise exception.MetadaNotFoundException(
                        "Cannot find Azure WireServer endpoint address")
                return socket.inet_ntoa(endpoint)
            except Exception:
                if not retries:
                    raise
                time.sleep(poll_time)
                retries -= 1

    def _check_version_header(self):
        if "x-ms-version" not in self._headers:
            versions = self._get_versions()
            if WIRE_SERVER_VERSION not in versions.Versions.Supported.Version:
                raise exception.MetadaNotFoundException(
                    "Unsupported Azure WireServer version: %s" %
                    WIRE_SERVER_VERSION)
            self._headers["x-ms-version"] = WIRE_SERVER_VERSION

    def _get_versions(self):
        return self._wire_server_request("?comp=Versions")

    def _wire_server_request(self, path, data_xml=None, headers=None,
                             parse_xml=True):
        if not self._base_url:
            raise exception.CloudbaseInitException(
                "Azure WireServer base url not set")

        all_headers = self._headers.copy()
        if data_xml:
            all_headers["Content-Type"] = "text/xml; charset=utf-8"
        if headers:
            all_headers.update(headers)

        data = self._exec_with_retry(
            lambda: super(AzureService, self)._http_request(
                path, data_xml, headers=all_headers))

        if parse_xml:
            return untangle.parse(six.StringIO(data.decode()))
        else:
            return data

    @staticmethod
    def _encode_xml(xml_root):
        bio = six.BytesIO()
        ElementTree.ElementTree(xml_root).write(
            bio, encoding='utf-8', xml_declaration=True)
        return bio.getvalue()

    def _get_health_report_xml(self, state, sub_status=None, description=None):
        xml_root = ElementTree.Element('Health')
        xml_goal_state_incarnation = ElementTree.SubElement(
            xml_root, 'GoalStateIncarnation')
        xml_goal_state_incarnation.text = str(self._get_incarnation())
        xml_container = ElementTree.SubElement(xml_root, 'Container')
        xml_container_id = ElementTree.SubElement(xml_container, 'ContainerId')
        xml_container_id.text = self._get_container_id()
        xml_role_instance_list = ElementTree.SubElement(
            xml_container, 'RoleInstanceList')
        xml_role = ElementTree.SubElement(xml_role_instance_list, 'Role')
        xml_role_instance_id = ElementTree.SubElement(xml_role, 'InstanceId')
        xml_role_instance_id.text = self._get_role_instance_id()
        xml_health = ElementTree.SubElement(xml_role, 'Health')
        xml_state = ElementTree.SubElement(xml_health, 'State')
        xml_state.text = state

        if sub_status:
            xml_details = ElementTree.SubElement(xml_health, 'Details')
            xml_sub_status = ElementTree.SubElement(xml_details, 'SubStatus')
            xml_sub_status.text = sub_status
            xml_description = ElementTree.SubElement(
                xml_details, 'Description')
            xml_description.text = description

        return self._encode_xml(xml_root)

    def _get_role_properties_xml(self, properties):
        xml_root = ElementTree.Element('RoleProperties')
        xml_container = ElementTree.SubElement(xml_root, 'Container')
        xml_container_id = ElementTree.SubElement(xml_container, 'ContainerId')
        xml_container_id.text = self._get_container_id()
        xml_role_instances = ElementTree.SubElement(
            xml_container, 'RoleInstances')
        xml_role_instance = ElementTree.SubElement(
            xml_role_instances, 'RoleInstance')
        xml_role_instance_id = ElementTree.SubElement(
            xml_role_instance, 'Id')
        xml_role_instance_id.text = self._get_role_instance_id()
        xml_role_properties = ElementTree.SubElement(
            xml_role_instance, 'Properties')

        for name, value in properties.items():
            ElementTree.SubElement(
                xml_role_properties, 'Property', name=name, value=value)

        return self._encode_xml(xml_root)

    def _get_goal_state(self, force_update=False):
        if not self._goal_state or force_update:
            self._goal_state = self._wire_server_request(
                "machine?comp=goalstate").GoalState

        expected_state = self._goal_state.Machine.ExpectedState
        if expected_state != GOAL_STATE_STARTED:
            raise exception.CloudbaseInitException(
                "Invalid machine expected state: %s" % expected_state)

        return self._goal_state

    def _get_incarnation(self):
        goal_state = self._get_goal_state()
        return goal_state.Incarnation.cdata

    def _get_container_id(self):
        goal_state = self._get_goal_state()
        return goal_state.Container.ContainerId.cdata

    def _get_role_instance_config(self):
        goal_state = self._get_goal_state()
        role_instance = goal_state.Container.RoleInstanceList.RoleInstance
        return role_instance.Configuration

    def _get_role_instance_id(self):
        goal_state = self._get_goal_state()
        role_instance = goal_state.Container.RoleInstanceList.RoleInstance
        return role_instance.InstanceId.cdata

    def _post_health_status(self, state, sub_status=None, description=None):
        health_report_xml = self._get_health_report_xml(
            state, sub_status, description)
        LOG.debug("Heath data: %s", health_report_xml)
        self._wire_server_request(
            "machine?comp=health", health_report_xml, parse_xml=False)

    def provisioning_started(self):
        self._post_health_status(
            HEALTH_STATE_NOT_READY, HEALTH_SUBSTATE_PROVISIONING,
            "Cloudbase-Init is preparing your computer for first use...")

    def provisioning_completed(self):
        self._post_health_status(HEALTH_STATE_READY)

    def provisioning_failed(self):
        self._post_health_status(
            HEALTH_STATE_NOT_READY, HEALTH_SUBSTATE_PROVISIONING_FAILED,
            "Provisioning failed")

    def _post_role_properties(self, properties):
        role_properties_xml = self._get_role_properties_xml(properties)
        LOG.debug("Role properties data: %s", role_properties_xml)
        self._wire_server_request(
            "machine?comp=roleProperties", role_properties_xml,
            parse_xml=False)

    @property
    def can_post_rdp_cert_thumbprint(self):
        return True

    def post_rdp_cert_thumbprint(self, thumbprint):
        properties = {ROLE_PROPERTY_CERT_THUMB: thumbprint}
        self._post_role_properties(properties)

    def _get_hosting_environment(self):
        config = self._get_role_instance_config()
        return self._wire_server_request(config.HostingEnvironmentConfig.cdata)

    def _get_shared_config(self):
        config = self._get_role_instance_config()
        return self._wire_server_request(config.SharedConfig.cdata)

    def _get_extensions_config(self):
        config = self._get_role_instance_config()
        return self._wire_server_request(config.ExtensionsConfig.cdata)

    def _get_full_config(self):
        config = self._get_role_instance_config()
        return self._wire_server_request(config.FullConfig.cdata)

    @contextlib.contextmanager
    def _create_transport_cert(self, cert_mgr):
        x509_thumbprint, x509_cert = cert_mgr.create_self_signed_cert(
            "CN=Cloudbase-Init AzureService Transport", machine_keyset=True,
            store_name=CONF.azure.transport_cert_store_name)

        try:
            yield (x509_thumbprint, x509_cert)
        finally:
            cert_mgr.delete_certificate_from_store(
                x509_thumbprint, machine_keyset=True,
                store_name=CONF.azure.transport_cert_store_name)

    def _get_encoded_cert(self, transport_cert):
        config = self._get_role_instance_config()
        cert_config = self._wire_server_request(
            config.Certificates.cdata,
            headers={"x-ms-guest-agent-public-x509-cert":
                     transport_cert.replace("\r\n", "")})

        cert_data = cert_config.CertificateFile.Data.cdata
        cert_format = cert_config.CertificateFile.Format.cdata
        return cert_data, cert_format

    def get_server_certs(self):
        def _get_store_location(store_location):
            if store_location == u"System":
                return constant.CERT_LOCATION_LOCAL_MACHINE
            else:
                return store_location

        cert_mgr = x509.CryptoAPICertManager()
        with self._create_transport_cert(cert_mgr) as (
                transport_cert_thumbprint, transport_cert):

            cert_data, cert_format = self._get_encoded_cert(transport_cert)
            pfx_data = cert_mgr.decode_pkcs7_base64_blob(
                cert_data, transport_cert_thumbprint, machine_keyset=True,
                store_name=CONF.azure.transport_cert_store_name)

        certs_info = []
        host_env = self._get_hosting_environment()
        host_env_config = host_env.HostingEnvironmentConfig
        for cert in host_env_config.StoredCertificates.StoredCertificate:
            certs_info.append({
                "store_name": cert["storeName"],
                "store_location": _get_store_location(
                    cert["configurationLevel"]),
                "certificate_id": cert["certificateId"],
                "name": cert["name"],
                "pfx_data": pfx_data,
            })
        return certs_info

    def get_instance_id(self):
        return self._get_role_instance_id()

    def _get_ovf_env_path(self):
        ovf_env_path = None
        base_paths = self._osutils.get_logical_drives()
        for base_path in base_paths:
            tag_path = os.path.join(base_path, OVF_ENV_DRIVE_TAG)
            if os.path.exists(tag_path):
                ovf_env_path = os.path.join(base_path, OVF_ENV_FILENAME)
                break

        if not ovf_env_path:
            raise exception.CloudbaseInitException(
                "No drive containing file %s could be found" %
                OVF_ENV_FILENAME)

        if not os.path.exists(ovf_env_path):
            raise exception.CloudbaseInitException(
                "ovf-env path does not exist: %s" % ovf_env_path)

        LOG.debug("ovs-env path: %s", ovf_env_path)
        return ovf_env_path

    def _get_ovf_env(self):
        if not self._ovf_env:
            ovf_env_path = self._get_ovf_env_path()
            self._ovf_env = untangle.parse(ovf_env_path)
        return self._ovf_env

    def get_admin_username(self):
        ovf_env = self._get_ovf_env()
        prov_section = ovf_env.Environment.wa_ProvisioningSection
        win_prov_conf_set = prov_section.WindowsProvisioningConfigurationSet
        return win_prov_conf_set.AdminUsername.cdata

    def get_admin_password(self):
        ovf_env = self._get_ovf_env()
        prov_section = ovf_env.Environment.wa_ProvisioningSection
        win_prov_conf_set = prov_section.WindowsProvisioningConfigurationSet
        return win_prov_conf_set.AdminPassword.cdata

    def get_host_name(self):
        ovf_env = self._get_ovf_env()
        prov_section = ovf_env.Environment.wa_ProvisioningSection
        win_prov_conf_set = prov_section.WindowsProvisioningConfigurationSet
        return win_prov_conf_set.ComputerName.cdata

    def get_enable_automatic_updates(self):
        ovf_env = self._get_ovf_env()
        prov_section = ovf_env.Environment.wa_ProvisioningSection
        win_prov_conf_set = prov_section.WindowsProvisioningConfigurationSet
        if hasattr(win_prov_conf_set, "EnableAutomaticUpdates"):
            auto_updates = win_prov_conf_set.EnableAutomaticUpdates.cdata
            return auto_updates.lower() == "true"
        return False

    def get_winrm_listeners_configuration(self):
        listeners_config = []
        ovf_env = self._get_ovf_env()
        prov_section = ovf_env.Environment.wa_ProvisioningSection
        win_prov_conf_set = prov_section.WindowsProvisioningConfigurationSet
        if hasattr(win_prov_conf_set, "WinRM"):
            for listener in win_prov_conf_set.WinRM.Listeners.Listener:
                protocol = listener.Protocol.cdata
                config = {"protocol": protocol}
                if hasattr(listener, "CertificateThumbprint"):
                    cert_thumbprint = listener.CertificateThumbprint.cdata
                    config["certificate_thumbprint"] = cert_thumbprint
                listeners_config.append(config)
        return listeners_config

    def get_kms_host(self):
        ovf_env = self._get_ovf_env()
        plat_sett_section = ovf_env.Environment.wa_PlatformSettingsSection
        if hasattr(plat_sett_section.PlatformSettings, "KmsServerHostname"):
            return plat_sett_section.PlatformSettings.KmsServerHostname.cdata

    def get_use_avma_licensing(self):
        ovf_env = self._get_ovf_env()
        plat_sett_section = ovf_env.Environment.wa_PlatformSettingsSection
        if hasattr(plat_sett_section.PlatformSettings, "UseAVMA"):
            use_avma = plat_sett_section.PlatformSettings.UseAVMA.cdata
            return use_avma.lower() == "true"
        return False

    def load(self):
        try:
            wire_server_endpoint = self._get_wire_server_endpoint_address()
            self._base_url = "http://%s" % wire_server_endpoint
        except Exception:
            LOG.debug("Azure WireServer endpoint not found")
            return False

        try:
            super(AzureService, self).load()
            self._check_version_header()
            self._get_ovf_env()
            return True
        except Exception as ex:
            LOG.exception(ex)
            return False


        # self._get_hosting_environment()
        # self._get_shared_config()
        # self._get_extensions_config()
        # self._get_full_config()

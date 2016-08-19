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


import json
import posixpath

from oslo_config import cfg
from oslo_log import log as oslo_logging

from cloudbaseinit import constants
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import x509constants


OPENSTACK_OPTS = [
    cfg.StrOpt("metadata_base_url", default="http://169.254.169.254/",
               help="The base URL where the service looks for metadata",
               deprecated_group="DEFAULT")
]

CONF = cfg.CONF
CONF.register_group(cfg.OptGroup('openstack'))
CONF.register_opts(OPENSTACK_OPTS, 'openstack')

LOG = oslo_logging.getLogger(__name__)


class _NetworkDetailsBuilder(service_base.NetworkDetailsBuilder):

    """OpenStack network details builder."""

    def __init__(self, service, content):
        super(_NetworkDetailsBuilder, self).__init__(service)
        self._link.update({
            constants.NAME: self._Field(
                name=constants.NAME, alias=debiface.NAME),
            constants.MAC_ADDRESS: self._Field(
                name=constants.MAC_ADDRESS, alias=debiface.MAC),
        })
        self._network.update({
            constants.IP_ADDRESS: self._Field(
                name=constants.IP_ADDRESS, alias=debiface.ADDRESS),
            constants.NETMASK: self._Field(
                name=constants.NETMASK, alias=debiface.NETMASK),
            constants.GATEWAY: self._Field(
                name=constants.GATEWAY, alias=debiface.GATEWAY),
            constants.BROADCAST: self._Field(
                name=constants.BROADCAST, alias=debiface.BROADCAST),
            constants.DNS: self._Field(
                name=constants.DNS, alias=debiface.DNSNS, default=[]),
        })

        self._content = content
        self._links = {}
        self._networks = {}

    def _process_link_networks(self, link, raw_data):
        """Digest the information related to networks."""
        raw_data[constants.ASSIGNED_TO] = link[constants.ID]
        raw_ipv6_network = {
            constants.IP_ADDRESS: raw_data.get(debiface.ADDRESS6),
            constants.NETMASK: raw_data.get(debiface.NETMASK6),
            constants.GATEWAY: raw_data.get(debiface.GATEWAY6),
            constants.VERSION: constants.IPV6,
            constants.ASSIGNED_TO: link[constants.ID],
            constants.PRIORITY: 10,
        }

        success = False
        for data in (raw_data, raw_ipv6_network):
            network = self._get_fields(self._network.values(), data)
            if network:
                self._networks[network[constants.ID]] = network
                success = True
        return success

    def _process(self):
        """Process the received network information."""
        for raw_link in debiface.parse(self._content):
            link = self._get_fields(self._link.values(), raw_link)
            if link:
                if self._process_link_networks(link, raw_link):
                    self._links[link[constants.ID]] = link
            else:
                # Note(alexcoman): The current raw_link does not contain
                #                  all the required fields.
                LOG.warning("%r does not contains all the required fields.",
                            raw_link)


class BaseOpenStackService(service_base.BaseNetworkMetadataService):

    def __init__(self):
        super(BaseOpenStackService, self).__init__()
        self._network_details_builder = None

    def get_content(self, name):
        path = posixpath.normpath(
            posixpath.join('openstack', 'content', name))
        return self._get_cache_data(path)

    def get_user_data(self):
        path = posixpath.normpath(
            posixpath.join('openstack', 'latest', 'user_data'))
        return self._get_cache_data(path)

    def _get_meta_data(self, version='latest'):
        path = posixpath.normpath(
            posixpath.join('openstack', version, 'meta_data.json'))
        data = self._get_cache_data(path, decode=True)
        if data:
            return json.loads(data)

    def get_instance_id(self):
        return self._get_meta_data().get('uuid')

    def get_host_name(self):
        return self._get_meta_data().get('hostname')

    def get_public_keys(self):
        """Get a list of all unique public keys found among the metadata."""
        public_keys = []
        meta_data = self._get_meta_data()
        public_keys_dict = meta_data.get("public_keys")
        if public_keys_dict:
            public_keys = list(public_keys_dict.values())
        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "ssh":
                    public_keys.append(key_dict["data"])
        return list(set((key.strip() for key in public_keys)))

    def get_admin_password(self):
        meta_data = self._get_meta_data()
        meta = meta_data.get('meta')

        if meta and 'admin_pass' in meta:
            password = meta['admin_pass']
        elif 'admin_pass' in meta_data:
            password = meta_data['admin_pass']
        else:
            password = None

        return password

    def get_client_auth_certs(self):
        """Gather all unique certificates found among the metadata.

        If there are no certificates under "meta" or "keys" field,
        then try looking into user-data for this kind of information.
        """
        certs = []
        meta_data = self._get_meta_data()

        meta = meta_data.get("meta")
        if meta:
            cert_data_list = []
            idx = 0
            while True:
                # Chunking is necessary as metadata items can be
                # max. 255 chars long.
                cert_chunk = meta.get("admin_cert%d" % idx)
                if not cert_chunk:
                    break
                cert_data_list.append(cert_chunk)
                idx += 1
            if cert_data_list:
                # It's a list of strings for sure.
                certs.append("".join(cert_data_list))

        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "x509":
                    certs.append(key_dict["data"])

        if not certs:
            # Look if the user_data contains a PEM certificate
            try:
                user_data = self.get_user_data().strip()
                if user_data.startswith(
                        x509constants.PEM_HEADER.encode()):
                    certs.append(encoding.get_as_string(user_data))
            except base.NotExistingMetadataException:
                LOG.debug("user_data metadata not present")

        return list(set((cert.strip() for cert in certs)))

    def _get_network_details_builder(self):
        """Get the required `NetworkDetailsBuilder` object.

        The `NetworkDetailsBuilder` is used in order to create the
        `NetworkDetails` object using the network related information
        exposed by the current metadata provider.
        """
        network_config = self._get_meta_data().get('network_config')
        if not network_config:
            LOG.debug("No network_config available.")
            return None

        key = "content_path"
        if key not in network_config:
            LOG.debug("The %r key was not found in network_config.", key)
            return None

        if not self._network_details_builder:
            content_name = network_config[key].rsplit("/", 1)[-1]
            content = self.get_content(content_name)
            content = encoding.get_as_string(content)
            self._network_details_builder = _NetworkDetailsBuilder(
                service=self, content=content)

        return self._network_details_builder

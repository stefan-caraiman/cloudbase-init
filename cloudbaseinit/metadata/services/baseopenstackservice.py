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

from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import x509constants


opts = [
    cfg.StrOpt('metadata_base_url', default='http://169.254.169.254/',
               help='The base URL where the service looks for metadata'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = oslo_logging.getLogger(__name__)


class _OpenStackNetworkAdapter(base.BaseNetworkAdapter):

    """OpenStack Service Network Adapter."""

    FIELDS = {
        base.LINK: {
            base.NAME: base.Field(base.NAME, debiface.NAME,
                                  required=True),
            base.MAC_ADDRESS: base.Field(base.MAC_ADDRESS, debiface.MAC,
                                         required=True),
        },
        base.NETWORK: {
            base.IP_ADDRESS: base.Field(base.IP_ADDRESS, debiface.ADDRESS,
                                        required=True),
            base.NETMASK: base.Field(base.NETMASK, debiface.NETMASK,
                                     required=True),
            base.GATEWAY: base.Field(base.GATEWAY, debiface.GATEWAY,
                                     required=True),
            base.DNS: base.Field(base.DNS, debiface.DNSNS,
                                 default=[], required=False),
        },
    }

    def __init__(self, service, content):
        super(_OpenStackNetworkAdapter, self).__init__(service)
        self._links = {}
        self._networks = {}
        self._digest(content)

    def _digest_network(self, link, raw_subnets):
        """Digest the information related to networks."""
        networks = self._networks.setdefault(link[base.NAME], [])
        raw_networks = [
            self.get_fields(self.fields[base.NETWORK], raw_subnets),
            {
                base.IP_ADDRESS: raw_subnets.get(debiface.ADDRESS6),
                base.NETMASK: raw_subnets.get(debiface.NETMASK6),
                base.GATEWAY: raw_subnets.get(debiface.GATEWAY6),
            }
        ]
        for network in raw_networks:
            network.update(self._digest_interface(
                network[base.IP_ADDRESS], network[base.NETMASK]))
            networks.append(network)

    def _digest(self, network_data):
        """Digest the received network information."""
        for raw_link in debiface.parse(network_data):
            try:
                link = self.get_fields(self.fields[base.LINK], raw_link)
                self._links[link[base.NAME]] = link
                self._digest_network(link, raw_link)
            except TypeError:
                # Note(alexandrucoman): The current raw_link do not contain
                #                       all the required fields.
                continue

    def get_link(self, name):
        """Return all the available information regarding the received
        link name.

        :rtype: dict

        .. notes:
            The returned dictionary should contain al least the following
            keys: `name` and `mac_address`.
        """
        return self._links.get(name)

    def get_links(self):
        """Return a list with the names of the available links.

        :rtype: list
        """
        return self._links.keys()

    def get_network(self, link, name):
        """Return all the available information regarding the required
        network.

        :param link: The name of the required link
        :type link:  str
        :param name: The name of the required network
        :type name: str

        .. notes:
            The returned dictionary should contain al least the following
            keys: `name`, `type`, `ip_address`, `netmask`, `brodcast` and
            `dns_nameservers`.
        """
        return self._networks[link][name]

    def get_networks(self, link):
        """Returns all the network names bound by the required link.

        :param link: The name of the required link
        :type link:  str

        :rtype: list
        """
        return range(0, len(self._networks[link]))


class BaseOpenStackService(base.BaseMetadataService):

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

    def get_network_adapter(self):
        network_config = self._get_meta_data().get('network_config')
        if not network_config:
            return None
        key = "content_path"
        if key not in network_config:
            return None

        content_name = network_config[key].rsplit("/", 1)[-1]
        content = self.get_content(content_name)
        content = encoding.get_as_string(content)

        return _OpenStackNetworkAdapter(self, content)

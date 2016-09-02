# Copyright 2012 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging
from six.moves.urllib import error

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import network as network_utils

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

_LINK_ID = "id"
_LINK_TYPE = "type"
_MAC_ADDRESS = "ethernet_mac_address"
_MTU = "mtu"

_BOND_LINKS = "bond_links"
_BOND_MODE = "bond_mode"
_BOND_POLICY = "bond_xmit_hash_policy"
_BOND_MIIMON = "bond_miimon"

_VLAN_LINK = "vlan_link"
_VLAN_ID = "vlan_id"
_VLAN_MAC = "vlan_mac_address"

_ASSIGNED_TO = "link"
_NETWORK_ID = "id"
_NETWORK_TYPE = "type"
_IP_ADDRESS = "ip_address"
_NETMASK = "netmask"
_DNS = "dns_nameservers"

_NETWORK = "network"
_GATEWAY = "gateway"

_PRIORITY = {
    constant.PHY: 0,
    constant.BOND: 10,
    constant.VIF: 20,
    constant.VLAN: 30,
    constant.OVS: 30,
}

_IPV4 = "ipv4"
_IPV6 = "ipv6"
_IPV4_DHCP = "ipv4_dhcp"
_IPV6_DHCP = "ipv6_dhcp"

_SERVICE_TYPE = "type"
_DNS_SERVICE = "dns"
_ADDRESS = "address"


class _NetworkDetailsBuilder(service_base.NetworkDetailsBuilder):

    """OpenStack HTTP Service network details builder."""

    _LINKS_KEY = "links"
    _NETWORKS_KEY = "networks"
    _ROUTES_KEY = "routes"
    _SERVICES_KEY = "services"

    def __init__(self, service, network_data):
        super(_NetworkDetailsBuilder, self).__init__(service)
        self._network_data = network_data
        self._invalid_links = []
        self._dns_services = []

        self._link_mapping = [
            # Aliases for base link
            self.Alias(field=constant.LINK_ID, name=_LINK_ID),
            self.Alias(field=constant.NAME, name=_LINK_ID),
            self.Alias(field=constant.TYPE, name=_LINK_TYPE),
            self.Alias(field=constant.MAC_ADDRESS, name=_MAC_ADDRESS),
            self.Alias(field=constant.MAC_ADDRESS, name=_VLAN_MAC),
            self.Alias(field=constant.MTU, name=_MTU),

            # Aliases for BondLink
            self.Alias(field=constant.BOND_LINKS, name=_BOND_LINKS),
            self.Alias(field=constant.BOND_MODE, name=_BOND_MODE),
            self.Alias(field=constant.BOND_MIIMON, name=_BOND_MIIMON),
            self.Alias(field=constant.BOND_HASH_POLICY, name=_BOND_POLICY),

            # Aliases for VLANLink
            self.Alias(field=constant.VLAN_ID, name=_VLAN_ID),
            self.Alias(field=constant.VLAN_LINK, name=_VLAN_LINK),
        ]

        self._network_mapping = [
            self.Alias(field=constant.ASSIGNED_TO, name=_ASSIGNED_TO),
            self.Alias(field=constant.IP_ADDRESS, name=_IP_ADDRESS),
            self.Alias(field=constant.NETMASK, name=_NETMASK),
            self.Alias(field=constant.DNS, name=_DNS),
        ]

        self._route_mapping = [
            self.Alias(field=constant.NETWORK, name=_NETWORK),
            self.Alias(field=constant.NETMASK, name=_NETMASK),
            self.Alias(field=constant.GATEWAY, name=_GATEWAY),
        ]

    @staticmethod
    def _process_network_type(network_type):
        """Process information related to network type."""
        changes = {}
        if network_type == _IPV4:
            changes[constant.PRIORITY] = 0
            changes[constant.VERSION] = constant.IPV4
        elif network_type == _IPV6:
            changes[constant.VERSION] = constant.IPV6
            changes[constant.PRIORITY] = 10
        elif network_type in (_IPV4_DHCP, _IPV6_DHCP):
            changes[constant.NETWORK_TYPE] = constant.DHCP

        return changes

    def _process_services(self):
        """Process the information related to services."""

        # TODO(alexcoman): Update the manner of processing services.

        # NOTE(alexcoman): For the moment there's no other type
        # of services except `dns`. Taking that into consideration
        # the current method will be very specific.

        for raw_data in self._network_data.get(self._SERVICES_KEY, []):
            if _SERVICE_TYPE in raw_data:
                service_type = raw_data.get(_SERVICE_TYPE)
                if service_type == _DNS_SERVICE:
                    self._dns_services.append(raw_data[_ADDRESS])

    def _process_raw_routes(self, subnetwork, raw_data):
        """Process the information related to routes."""
        for raw_route in raw_data.get(self._ROUTES_KEY, []):
            # Normalize the keys from the raw route dictionary
            raw_route = self._apply_mapping(raw_route,
                                            self._route_mapping)
            raw_route[constant.ASSIGNED_TO] = subnetwork.subnet_id
            try:
                self._add_route(raw_route)
            except exception.NetworkDetailsError as exc:
                LOG.warning("Failed to obtain the route: %r.", exc)

    def _process_raw_networks(self):
        """Process the information related to networks."""
        network_data = self._network_data.get(self._NETWORKS_KEY, [])
        if not network_data:
            LOG.warning("No information regarding networks available.")
            return

        for raw_data in network_data:
            # Process the information regarding network type and obtain
            # a list of changes that should be added to the new network
            # model.
            changes = self._process_network_type(raw_data[_NETWORK_TYPE])

            # Normalize the keys from the raw subnetwork dictionary
            raw_network = self._apply_mapping(raw_data,
                                              self._network_mapping)
            raw_network.update(changes)

            # NOTE(alexcoman): If the dns nameserves are not specified
            # into the raw subnetwork information, it will be used the
            # dns information from the services key (if it exists).
            if not raw_network.get(constant.DNS, None):
                raw_network[constant.DNS] = self._dns_services

            try:
                subnetwork = self._add_subnetwork(raw_network)
            except exception.NetworkDetailsError as exc:
                LOG.warning("Failed to obtain the subnetwork: %r.", exc)
                continue

            if subnetwork.assigned_to in self._invalid_links:
                self._invalid_links.remove(subnetwork.assigned_to)
            elif subnetwork.assigned_to not in self._links:
                LOG.warning("The link with id %r doesn't exists",
                            subnetwork.assigned_to)

            self._process_raw_routes(subnetwork, raw_data)

    def _process(self):
        """Digest the received network information."""
        self._process_services()
        for raw_data in self._network_data.get(self._LINKS_KEY, []):
            # Get the priority for the current link
            priority = _PRIORITY.get(raw_data[_LINK_TYPE], None)
            if priority is None:
                LOG.debug("No priority available for %r (using: 0)",
                          raw_data[_LINK_TYPE])
                priority = 0

            # Normalize the keys from the raw link dictionary
            raw_link = self._apply_mapping(raw_data, self._link_mapping)
            # Set the priority for the current link
            raw_link[constant.PRIORITY] = priority

            try:
                self._add_link(raw_link)
            except exception.NetworkDetailsError as exc:
                LOG.warning("Failed to obtain the link: %r.", exc)

        self._invalid_links = list(self._links.keys())
        self._process_raw_networks()
        while self._invalid_links:
            invalid_link = self._invalid_links.pop()
            LOG.debug("The link %r does not contain any network.",
                      invalid_link)


class HttpService(base.BaseHTTPMetadataService,
                  baseopenstackservice.BaseOpenStackService):

    _POST_PASSWORD_MD_VER = '2013-04-04'
    _NETWORK_DATA_JSON = "openstack/latest/network_data.json"

    def __init__(self):
        super(HttpService, self).__init__(
            base_url=CONF.openstack.metadata_base_url,
            https_allow_insecure=CONF.openstack.https_allow_insecure,
            https_ca_bundle=CONF.openstack.https_ca_bundle)
        self._enable_retry = True

    def load(self):
        super(HttpService, self).load()
        if CONF.openstack.add_metadata_private_ip_route:
            network_utils.check_metadata_ip_route(self._base_url)
        try:
            self._get_meta_data()
            return True
        except Exception:
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.openstack.metadata_base_url)
            return False

    def _post_data(self, path, data):
        self._http_request(path, data=data)
        return True

    def _get_password_path(self):
        return 'openstack/%s/password' % self._POST_PASSWORD_MD_VER

    @property
    def can_post_password(self):
        try:
            self._get_meta_data(self._POST_PASSWORD_MD_VER)
            return True
        except base.NotExistingMetadataException:
            return False

    @property
    def is_password_set(self):
        path = self._get_password_path()
        return len(self._get_data(path)) > 0

    def post_password(self, enc_password_b64):
        try:
            path = self._get_password_path()
            action = lambda: self._post_data(path, enc_password_b64)
            return self._exec_with_retry(action)
        except error.HTTPError as ex:
            if ex.code == 409:
                # Password already set
                return False
            else:
                raise

    def _get_network_details_builder(self):
        """Get the required `NetworkDetailsBuilder` object.

        The `NetworkDetailsBuilder` is used in order to create the
        `NetworkDetails` object using the network related information
        exposed by the current metadata provider.
        """
        if not self._network_details_builder:
            network_data = None
            try:
                data = self._get_data(self._NETWORK_DATA_JSON)
                network_data = json.loads(encoding.get_as_string(data))
            except base.NotExistingMetadataException:
                LOG.debug("JSON network metadata not found.")
            except ValueError as exc:
                LOG.error("Failed to load json data: %r" % exc)
            else:
                self._network_details_builder = _NetworkDetailsBuilder(
                    service=self, network_data=network_data)

            if not network_data:
                super(HttpService, self)._get_network_details_builder()

        return self._network_details_builder

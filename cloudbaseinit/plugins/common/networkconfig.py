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

import ipaddress
from oslo_log import log as oslo_logging
import six

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugin_base
from cloudbaseinit.utils import network as network_utils

LOG = oslo_logging.getLogger(__name__)


class NetworkConfigPlugin(plugin_base.BasePlugin):

    """Static networking plugin.

    Statically configures each network adapter for which corresponding
    details are found into metadata.
    """

    def __init__(self):
        super(NetworkConfigPlugin, self).__init__()
        self._network_details = None
        self._osutils = osutils_factory.get_os_utils()
        self._adapters = sorted(self._osutils.get_network_adapters())

    @staticmethod
    def _update_link(link, data):
        """Update the received link with the received information."""
        new_link = {}
        for field in service_base.LINK_FIELDS:
            new_link[field] = getattr(link, field)
        new_link.update(data)
        return service_base.Link(**new_link)

    @staticmethod
    def _update_network(network, data):
        """Update the received link with the received information."""
        new_network = {}
        for field in service_base.NETWORK_FIELDS:
            new_network[field] = getattr(network, field)
        new_network.update(data)
        return service_base.Network(**new_network)

    def _validate_link(self, link):
        """Check if the link contains all the required information.

        :rtype: cloudbaseinit.metadata.services.basenetworkservice.Link
        """
        new_link = {}
        mac_address = link.mac_address
        if not mac_address:
            mac_address = self._on_mac_not_found(link)
            if not mac_address:
                raise exception.NetworkDetailsError(
                    "The mac_address is missing.")
            else:
                new_link[constant.MAC_ADDRESS] = mac_address

        if new_link:
            return self._update_link(link, new_link)
        else:
            return link

    def _validate_network(self, network, routes):
        """Check if the network contains all the required information.

        :rtype: cloudbaseinit.metadata.services.basenetworkservice.Network
        """
        new_network = {}
        if not network.netmask:
            try:
                ip_address, netmask = self._on_netmask_not_found(network)
            except (ValueError, TypeError):
                raise exception.NetworkDetailsError(
                    "The netmask is missing for network %r", network)
            else:
                new_network[constant.IP_ADDRESS] = ip_address
                new_network[constant.NETMASK] = netmask

        if not network.gateway:
            gateway = self._on_gateway_not_found(routes)
            if gateway:
                new_network[constant.GATEWAY] = gateway
            else:
                raise exception.NetworkDetailsError(
                    "The gateway is missing for network %r", network)

        if new_network:
            return self._update_network(network, new_network)
        else:
            return network

    def _on_mac_not_found(self, link):
        """Handle the scenario where the mac address is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.

        :rtype: bool
        """
        if not link.name:
            LOG.debug("Failed to get the link name.")
            return None

        LOG.debug("Trying to find the MAC address using link name.")
        for adapter_name, mac_address in self._adapters:
            if adapter_name == link.name:
                LOG.debug("The MAC address for the current link was found.")
                return mac_address.upper()
        LOG.debug("The link name %r is not present in the network adapters"
                  " information %r.", link.name, self._adapters)
        return None

    def _set_static_network_config_v4(self, link, network):
        """Set IPv4 info for a network card."""
        LOG.debug("Setting static network config %r for %r", network, link)
        return self._osutils.set_static_network_config(
            mac_address=link.mac_address,
            address=network.ip_address,
            netmask=network.netmask,
            broadcast=network.broadcast,
            gateway=network.gateway,
            dnsnameservers=network.dns_nameservers,
        )

    @staticmethod
    def _on_netmask_not_found(network):
        """Handle the scenario where the netmask is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.

        :rtype: tuple or None
        """
        ip_address = network.ip_address
        if not ip_address:
            LOG.debug("Failed to get the ip address.")
            return None

        LOG.debug("Checking if the ip address is condensed with "
                  "CIDR netmask.")
        if "/" in ip_address:
            ip_address, netmask = ip_address.split("/")
            interface = network_utils.process_interface(ip_address, netmask)
            ip_address = interface[constant.IP_ADDRESS]
            netmask = interface[constant.NETMASK]
            LOG.debug("The netmask found: %r" % netmask)
            return ip_address, netmask

        LOG.debug("Failed to obtain the netmask.")
        return None

    @staticmethod
    def _on_gateway_not_found(routes):
        """Handle the scenario where the gateway is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.

        :rtype: bool
        """
        current_network = None
        current_route = None

        for route in routes[:]:
            if not route.netmask or not route.gateway:
                LOG.debug("The route %r does not contains all the "
                          "required fields.", route)
                routes.remove(route)
                continue

            netmask = network_utils.netmask_to_int(route.netmask)
            network = ipaddress.ip_network(six.u("%s/%s") % (
                route.network, netmask))
            if not current_network or current_network in network:
                current_network = network
                current_route = route

        if current_route:
            LOG.debug("The gateway for the current network was found. (%s)",
                      current_route.gateway)
            return current_route.gateway

        LOG.debug("No extra information regarding gateway available.")

    def _configure_phy(self, link):
        """Configure physical NICs."""
        LOG.debug("Configuring the physical NIC: %r.", link.mac_address)
        response = False
        for network in self._network_details.get_link_networks(link.id):
            routes = self._network_details.get_network_routes(network.id)
            try:
                network = self._validate_network(network, routes)
            except exception.NetworkDetailsError as exc:
                LOG.debug("Failed to configure network %s: %s", network, exc)
                continue
            LOG.debug("Configuring network %(id)r.", {"id": network.id})
            if network.version == constant.IPV4:
                response |= self._set_static_network_config_v4(link, network)
            else:
                # TODO(alexcoman): Update the manner of configuring the
                #                  IPV6 networks.
                LOG.warning("Setting static network config for IPV6 network "
                            "is not supported.")
        return response

    def _configure_interface(self, link):
        """Configure different types of interfaces.

        :rtype: bool
        """
        try:
            link = self._validate_link(link)
        except exception.NetworkDetailsError as exc:
            LOG.debug("Failed to configure link %s: %s", link, exc)

        LOG.debug("Configuring link %(name)r: %(mac)s",
                  {"name": link.name, "mac": link.mac_address})
        if link.type == constant.PHY:
            return self._configure_phy(link)

        raise exception.NetworkDetailsError("The %r interface type is not"
                                            " supported." % link.type)

    def execute(self, service, shared_data):
        self._network_details = service.get_network_details()
        if not self._network_details:
            LOG.debug("Network details are not available.")
            return plugin_base.PLUGIN_EXECUTION_DONE, False

        if not isinstance(self._network_details, service_base.NetworkDetails):
            raise exception.CloudbaseInitException(
                "Invalid NetworkDetails object {!r} provided."
                .format(type(self._network_details)))

        reboot_required = False
        configured = False
        for link in self._network_details.get_links():
            try:
                reboot_required |= self._configure_interface(link)
            except exception.NetworkDetailsError as exc:
                LOG.error("Failed to configure the interface %r: %s",
                          link.mac_address, exc)
            else:
                configured = True

        if not configured:
            LOG.error("No adapters were configured")

        return plugin_base.PLUGIN_EXECUTION_DONE, reboot_required

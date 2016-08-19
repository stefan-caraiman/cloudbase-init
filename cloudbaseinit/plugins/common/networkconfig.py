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
import abc

import ipaddress
from oslo_log import log as oslo_logging
import six

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit import model as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base as plugin_base
from cloudbaseinit.utils import network as network_utils

LOG = oslo_logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class _Processor(object):

    """Base class for all the data processors."""

    SUPPORTED_MODELS = []

    def __init__(self, model, plugin):
        if model.__class__ not in self.SUPPORTED_MODELS:
            raise exception.NetworkDetailsError(
                "The current executor do not support %r models" % model)
        self._model = model
        self._plugin = plugin

        # pylint: disable=protected-access
        self._network_details = plugin._network_details
        self._osutils = plugin._osutils

        # Check if the model contains all the required information.
        self._validate()

    @abc.abstractmethod
    def _validate(self):
        """Check if the received model is valid."""
        pass

    @abc.abstractmethod
    def run(self):
        """Use the model information in order to setup up the system."""
        pass


class _LinkExecutor(_Processor):

    """Process link related information."""

    SUPPORTED_MODELS = [network_model.Link]

    def __init__(self, model, plugin):
        super(_LinkExecutor, self).__init__(model, plugin)
        self._networks = self._network_details.get_link_networks(model.link_id)

    def _on_mac_not_found(self):
        """Handle the scenario where the mac address is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.

        :rtype: bool
        """
        if not self._model.name:
            LOG.debug("Failed to get the link name.")
            return None

        LOG.debug("Trying to find the MAC address using link name.")
        network_adapters = sorted(self._osutils.get_network_adapters())
        for adapter_name, mac_address in network_adapters:
            if adapter_name == self._model.name:
                LOG.debug("The MAC address for the current link was found.")
                return mac_address.upper()
        LOG.debug("The link name %r is not present in the network adapters"
                  " information %r.", self._model.name, network_adapters)
        return None

    def _validate(self):
        """Check if the link contains all the required information."""
        mac_address = self._model.mac_address
        if not mac_address:
            mac_address = self._on_mac_not_found()
            if not mac_address:
                raise exception.NetworkDetailsError(
                    "The mac_address is missing.")

        if "-" in mac_address:
            mac_address = mac_address.replace("-", ":")

        if self._model.mac_address != mac_address:
            LOG.debug("Update the mac address %r with %r",
                      self._model.mac_address, mac_address)
            self._model.mac_address = mac_address
            self._model.commit()

    def run(self):
        """Use the model information in order to setup up the system."""
        LOG.debug("Configuring link %(name)r: %(mac)s",
                  {"name": self._model.name, "mac": self._model.mac_address})

        response = False
        for network in self._networks:
            executor = self._plugin.get_executor(network)
            if not executor:
                LOG.debug("Network type %r is currently unsupported.",
                          network.network_type)
                continue

            try:
                response |= executor.run()
            except exception.DataProcessingError as reason:
                LOG.error("Failed to setup subnetwork %r: %r",
                          network, reason)
                LOG.debug("The content of the %r model: %r",
                          network, network.dump())

        return response


class _StaticSubNetworkExecutor(_Processor):

    SUPPORTED_MODELS = [network_model.StaticNetwork]

    def _on_netmask_not_found(self):
        """Handle the scenario where the netmask is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.

        :rtype: tuple or None
        """
        ip_address = self._model.ip_address
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

    def _on_gateway_not_found(self):
        """Handle the scenario where the gateway is missing from raw data.

        Check the raw data in order to find some pice of information that
        may help to fill the missing data if possible.
        """
        current_network = None
        current_route = None
        routes = self._network_details.get_network_routes(
            self._model.subnet_id)

        for route in routes[:]:
            if not route.netmask or not route.gateway:
                LOG.debug("The route %r does not contains all the "
                          "required fields.", route)
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

    def _validate(self):
        """Check if the network contains all the required information."""
        changes = {}
        if not self._model.netmask:
            try:
                ip_address, netmask = self._on_netmask_not_found()
            except (ValueError, TypeError):
                raise exception.NetworkDetailsError(
                    "The netmask is missing for network %r", self._model)
            else:
                changes[constant.IP_ADDRESS] = ip_address
                changes[constant.NETMASK] = netmask

        if not self._model.gateway:
            gateway = self._on_gateway_not_found()
            if gateway:
                changes[constant.GATEWAY] = gateway
            else:
                raise exception.NetworkDetailsError(
                    "The gateway is missing for network %r", self._model)

        if changes:
            self._model.update(changes)
            self._model.commit()

    def _set_static_network_config_v4(self):
        """Set IPv4 info for a network card."""
        link = self._network_details.get_link(self._model.assigned_to)
        LOG.debug("Setting static network config %r for %r",
                  self._model, link)

        return self._osutils.set_static_network_config(
            mac_address=link.mac_address,
            address=self._model.ip_address,
            netmask=self._model.netmask,
            broadcast=self._model.broadcast,
            gateway=self._model.gateway,
            dnsnameservers=self._model.dns_nameservers,
        )

    def run(self):
        if self._model.version == constant.IPV4:
            return self._set_static_network_config_v4()
        else:
            LOG.warning("Setting static network config for IPV6 network "
                        "is not supported.")


class NetworkConfigPlugin(plugin_base.BasePlugin):

    """Static networking plugin.

    Statically configures each network adapter for which corresponding
    details are found into metadata.
    """

    _SUPPORTED_PROCESSORS = (
        _LinkExecutor, _StaticSubNetworkExecutor,
    )

    def __init__(self):
        super(NetworkConfigPlugin, self).__init__()
        self._network_details = None
        self._osutils = osutils_factory.get_os_utils()

        # Load all the supported executors
        self._executors = {}
        for executor in self._SUPPORTED_PROCESSORS:
            for model in executor.SUPPORTED_MODELS:
                self._executors[model] = executor

    def get_executor(self, model):
        """Get a specialized executor for processing this kind of model."""
        executor = self._executors.get(model.__class__, None)
        if not executor:
            LOG.error("No executor available for %s.", model)
            return None
        return executor(model, self)

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
            executor = self.get_executor(link)
            if not executor:
                LOG.warning("Link type %r is currently unsupported.",
                            link.link_type)
                LOG.debug("Unsuported link type %r: %s", link, link.dump())
                continue

            try:
                reboot_required |= executor.run()
            except exception.NetworkDetailsError as exc:
                LOG.error("Failed to configure the interface %r: %s",
                          link.mac_address, exc)
            else:
                configured = True

        if not configured:
            LOG.error("No adapters were configured")

        return plugin_base.PLUGIN_EXECUTION_DONE, reboot_required

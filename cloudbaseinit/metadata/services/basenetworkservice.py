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

"""Network Metadata Services base-classes.

(Beginning of) the contract that metadata services which expose network
information and parsers must follow.
"""

import abc
import collections
import operator
import uuid

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit.utils import network as network_utils

LOG = oslo_logging.getLogger(__name__)


LINK_FIELDS = [
    constant.ID, constant.NAME, constant.TYPE, constant.MAC_ADDRESS,
    constant.MTU, constant.NEUTRON_PORT_ID, constant.BOND_LINKS,
    constant.BOND_MODE, constant.BOND_MIIMON, constant.BOND_HASH_POLICY,
    constant.VIF_ID, constant.VLAN_ID, constant.VLAN_LINK,
    constant.PRIORITY,
]
NETWORK_FIELDS = [
    constant.ID, constant.IP_ADDRESS, constant.VERSION, constant.NETMASK,
    constant.GATEWAY, constant.BROADCAST, constant.DNS,
    constant.ASSIGNED_TO, constant.NEUTRON_NETWORK_ID, constant.PRIORITY,
]
ROUTE_FIELDS = [
    constant.ID, constant.NETWORK, constant.NETMASK, constant.GATEWAY,
    constant.ASSIGNED_TO,
]

Link = collections.namedtuple("Link", LINK_FIELDS)
Network = collections.namedtuple("Network", NETWORK_FIELDS)
Route = collections.namedtuple("Route", ROUTE_FIELDS)


class NetworkDetails(object):

    """Container for network information.

    .. note ::
        Both the custom service(s) and the networking plugin
        should know about the entries of these kind of objects.
    """

    def __init__(self, links, networks, references, routes):
        self._assigned_to = references
        self._links = links
        self._networks = networks
        self._routes = routes

    def get_links(self):
        """Return a list with the ids of the available links.

        :rtype: list

        .. note ::
            The link namedtuple contains the following fields: `id`, `name`,
            `type`, `mac_address`, `mtu`, `bond_links`, `bond_mode`,
            `vlan_id`, `priority` and `vlan_link`.
        """
        return [link for link in sorted(
            self._links.values(), key=operator.attrgetter("priority"))]

    def get_link_networks(self, link_id):
        """Returns all the networks assigned to the required link.

        :rtype: list of `cloudbaseinit.metadata.services.basenetworkservice.
                         Network objects.`
        .. note ::
            The link namedtuple contains the following fields: `id`,
            `ip_address`, `version`, `netmask`, `gateway`, `broadcast`,
            `dns_nameservers`, `priority` and `assigned_to`.
        """
        networks = [self._networks[network_id]
                    for network_id in self._assigned_to[link_id]]
        return [network for network in
                sorted(networks, key=operator.attrgetter("priority"))]

    def get_network_routes(self, network_id):
        """Returns all the routes assigned to the required network.

        :rtype: list of `cloudbaseinit.metadata.services.basenetworkservice.
                         Route objects.`
        .. note ::
            The link namedtuple contains the following fields: `id`,
            `network`, `netmask`, `gateway`, `assigned_to`.
        """
        return [self._routes[route_id] for route_id in
                self._assigned_to.get(network_id)]


@six.add_metaclass(abc.ABCMeta)
class NetworkDetailsBuilder(object):

    """The contract class for all the network details builders.

    Build the `NetworkDetails` object using the network information
    available in service specific format in order to be easily consumed
    by the network plugin.
    """

    class _Field(collections.namedtuple("Field", ["name", "alias",
                                                  "default"])):

        """Container for meta information regarding network data.

        :param name:     The name of the current piece of information.
        :param alias:    A list of alternative names of the current piece of
                         information (default: `None`).
        :param default:  If this information is not required a default value
                         can be provided (default: `None`)
        """

        __slots__ = ()

        def __new__(cls, name, alias=None, default=None):
            return super(cls, cls).__new__(cls, name, alias, default)

    def __init__(self, service):
        self._service = service
        self._networks = {}
        self._links = {}
        self._routes = {}

        self._link = {
            constant.ID: self._Field(
                name=constant.ID, default=lambda: str(uuid.uuid1())),
            constant.NAME: self._Field(name=constant.NAME),
            constant.MAC_ADDRESS: self._Field(name=constant.MAC_ADDRESS),
            constant.TYPE: self._Field(
                name=constant.TYPE, default=constant.PHY),
            constant.NEUTRON_PORT_ID: self._Field(
                name=constant.NEUTRON_PORT_ID),
            constant.MTU: self._Field(name=constant.MTU),
            constant.BOND_LINKS: self._Field(name=constant.BOND_LINKS),
            constant.BOND_MODE: self._Field(name=constant.BOND_MODE),
            constant.BOND_MIIMON: self._Field(name=constant.BOND_MIIMON),
            constant.BOND_HASH_POLICY: self._Field(
                name=constant.BOND_HASH_POLICY),
            constant.VIF_ID: self._Field(name=constant.VIF_ID),
            constant.VLAN_ID: self._Field(name=constant.VLAN_ID),
            constant.VLAN_LINK: self._Field(name=constant.VLAN_LINK),
            constant.PRIORITY: self._Field(
                name=constant.PRIORITY, default=0),
        }
        self._network = {
            constant.ID: self._Field(
                name=constant.ID, default=lambda: str(uuid.uuid1())),
            constant.IP_ADDRESS: self._Field(name=constant.IP_ADDRESS),
            constant.VERSION: self._Field(
                name=constant.VERSION, default=constant.IPV4),
            constant.NETMASK: self._Field(name=constant.NETMASK),
            constant.GATEWAY: self._Field(name=constant.GATEWAY),
            constant.BROADCAST: self._Field(name=constant.BROADCAST),
            constant.DNS: self._Field(name=constant.DNS, default=[]),
            constant.ASSIGNED_TO: self._Field(name=constant.ASSIGNED_TO),
            constant.NEUTRON_NETWORK_ID: self._Field(
                name=constant.NEUTRON_NETWORK_ID),
            constant.PRIORITY: self._Field(
                name=constant.PRIORITY, default=0),
        }
        self._route = {
            constant.ID: self._Field(
                name=constant.ID, default=lambda: str(uuid.uuid1())),
            constant.NETWORK: self._Field(name=constant.NETWORK),
            constant.NETMASK: self._Field(name=constant.NETMASK),
            constant.GATEWAY: self._Field(name=constant.GATEWAY),
            constant.ASSIGNED_TO: self._Field(name=constant.ASSIGNED_TO),
        }

    @staticmethod
    def _get_field(field, raw_data):
        """Find the required information in the raw data."""
        aliases = [field.name]
        if isinstance(field.alias, six.string_types):
            aliases.append(field.alias)
        elif isinstance(field.alias, (list, tuple)):
            aliases.extend(field.alias)

        for alias in aliases:
            if alias in raw_data:
                return field.name, raw_data[alias]

        if six.callable(field.default):
            return field.name, field.default()
        else:
            return field.name, field.default

    def _get_fields(self, fields, raw_data):
        """Get the received fields from the raw data.

        Get all the required information related to all the received
        fields if it is posible.
        """
        data = {}
        for field in fields:
            field_name, field_value = self._get_field(field, raw_data)
            data[field_name] = field_value
        return data

    def _process_links(self):
        """Process raw data regarding the links."""
        LOG.debug("Processing raw data regarding the links.")
        links = {}
        for _, raw_link in self._links.items():
            if raw_link[constant.MAC_ADDRESS]:
                address = raw_link[constant.MAC_ADDRESS].replace('-', ':')
                raw_link[constant.MAC_ADDRESS] = address
            try:
                link = Link(**raw_link)
            except TypeError as exc:
                LOG.debug("Failed to process raw link %(link)r: %(reason)s",
                          {"link": raw_link, "reason": exc})
                raise exception.NetworkDetailsError(
                    "Invalid raw link %r provied." % raw_link)
            else:
                links[link.id] = link
        LOG.debug("%d links available.", len(links))
        return links

    def _process_networks(self):
        """Process raw data regarding the networks."""
        LOG.debug("Processing raw data regarding the networks.")
        networks = {}
        references = {}
        for _, raw_network in self._networks.items():
            raw_network.update(network_utils.process_interface(
                ip_address=raw_network[constant.IP_ADDRESS],
                netmask=raw_network[constant.NETMASK]))
            try:
                network = Network(**raw_network)
            except TypeError as exc:
                LOG.debug("Failed to process raw network %(network)r: "
                          "%(exc)s", {"network": raw_network, "exc": exc})
                raise exception.NetworkDetailsError(
                    "Invalid raw network %r provied." % raw_network)
            else:
                networks[network.id] = network
                assigned_to = references.setdefault(
                    network.assigned_to, [])
                assigned_to.append(network.id)
        LOG.debug("%d networks available.", len(networks))
        return networks, references

    def _process_routes(self, references):
        """Process raw data regarding the routes."""
        LOG.debug("Processing raw data regarding the routes.")
        routes = {}
        for _, raw_route in self._routes.items():
            try:
                route = Route(**raw_route)
            except TypeError as exc:
                LOG.debug("Failed to process raw route %(route)r: "
                          "%(exc)s", {"route": raw_route, "exc": exc})
                raise exception.NetworkDetailsError(
                    "Invalid raw route %r provied." % raw_route)
            else:
                routes[route.id] = route
                assigned_to = references.setdefault(route.assigned_to, [])
                assigned_to.append(route.id)

        LOG.debug("%d routes available.", len(routes))
        return routes

    @abc.abstractmethod
    def _process(self):
        """Process the received network information."""
        pass

    def get_network_details(self):
        """Create a `NetworkDetails` object using available information."""
        if not self._links or not self._networks:
            LOG.debug("Processing available network information.")
            self._process()

        links = self._process_links()
        networks, references = self._process_networks()
        routes = self._process_routes(references)

        return NetworkDetails(links=links,
                              networks=networks,
                              references=references,
                              routes=routes)


@six.add_metaclass(abc.ABCMeta)
class BaseNetworkMetadataService(service_base.BaseMetadataService):

    """Base class for all metadata services which expose network information.

    Process the network information provided in the service specific
    format to a format that can be easily procesed by cloudbase-init
    plugins.
    """

    def __init__(self):
        super(BaseNetworkMetadataService, self).__init__()

    @abc.abstractmethod
    def _get_network_details_builder(self):
        """Get the required `NetworkDetailsBuilder` object.

        The `NetworkDetailsBuilder` is used in order to create the
        `NetworkDetails` object using the network related information
        exposed by the current metadata provider.
        """
        pass

    def get_network_details(self):
        """Return a list of `NetworkDetails` objects.

        These objects provide details regarding static
        network configuration.
        """
        builder = self._get_network_details_builder()
        if builder:
            return builder.get_network_details()


@six.add_metaclass(abc.ABCMeta)
class BaseHTTPNetworkMetadataService(service_base.BaseHTTPMetadataService,
                                     BaseNetworkMetadataService):

    """Base class for http services which expose network information."""

    pass

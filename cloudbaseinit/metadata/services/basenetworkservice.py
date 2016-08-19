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

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base as service_base
from cloudbaseinit import model as network_model

LOG = oslo_logging.getLogger(__name__)


class NetworkDetails(object):

    """Container for network information.

    .. note ::
        Both the custom service(s) and the networking plugin
        should know about the entries of these kind of objects.
    """

    def __init__(self, links, networks, routes):
        self._links = links
        self._networks = networks
        self._routes = routes

    def get_link(self, link_id):
        """Return the required link."""
        return self._links[link_id]

    def get_links(self):
        """Return a list with all the available Link models."""
        return sorted(self._links.values(),
                      key=operator.attrgetter("priority"))

    def get_link_networks(self, link_id):
        """Returns all the networks assigned to the required link."""
        networks = []
        for network in self._networks.values():
            if network.assigned_to == link_id:
                networks.append(network)

        return sorted(networks, key=operator.attrgetter("priority"))

    def get_network_routes(self, network_id):
        """Returns all the routes assigned to the required network."""
        routes = []
        for route in self._routes.values():
            if route.assigned_to == network_id:
                routes.append(route)

        return routes


@six.add_metaclass(abc.ABCMeta)
class NetworkDetailsBuilder(object):

    """The contract class for all the network details builders.

    Build the `NetworkDetails` object using the network information
    available in service specific format in order to be easily consumed
    by the network plugin.
    """

    _SUPPORTED_MODELS = (network_model.Link, network_model.BondLink,
                         network_model.VLANLink, network_model.Subnetwork,
                         network_model.StaticNetwork, network_model.Route)
    Alias = collections.namedtuple("Alias", ["field", "name"])

    def __init__(self, service):
        self._service = service
        self._models = {}
        self._networks = {}
        self._links = {}
        self._routes = {}

        # Get information regarding the structure of the suported models.
        for model in self._SUPPORTED_MODELS:
            # pylint: disable=no-member
            fields = [field for field in model._meta.fields]
            self._models[model] = set(fields)

    @staticmethod
    def _apply_mapping(raw_data, aliases):
        """Create a new dictionary containing only relevant information.

        :param raw_data:  The raw data which contains the required information
        :param aliases:   A list which contains all the `Alias` objects
                          required for this kind of data
        """
        data = {}
        for alias in aliases:
            if alias.name in raw_data:
                data[alias.field] = raw_data.get(alias.name)
        return data

    def _get_model(self, fields, models=None):
        """Get the model able to handle the received fields.

        :param fields: A list which contains all the available keys
                       for a specific data set.
        :param models: A list of models that can be used.
        """
        maximum = (0, None)
        fields = set(fields)

        for model in models or self._models:
            model_fields = self._models.get(model, set())
            common_fields = len(fields & model_fields)
            if common_fields > maximum[0]:
                maximum = (common_fields, model)

        return maximum[1]

    def _add_link(self, fields):
        """Create a link using the received information."""
        models = [network_model.Link, network_model.BondLink,
                  network_model.VLANLink]
        link = self._create_entity(fields, models)

        LOG.debug("Adding %s %r to NetworkDetails object.",
                  link, link.link_id)
        self._links[link.link_id] = link
        return link

    def _add_subnetwork(self, fields):
        """Create a network using the received information."""
        models = [network_model.Subnetwork, network_model.StaticNetwork]
        network = self._create_entity(fields, models)

        LOG.debug("Adding %s %r assigned to %s to NetworkDetails object.",
                  network, network.subnet_id, network.assigned_to)
        self._networks[network.subnet_id] = network
        return network

    def _add_route(self, fields):
        """Create a route using the received information."""
        route = self._create_entity(fields, [network_model.Route])

        LOG.debug("Adding %s %r assigned to %s to NetworkDetails object.",
                  route, route.route_id, route.assigned_to)
        self._routes[route.route_id] = route
        return route

    def _create_entity(self, raw_data, models=None):
        """Create a new entity using the received model and data.

        :param raw_data: A dictionary that contains all the available
                         information for the required model.
        :param models:   A list of models that can be used.
        """
        model = self._get_model(raw_data.keys(), models)
        if not model:
            raise exception.NetworkDetailsError("No model available for %r." %
                                                raw_data)
        try:
            entity = model(**raw_data)
        except exception.DataProcessingError as exc:
            LOG.debug("Failed to create %(entity)r: %(reason)s",
                      {"entity": model.__name__, "reason": exc})
            raise exception.NetworkDetailsError("Invalid data %r provied." %
                                                raw_data)
        return entity

    @abc.abstractmethod
    def _process(self):
        """Process the received network information."""
        pass

    def get_network_details(self):
        """Create a `NetworkDetails` object using available information."""
        if not self._links or not self._networks:
            LOG.debug("Processing available network information.")
            self._process()

        return NetworkDetails(links=self._links,
                              networks=self._networks,
                              routes=self._routes)


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

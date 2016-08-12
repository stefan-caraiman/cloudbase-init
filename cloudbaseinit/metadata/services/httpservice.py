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
from oslo_config import cfg
from oslo_log import log as oslo_logging
from six.moves.urllib import error

from cloudbaseinit import constants
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import network as network_utils

OPENSTACK_OPTS = [
    cfg.StrOpt("metadata_base_url", default="http://169.254.169.254/",
               help="The base URL where the service looks for metadata",
               deprecated_group="DEFAULT"),
    cfg.BoolOpt("add_metadata_private_ip_route", default=True,
                help="Add a route for the metadata ip address to the gateway",
                deprecated_group="DEFAULT"),
    cfg.BoolOpt("https_allow_insecure", default=False,
                help="Whether to disable the validation of HTTPS "
                     "certificates."),
    cfg.StrOpt("https_ca_bundle", default=None,
               help="The path to a CA_BUNDLE file or directory with "
                    "certificates of trusted CAs."),
]

CONF = cfg.CONF
CONF.register_opts(OPENSTACK_OPTS, "openstack")

LOG = oslo_logging.getLogger(__name__)


class _NetworkDetailsBuilder(service_base.NetworkDetailsBuilder):

    """OpenStack HTTP Service network details builder."""

    _ASSIGNED_TO = "link"
    _MAC_ADDRESS = "ethernet_mac_address"
    _NAME = "id"
    _VERSION = "type"
    _LINKS = "links"
    _NETWORKS = "networks"
    _ROUTES = "routes"
    _IPV4 = "ipv4"
    _PRIORITY = {
        constants.PHY: 0,
        constants.BOND: 10,
        constants.VIF: 20,
        constants.VLAN: 30,
    }

    def __init__(self, service, network_data):
        super(_NetworkDetailsBuilder, self).__init__(service)
        self._network_data = network_data
        self._invalid_links = []

        self._link.update({
            constants.NAME: self._Field(
                name=constants.NAME, alias=self._NAME),
            constants.MAC_ADDRESS: self._Field(
                name=constants.MAC_ADDRESS,
                alias=[self._MAC_ADDRESS, constants.VLAN_MAC_ADDRESS]),
        })
        self._network.update({
            constants.GATEWAY: self._Field(
                name=constants.GATEWAY),
            constants.VERSION: self._Field(
                name=constants.VERSION, alias=self._VERSION,
                default=4),
            constants.ASSIGNED_TO: self._Field(
                name=constants.ASSIGNED_TO, alias=self._ASSIGNED_TO),
        })

    def _process_raw_networks(self):
        """Process the information related to networks."""
        network_data = self._network_data.get(self._NETWORKS, [])
        if not network_data:
            LOG.warning("No information regarding networks available.")
            return

        for raw_network in network_data:
            network = self._get_fields(self._network.values(), raw_network)
            if network:
                if network[constants.VERSION] == self._IPV4:
                    network[constants.VERSION] = constants.IPV4
                else:
                    network[constants.VERSION] = constants.IPV6
                    network[constants.PRIORITY] = 10
                self._networks[network[constants.ID]] = network
            else:
                LOG.warning("The network %r does not contains all the "
                            "required fields.", raw_network)
                continue

            if network[constants.ASSIGNED_TO] in self._invalid_links:
                self._invalid_links.remove(network[constants.ASSIGNED_TO])

            for raw_route in raw_network.get(self._ROUTES, []):
                raw_route[constants.ASSIGNED_TO] = network[constants.ID]
                route = self._get_fields(self._route.values(), raw_route)
                if route:
                    self._routes[route[constants.ID]] = route
                else:
                    LOG.warning("The route %r does not contain all the "
                                "required fields.", raw_route)

    def _process(self):
        """Digest the received network information."""
        for raw_link in self._network_data.get(self._LINKS, []):
            link = self._get_fields(self._link.values(), raw_link)
            if link:
                priority = self._PRIORITY.get(link[constants.TYPE], None)
                if priority is None:
                    LOG.debug("No priority available for %r (using: 0)",
                              link[constants.TYPE])
                    priority = 0
                link[constants.PRIORITY] = priority
                self._links[link[constants.ID]] = link
            else:
                LOG.warning("The link %r does not contain all the required "
                            "fields.", raw_link)

        self._invalid_links = list(self._links.keys())
        self._process_raw_networks()
        while self._invalid_links:
            invalid_link = self._invalid_links.pop()
            LOG.debug("The link %r does not contain any network.",
                      invalid_link)


class HttpService(base.BaseHTTPMetadataService,
                  baseopenstackservice.BaseOpenStackService):

    _POST_PASSWORD_MD_VER = '2013-04-04'
    _NETWORK_DATA_JSON = "openstack/latest/metadata/network_data.json"

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

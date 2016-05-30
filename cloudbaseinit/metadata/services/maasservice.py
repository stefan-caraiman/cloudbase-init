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

import re

from oauthlib import oauth1
from oslo_config import cfg
from oslo_log import log as oslo_logging
try:
    import simplejson as json
except ImportError:
    import json

from cloudbaseinit import constants
from cloudbaseinit.metadata.services import basenetworkservice as service_base
from cloudbaseinit.utils import x509constants

MAAS_OPTS = [
    cfg.StrOpt("metadata_base_url", default=None,
               help="The base URL for MaaS metadata",
               deprecated_name="maas_metadata_url",
               deprecated_group="DEFAULT"),
    cfg.StrOpt("oauth_consumer_key", default="",
               help="The MaaS OAuth consumer key",
               deprecated_name="maas_oauth_consumer_key",
               deprecated_group="DEFAULT"),
    cfg.StrOpt("oauth_consumer_secret", default="",
               help="The MaaS OAuth consumer secret",
               deprecated_name="maas_oauth_consumer_secret",
               deprecated_group="DEFAULT"),
    cfg.StrOpt("oauth_token_key", default="",
               help="The MaaS OAuth token key",
               deprecated_name="maas_oauth_token_key",
               deprecated_group="DEFAULT"),
    cfg.StrOpt("oauth_token_secret", default="",
               help="The MaaS OAuth token secret",
               deprecated_name="maas_oauth_token_secret",
               deprecated_group="DEFAULT"),
    cfg.BoolOpt("https_allow_insecure", default=False,
                help="Whether to disable the validation of HTTPS "
                "certificates."),
    cfg.StrOpt("https_ca_bundle", default=None,
               help="The path to a CA_BUNDLE file or directory with "
                    "certificates of trusted CAs."),
]

CONF = cfg.CONF
CONF.register_group(cfg.OptGroup("maas"))
CONF.register_opts(MAAS_OPTS, "maas")

LOG = oslo_logging.getLogger(__name__)


class _NetworkDetailsBuilder(service_base.NetworkDetailsBuilder):

    """MAAS HTTP service network details builders."""

    _CONFIG = "config"
    _SUBNETS = "subnets"

    # Network types
    STATIC = "static"
    MANUAL = "manual"

    def __init__(self, service, network_data):
        super(_NetworkDetailsBuilder, self).__init__(service)
        self._link.update({
            constants.TYPE: self._Field(name=constants.TYPE),
            constants.ID: self._Field(name=constants.ID),
            constants.MTU: self._Field(name=constants.MTU),
        })
        self._network.update({
            constants.DNS: self._Field(name=constants.DNS),
            constants.IP_ADDRESS: self._Field(name=constants.IP_ADDRESS),
            constants.NETMASK: self._Field(name=constants.NETMASK),
        })

        self._links = {}
        self._networks = {}
        self._network_data = network_data

    def _process_network(self, raw_subnets):
        """Digest the information related to networks."""
        success = False
        for raw_network in raw_subnets:
            network = self._get_fields(self._network.values(),
                                       raw_network)
            if network and network[constants.TYPE] == self.STATIC:
                self._networks[network[constants.ID]] = network
                success = True
        return success

    def _process(self):
        """Digest the received network information."""
        for raw_link in self._network_data.get(self._CONFIG, []):
            link = self._get_fields(self._link.values(), raw_link)
            if link and self._SUBNETS in raw_link:
                if self._process_network(raw_link.get(self._SUBNETS)):
                    self._links[link[constants.ID]] = link
            else:
                # Note(alexandrucoman): The current raw_link do not contain
                #                       all the required fields.
                LOG.warning("%r does not contain all the required fields.",
                            raw_link)
                continue


class _Realm(str):
    # There's a bug in oauthlib which ignores empty realm strings,
    # by checking that the given realm is always True.
    # This string class always returns True in a boolean context,
    # making sure that an empty realm can be used by oauthlib.
    def __bool__(self):
        return True

    __nonzero__ = __bool__


class MaaSHttpService(service_base.BaseHTTPNetworkMetadataService):

    _METADATA_2012_03_01 = '2012-03-01'

    def __init__(self):
        super(MaaSHttpService, self).__init__(
            base_url=CONF.maas.metadata_base_url,
            https_allow_insecure=CONF.maas.https_allow_insecure,
            https_ca_bundle=CONF.maas.https_ca_bundle)
        self._enable_retry = True
        self._metadata_version = self._METADATA_2012_03_01

    def load(self):
        super(MaaSHttpService, self).load()

        if not CONF.maas.metadata_base_url:
            LOG.debug('MaaS metadata url not set')
        else:
            try:
                self._get_cache_data('%s/meta-data/' % self._metadata_version)
                return True
            except Exception as ex:
                LOG.exception(ex)
                LOG.debug('Metadata not found at URL \'%s\'' %
                          CONF.maas.metadata_base_url)
        return False

    def _get_oauth_headers(self, url):
        client = oauth1.Client(
            CONF.maas.oauth_consumer_key,
            client_secret=CONF.maas.oauth_consumer_secret,
            resource_owner_key=CONF.maas.oauth_token_key,
            resource_owner_secret=CONF.maas.oauth_token_secret,
            signature_method=oauth1.SIGNATURE_PLAINTEXT)
        realm = _Realm("")
        headers = client.sign(url, realm=realm)[1]
        return headers

    def _http_request(self, url, data=None, headers=None):
        """Get content for received url."""
        if headers is None:
            headers = self._get_oauth_headers(url)
        super(MaaSHttpService, self)._http_request(url, data, headers)

    def get_host_name(self):
        return self._get_cache_data('%s/meta-data/local-hostname' %
                                    self._metadata_version, decode=True)

    def get_instance_id(self):
        return self._get_cache_data('%s/meta-data/instance-id' %
                                    self._metadata_version, decode=True)

    def get_public_keys(self):
        return self._get_cache_data('%s/meta-data/public-keys' %
                                    self._metadata_version,
                                    decode=True).splitlines()

    def get_client_auth_certs(self):
        certs_data = self._get_cache_data('%s/meta-data/x509' %
                                          self._metadata_version,
                                          decode=True)
        pattern = r"{begin}[\s\S]+?{end}".format(
            begin=x509constants.PEM_HEADER,
            end=x509constants.PEM_FOOTER)
        return re.findall(pattern, certs_data)

    def get_user_data(self):
        return self._get_cache_data('%s/user-data' % self._metadata_version)

    def _get_network_details_builder(self):
        """Get the required `NetworkDetailsBuilder` object.

        The `NetworkDetailsBuilder` is used in order to create the
        `NetworkDetails` object using the network related information
        exposed by the current metadata provider.
        """
        network_data = self._get_cache_data('latest/network_data.json',
                                            decode=True)
        if not network_data:
            LOG.debug("'network_data.json' not found.")
            return None

        try:
            network_data = json.loads(network_data)
        except ValueError as exc:
            LOG.error("Failed to load json data: %r" % exc)
            return None

        return _NetworkDetailsBuilder(self, network_data)

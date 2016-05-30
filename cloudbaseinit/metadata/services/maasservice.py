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

import posixpath
import re

from oauthlib import oauth1
from oslo_config import cfg
from oslo_log import log as oslo_logging
from six.moves.urllib import error
from six.moves.urllib import request
try:
    import simplejson as json
except ImportError:
    import json

from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import x509constants

opts = [
    cfg.StrOpt('maas_metadata_url', default=None,
               help='The base URL for MaaS metadata'),
    cfg.StrOpt('maas_oauth_consumer_key', default="",
               help='The MaaS OAuth consumer key'),
    cfg.StrOpt('maas_oauth_consumer_secret', default="",
               help='The MaaS OAuth consumer secret'),
    cfg.StrOpt('maas_oauth_token_key', default="",
               help='The MaaS OAuth token key'),
    cfg.StrOpt('maas_oauth_token_secret', default="",
               help='The MaaS OAuth token secret'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = oslo_logging.getLogger(__name__)


class _MaaSNetworkAdapter(base.BaseNetworkAdapter):

    """MaaS HTTP Service Network Adapter."""

    _CONFIG = "config"
    _SUBNETS = "subnets"

    FIELDS = {
        base.LINK: {
            base.TYPE: base.Field(name=base.TYPE, required=True),
            base.ID: base.Field(name=base.ID, required=True),
            base.MTU: base.Field(name=base.MTU, required=True),
        },
        base.NETWORK: {
            base.TYPE: base.Field(name=base.TYPE, required=True),
            base.DNS: base.Field(name=base.DNS, required=False),
            base.IP_ADDRESS: base.Field(name=base.IP_ADDRESS, required=False),
            base.NETMASK: base.Field(name=base.NETMASK, required=False),
        },
    }

    # Network types
    STATIC = "static"
    MANUAL = "manual"

    def __init__(self, service, network_data):
        super(_MaaSNetworkAdapter, self).__init__(service)
        self._links = {}
        self._networks = {}

        self._digest(network_data)

    def _digest_network(self, link, raw_subnets):
        """Digest the information related to networks."""
        networks = self._networks.setdefault(link[base.NAME], [])
        for raw_network in raw_subnets:
            network = self.get_fields(self.fields[base.NETWORK],
                                      raw_network)
            if network and network[base.TYPE] == self.STATIC:
                interface = self._digest_interface(network[base.IP_ADDRESS],
                                                   network[base.NETMASK])
                network.update(interface)
                networks.append(network)

    def _digest(self, network_data):
        """Digest the received network information."""
        for raw_link in network_data.get(self._CONFIG, []):
            try:
                link = self.get_fields(self.fields[base.LINK], raw_link)
                self._links[link[base.NAME]] = link
                self._digest_network(link, raw_link.get(self._SUBNETS, []))
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
        return self._links[name]

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
            keys: `name`, `type`, `ip_address`, `netmask` and
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


class _Realm(str):
    # There's a bug in oauthlib which ignores empty realm strings,
    # by checking that the given realm is always True.
    # This string class always returns True in a boolean context,
    # making sure that an empty realm can be used by oauthlib.
    def __bool__(self):
        return True

    __nonzero__ = __bool__


class MaaSHttpService(base.BaseMetadataService):
    _METADATA_2012_03_01 = '2012-03-01'

    def __init__(self):
        super(MaaSHttpService, self).__init__()
        self._enable_retry = True
        self._metadata_version = self._METADATA_2012_03_01

    def load(self):
        super(MaaSHttpService, self).load()

        if not CONF.maas_metadata_url:
            LOG.debug('MaaS metadata url not set')
        else:
            try:
                self._get_cache_data('%s/meta-data/' % self._metadata_version)
                return True
            except Exception as ex:
                LOG.exception(ex)
                LOG.debug('Metadata not found at URL \'%s\'' %
                          CONF.maas_metadata_url)
        return False

    def _get_response(self, req):
        try:
            return request.urlopen(req)
        except error.HTTPError as ex:
            if ex.code == 404:
                raise base.NotExistingMetadataException()
            else:
                raise

    def _get_oauth_headers(self, url):
        client = oauth1.Client(
            CONF.maas_oauth_consumer_key,
            client_secret=CONF.maas_oauth_consumer_secret,
            resource_owner_key=CONF.maas_oauth_token_key,
            resource_owner_secret=CONF.maas_oauth_token_secret,
            signature_method=oauth1.SIGNATURE_PLAINTEXT)
        realm = _Realm("")
        headers = client.sign(url, realm=realm)[1]
        return headers

    def _get_data(self, path):
        norm_path = posixpath.join(CONF.maas_metadata_url, path)
        oauth_headers = self._get_oauth_headers(norm_path)

        LOG.debug('Getting metadata from: %(norm_path)s',
                  {'norm_path': norm_path})
        req = request.Request(norm_path, headers=oauth_headers)
        response = self._get_response(req)
        return response.read()

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

    def get_network_adapter(self):
        network_data = self._get_cache_data('latest/network_data.json')
        if not network_data:
            return None

        try:
            network_data = json.loads(network_data)
        except ValueError:
            return None

        return _MaaSNetworkAdapter(self, network_data)

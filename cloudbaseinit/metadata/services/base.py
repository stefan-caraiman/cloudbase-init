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
import collections
import gzip
import io
import time

import ipaddress
from oslo_config import cfg
from oslo_log import log as oslo_logging
import six

from cloudbaseinit.utils import encoding


opts = [
    cfg.IntOpt('retry_count', default=5,
               help='Max. number of attempts for fetching metadata in '
               'case of transient errors'),
    cfg.FloatOpt('retry_count_interval', default=4,
                 help='Interval between attempts in case of transient errors, '
                 'expressed in seconds'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = oslo_logging.getLogger(__name__)

# Network types
IPV4 = 4
IPV6 = 6

# Field names related to network configuration
BROADCAST = "broadcast"
DNS = "dns_nameservers"
GATEWAY = "gateway"
ID = "id"
IP_ADDRESS = "ip_address"
NAME = "name"
MAC_ADDRESS = "mac_address"
MTU = "mtu"
NETMASK = "netmask"
TYPE = "type"
VERSION = "version"

# Fields name
LINK = "link"
NETWORK = "network"

# Both the custom service(s) and the networking plugin
# should know about the entries of these kind of objects.
NetworkDetails = collections.namedtuple(
    "NetworkDetails",
    [
        "name",
        "mac",
        "address",
        "address6",
        "netmask",
        "netmask6",
        "broadcast",
        "gateway",
        "gateway6",
        "dnsnameservers",
    ]
)


class Field(collections.namedtuple("Field", "name alias default required")):

    """Namedtuple used for fields information."""

    __slots__ = ()

    def __new__(cls, name, alias=None, default=None, required=False):
        return super(Field, cls).__new__(cls, name, alias, default, required)


@six.add_metaclass(abc.ABCMeta)
class BaseNetworkAdapter(object):

    """Translate the network information from the service specific
    format to a format that can be easily procesed by cloudbase-init
    plugins.
    """

    FIELDS = {
        LINK: {
            NAME: Field(name=NAME, required=True),
            MAC_ADDRESS: Field(name=MAC_ADDRESS, required=True),
        },
        NETWORK: {
            IP_ADDRESS: Field(name=IP_ADDRESS, required=True),
            NETMASK: Field(name=NETMASK, required=True),
            GATEWAY: Field(name=GATEWAY, required=True),
            VERSION: Field(name=VERSION, default=4, required=False),
            DNS: Field(name=DNS, default=[], required=False),
        },
    }

    def __init__(self, service):
        self._service = service
        self._fields = {}

        mro = type(self).mro()
        while mro:
            parent = mro.pop()
            try:
                fields = getattr(parent, "FIELDS")
                self._fields.update(fields)
            except AttributeError:
                pass

    @property
    def fields(self):
        """Return the information regarding network data fields."""
        return self._fields

    @staticmethod
    def _digest_interface(address, netmask=None):
        """Compute the provided information."""
        if netmask:
            address = six.u("%s/%s" % (address, netmask))

        interface = ipaddress.ip_interface(six.u(address))
        return {
            BROADCAST: str(interface.network.broadcast_address),
            NETMASK: str(interface.netmask),
            IP_ADDRESS: str(interface.ip),
            VERSION: str(interface.version)
        }

    @staticmethod
    def _get_field(field, raw_data):
        """Find the required information in the raw data."""
        aliases = [field.name]
        if isinstance(field.alias, six.string_types):
            aliases = aliases.append(field.alias)
        elif isinstance(field.alias, (list, tuple)):
            aliases.extend(field.alias)

        for alias in aliases:
            if alias in raw_data:
                return field.name, raw_data[alias]

        if not field.required:
            return field.name, field.default

        raise ValueError("The required field %r is missing." % field.name)

    def get_fields(self, fields, raw_data):
        """Get the information related to all the received fields
        if it is posible.
        """
        data = {}
        for field in fields:
            try:
                field_name, field_value = self._get_field(raw_data, field)
                data[field_name] = field_value
            except ValueError as reason:
                LOG.warning("Failed to process %r: %s", raw_data, reason)
                return
        return data

    @abc.abstractmethod
    def get_link(self, name):
        """Return all the available information regarding the received
        link name.

        :rtype: dict

        .. notes:
            The returned dictionary should contain al least the following
            keys: `name` and `mac_address`.
        """
        pass

    @abc.abstractmethod
    def get_links(self):
        """Return a list with the names of the available links.

        :rtype: list
        """
        pass

    @abc.abstractmethod
    def get_network(self, link, name):
        """Return all the available information regarding the required
        network.

        :param link: The name of the required link
        :type link:  str
        :param name: The name of the required network
        :type name: str

        .. notes:
            The returned dictionary should contain al least the following
            keys: `name`, `version`, `ip_address`, `netmask` and
            `dns_nameservers`.
        """
        pass

    @abc.abstractmethod
    def get_networks(self, link):
        """Returns all the network names bound by the required link.

        :param link: The name of the required link
        :type link:  str

        :rtype: list
        """
        pass


class NetworkConfig(object):

    """Process information related to the network."""

    def __init__(self, network_adapter):
        self._adapter = network_adapter
        self._networks = []

    def _get_networks(self):
        """Get all the information available on the current service."""
        for link_name in self._adapter.get_links():
            link = self._adapter.get_link(link_name)
            for network_name in self._adapter.get_networks(link):
                network = self._adapter.get_network(link_name, network_name)
                if link and network:
                    yield link, network

    def _digest(self):
        """Return a dictionary that contains all the information
        related to the networks available on the current metadata
        service.

        .. notes:
            The structure of the returned dictionary is the following:
                {
                    "interface0" : {
                        "name": "interface0",
                        "mac_address": "a0:36:9f:2c:e8:80",
                        "network": {
                            "ipv4": {
                                "id": "private-ipv4",
                                "type": "ipv4",
                                "ip_address": "10.184.0.244",
                                "netmask": "255.255.240.0",
                                "dns_nameservers": [
                                    "69.20.0.164",
                                    "69.20.0.196"
                                ],
                                # ...
                            },
                            "ipv6": {
                                "id": "private-ipv4",
                                "type": "ipv6",
                                "ip_address": "2001:cdba::3257:9652/24"
                                # ...
                            }
                        }
                    }
                }
        """
        raw_data = {}
        for link, network in self._get_networks():
            link_data = raw_data.setdefault(link[NAME], link)
            network_data = link_data.setdefault("network", {})
            network_data[network[VERSION]] = network

        return raw_data

    def get_network_details(self):
        """Return a list of `NetworkDetails` objects."""
        if not self._networks:
            raw_data = self._digest()
            for network in raw_data:
                ipv4 = network.get("network", {}).get(IPV4, {})
                ipv6 = network.get("network", {}).get(IPV6, {})

                self._networks.append(NetworkDetails(
                    name=network.get(NAME),
                    mac=network.get(MAC_ADDRESS),

                    address=ipv4.get(IP_ADDRESS, None),
                    netmask=ipv4.get(NETMASK, None),
                    gateway=ipv4.get(GATEWAY, None),
                    broadcast=network.get(BROADCAST, None),
                    dnsnameservers=ipv4.get(DNS, None),

                    address6=ipv6.get(IP_ADDRESS, None),
                    netmask6=ipv6.get(NETMASK, None),
                    gateway6=ipv6.get(GATEWAY, None),
                ))

        return self._networks


class NotExistingMetadataException(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class BaseMetadataService(object):
    _GZIP_MAGIC_NUMBER = b'\x1f\x8b'

    def __init__(self):
        self._cache = {}
        self._enable_retry = False

    def get_name(self):
        return self.__class__.__name__

    def load(self):
        self._cache = {}

    @abc.abstractmethod
    def _get_data(self, path):
        pass

    def _exec_with_retry(self, action):
        i = 0
        while True:
            try:
                return action()
            except NotExistingMetadataException:
                raise
            except Exception:
                if self._enable_retry and i < CONF.retry_count:
                    i += 1
                    time.sleep(CONF.retry_count_interval)
                else:
                    raise

    def _get_cache_data(self, path, decode=False):
        """Get meta data with caching and decoding support."""
        key = (path, decode)
        if key in self._cache:
            LOG.debug("Using cached copy of metadata: '%s'" % path)
            return self._cache[key]
        else:
            data = self._exec_with_retry(lambda: self._get_data(path))
            if decode:
                data = encoding.get_as_string(data)
            self._cache[key] = data
            return data

    def get_instance_id(self):
        pass

    def get_content(self, name):
        """Get raw content within a service."""

    def get_user_data(self):
        pass

    def get_decoded_user_data(self):
        """Get the decoded user data, if any

        The user data can be gzip-encoded, which means
        that every access to it should verify this fact,
        leading to code duplication.
        """
        user_data = self.get_user_data()
        if user_data and user_data[:2] == self._GZIP_MAGIC_NUMBER:
            bio = io.BytesIO(user_data)
            with gzip.GzipFile(fileobj=bio, mode='rb') as out:
                user_data = out.read()

        return user_data

    def get_host_name(self):
        pass

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
        pass

    def get_network_adapter(self):
        pass

    def get_network_details(self):
        """Return a list of `NetworkDetails` objects.

        These objects provide details regarding static
        network configuration, details which can be found
        in the namedtuple defined above.
        """
        adapter = self.get_network_adapter()
        if not adapter:
            return

        return adapter.get_network_details()

    def get_admin_password(self):
        pass

    @property
    def can_post_password(self):
        return False

    @property
    def is_password_set(self):
        return False

    def post_password(self, enc_password_b64):
        pass

    def get_client_auth_certs(self):
        pass

    def cleanup(self):
        pass

    @property
    def can_update_password(self):
        """The ability to update password of the metadata provider.

        If :meth:`~can_update_password` is True, plugins can check
        periodically (e.g. at every boot) if the password changed.

        :rtype: bool

        .. notes:
            The password will be updated only if the
            :meth:`~is_password_changed` returns True.
        """
        return False

    def is_password_changed(self):
        """Check if the metadata provider has a new password for this instance

        :rtype: bool

        .. notes:
            This method will be used only when :meth:`~can_update_password`
            is True.
        """
        return False

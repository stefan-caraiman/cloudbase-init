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

# pylint: disable=missing-docstring, bad-builtin


import os
import re

from oslo_log import log as oslo_logging
import six

from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import encoding


LOG = oslo_logging.getLogger(__name__)

CONTEXT_FILE = "context.sh"
INSTANCE_ID = "iid-dsopennebula"
# interface name default template
IF_FORMAT = "eth{iid}"

# metadata identifiers
HOST_NAME = ["SET_HOSTNAME", "HOSTNAME"]
USER_DATA = ["USER_DATA", "USERDATA"]
PUBLIC_KEY = ["SSH_PUBLIC_KEY", "SSH_KEY"]

MAC = ["ETH{iid}_MAC"]
ADDRESS = ["ETH{iid}_IP"]
NETMASK = ["ETH{iid}_MASK"]
GATEWAY = ["ETH{iid}_GATEWAY"]
DNSNS = ["ETH{iid}_DNS"]


class OpenNebulaNetworkAdapter(base.BaseNetworkAdapter):

    """Open Nebula Network Adapter."""

    def __init__(self, service):
        super(OpenNebulaNetworkAdapter, self).__init__(service)
        self._links = {}
        self._networks = {}

    @staticmethod
    def _calculate_netmask(address, gateway):
        """Try to determine a default netmask.

        It is a simple, frequent and dummy prediction
        based on the provided IP and gateway addresses.
        """
        address_chunks = address.split(".")
        gateway_chunks = gateway.split(".")
        netmask_chunks = []
        for achunk, gchunk in six.moves.zip(
                address_chunks, gateway_chunks):
            if achunk == gchunk:
                nchunk = "255"
            else:
                nchunk = "0"
            netmask_chunks.append(nchunk)
        return ".".join(netmask_chunks)

    def _get_cache_data(self, names, iid=None, decode=True):
        """Solves caching issues when working with multiple names
        (lists not hashable).

        This happens because the caching function used to store already
        computed results inside a dictionary and the keys were strings
        (and must be anything that is hashable under a dictionary, that's
        why the exception is thrown).
        """
        names = names[:]
        if iid is not None:
            for ind, value in enumerate(names):
                names[ind] = value.format(iid=iid)

        for name in names:
            try:
                return self._service._get_cache_data(name, decode=decode)
            except base.NotExistingMetadataException:
                pass

        msg = "None of {} metadata was found".format(", ".join(names))
        LOG.debug(msg)
        raise base.NotExistingMetadataException(msg)

    def _digest_network(self, link, name):
        """Try to find/predict and compute network configuration.

        :raise: NotExistingMetadataException
        """
        networks = self._networks.setdefault(link[base.NAME], [])

        address = self._get_cache_data(ADDRESS, iid=name)
        try:
            netmask = self._get_cache_data(NETMASK, iid=name)
        except base.NotExistingMetadataException:
            gateway = self._get_cache_data(GATEWAY, iid=name)
            if not gateway:
                LOG.debug("Incomplete NIC details for %s",
                          IF_FORMAT.format(iid=name))
                return
            netmask = self._calculate_netmask(address, gateway)

        network = self._digest_interface(address, netmask)
        network[base.DNS] = self._get_cache_data(DNSNS, iid=name).split(" ")
        network[base.GATEWAY] = gateway
        networks.append(network)

    def _digest(self):
        """Digest the received network information."""
        iid = 0
        while True:
            mac_address = self._service.content.get(MAC[0].format(iid=iid))
            name = IF_FORMAT.format(iid=iid)
            if not mac_address:
                break

            link = self._links.setdefault(name, {})
            link[base.MAC_ADDRESS] = mac_address
            link[base.NAME] = name
            self._digest_network(link, iid)
            iid += 1

    def get_link(self, name):
        """Return all the available information regarding the received
        link name.

        :rtype: dict
        :raises: NotExistingMetadataException

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


class OpenNebulaService(base.BaseMetadataService):

    """Service handling ONE.

    Service able to expose OpenNebula metadata
    using information found in a mounted ISO file.
    """

    def __init__(self):
        super(OpenNebulaService, self).__init__()
        self._context_path = None
        self._raw_content = None
        self._dict_content = {}

    @property
    def content(self):
        """Expose the information from the config file."""
        return self._dict_content

    @staticmethod
    def _parse_shell_variables(content):
        """Returns a dictionary with variables and their values.

        This is a dummy approach, because it works only with simple literals.
        """
        # preprocess the content
        lines = []
        for line in content.splitlines():
            if not line or line.startswith(b"#"):
                continue
            lines.append(line)
        # for cleaner pattern matching
        lines.append(b"__REGEX_DUMMY__='__regex_dummy__'")
        sep = b"\r\n" if b"\r\n" in content else b"\n"
        new_content = sep.join(lines)
        # get pairs
        pairs = {}
        pattern = (br"(?P<key>\w+)=(['\"](?P<str_value>[\s\S]+?)['\"]|"
                   br"(?P<int_value>\d+))(?=\s+\w+=)")
        for match in re.finditer(pattern, new_content):
            key = encoding.get_as_string(match.group("key"))
            pairs[key] = (match.group("str_value") or
                          int(match.group("int_value")))
        return pairs

    def _parse_context(self):
        # Get the content if it's not already retrieved and parse it.
        if not self._raw_content:
            if not self._context_path:
                msg = "No metadata file path found"
                LOG.debug(msg)
                raise base.NotExistingMetadataException(msg)
            with open(self._context_path, "rb") as fin:
                self._raw_content = fin.read()
            # fill the dict with values
            vardict = OpenNebulaService._parse_shell_variables(
                self._raw_content
            )
            self._dict_content.update(vardict)

    def _get_data(self, name):
        # Return the requested field's value or raise an error if not found.
        if name not in self._dict_content:
            msg = "Metadata {} not found".format(name)
            LOG.debug(msg)
            raise base.NotExistingMetadataException(msg)
        return self._dict_content[name]

    def load(self):
        """Loads the context metadata from the ISO provided by OpenNebula."""
        super(OpenNebulaService, self).__init__()
        LOG.debug("Searching for a drive containing OpenNebula context data")
        osutils = osutils_factory.get_os_utils()
        for drive in osutils.get_cdrom_drives():
            label = osutils.get_volume_label(drive)
            file_path = os.path.join(drive, CONTEXT_FILE)
            if os.path.isfile(file_path):
                LOG.info("Found drive %(label)s (%(drive)s) with "
                         "OpenNebula metadata file %(file_path)s",
                         {"label": label, "drive": drive,
                          "file_path": file_path})
                self._context_path = file_path
                # Load and parse the file on-site.
                self._parse_context()
                return True
        LOG.error("No drive or context file found")
        return False

    def get_instance_id(self):
        # return a dummy default value
        return INSTANCE_ID

    def get_host_name(self):
        return self._get_cache_data(HOST_NAME, decode=True)

    def get_user_data(self):
        return self._get_cache_data(USER_DATA)

    def get_public_keys(self):
        return self._get_cache_data(PUBLIC_KEY, decode=True).splitlines()

    def get_network_adapter(self):
        return OpenNebulaNetworkAdapter(self)

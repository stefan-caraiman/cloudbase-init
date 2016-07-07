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

"""Metadata Service for Packet."""


import json

from oslo_log import log as oslo_logging
import requests

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class PacketService(base.BaseHTTPMetadataService):

    """Metadata Service for Packet.

    Packet is a NYC-based infrastructure startup, focused on reinventing
    how SaaS/PaaS companies go global with premium bare metal and container
    hosting.
    """

    def __init__(self):
        super(PacketService, self).__init__(
            base_url=CONF.packet.metadata_url,
            https_allow_insecure=CONF.packet.https_allow_insecure,
            https_ca_bundle=CONF.packet.https_ca_bundle)

        self._raw_data = {}
        self._enable_retry = True

    @property
    def can_post_password(self):
        """The Packet metadata service supports posting the password."""
        return True

    def load(self):
        """Load all the available information from the metadata service."""
        super(PacketService, self).load()
        for path in ("metadata", "userdata"):
            url = requests.compat.urljoin(self._base_url, path)
            try:
                action = lambda: self._http_request(url)
                self._raw_data[path] = self._exec_with_retry(action)
            except requests.RequestException as exc:
                LOG.debug("%(data)s not found at URL %(url)r: %(reason)r",
                          {"data": path.title(), "url": url, "reason": exc})

        try:
            self._raw_data["metadata"] = json.loads(encoding.get_as_string(
                self._raw_data["metadata"]))
        except (KeyError, ValueError) as exc:
            LOG.warning("Failed to load metadata: %s", exc)
            return False

        return True

    def get_instance_id(self):
        """Get the identifier for the current instance.

        The instance identifier provides an unique way to address an
        instance into the current metadata provider.
        """
        try:
            identifier = self._raw_data["metadata"]["id"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the identifier for the current instance. ")
        else:
            return encoding.get_as_string(identifier)

    def get_host_name(self):
        """Get the hostname for the current instance."""
        try:
            hostname = self._raw_data["metadata"]["hostname"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the hostname for the current instance. ")
        else:
            return encoding.get_as_string(hostname)

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
        public_keys = []
        try:
            public_keys.extend(self._raw_data["metadata"]["ssh_keys"])
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the public keys for the current instance.")

        public_keys = [encoding.get_as_string(key) for key in public_keys]
        return public_keys

    def get_encryption_public_key(self):
        try:
            endpoint = self._raw_data["metadata"]["phone_home_url"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the phone_home_url endpoint "
                "for the current instance.")

        url = requests.compat.urljoin('{}/'.format(endpoint), "key")
        try:
            action = lambda: self._http_request(url)
            raw_data = self._exec_with_retry(action)
        except requests.RequestException as exc:
            LOG.debug("Data not found at URL %(url)r: %(reason)r",
                      {"url": url, "reason": exc})
            return False
        return [encoding.get_as_string(raw_data)]

    def get_user_data(self):
        """Get the available user data for the current instance."""
        return self._raw_data["userdata"]

    def post_password(self, enc_password_b64):
        """Send the new password to the Packet metadata service."""
        try:
            endpoint = self._raw_data["metadata"]["phone_home_url"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the phone_home_url endpoint "
                "for the current instance.")

        payload = {'password': enc_password_b64.decode()}
        action = lambda: self._http_request(url=endpoint, data=payload,
                                            method="POST")

        try:
            self._exec_with_retry(action)
        except requests.HTTPError as exc:
            LOG.error("Failed to post password to the metadata service: %s",
                      exc)
            raise

        return True

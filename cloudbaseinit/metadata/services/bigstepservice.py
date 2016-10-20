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

"""Metadata Service for Bigstep."""

import json

from oslo_log import log as oslo_logging
import requests
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class BigstepService(base.BaseHTTPMetadataService):

    """Metadata Service for Bigstep."""

    def __init__(self):
        # Note: The base url used by the current metadata service will be
        # updated later by the `load` method.
        super(BigstepService, self).__init__(
            base_url=None,
            https_allow_insecure=CONF.bigstep.https_allow_insecure,
            https_ca_bundle=CONF.bigstep.https_ca_bundle)
        self._raw_data = {}
        self._enable_retry = True

    @property
    def can_update_password(self):
        """The Bigstep metadata service supports updating the password."""
        return True

    @property
    def can_post_password(self):
        """The Bigstep metadata service supports posting the password."""
        return True

    def _set_base_url(self):
        """Set the metadata base URL for the current instance."""
        try:
            with open(CONF.bigstep.metadata_path, "r") as file_handle:
                url = file_handle.read()
                self._base_url = url.strip()
        except IOError as exc:
            LOG.debug("Failed to get the metadata URL: %s", exc)
            raise

    def load(self):
        """Load all the available information from the metadata service."""
        super(BigstepService, self).load()
        self._exec_with_retry(self._set_base_url)

        try:
            action = lambda: self._http_request(self._base_url)
            raw_data = self._exec_with_retry(action)
        except requests.RequestException as exc:
            LOG.debug("Metadata not found at URL %(url)r: %(reason)r",
                      {"url": self._base_url, "reason": exc})
            return False

        try:
            self._raw_data = json.loads(encoding.get_as_string(raw_data))
        except ValueError as exc:
            LOG.warning("Failed to load metadata: %s", exc)
            return False

        return True

    def get_instance_id(self):
        """Get the identifier for the current instance."""
        try:
            identifier = self._raw_data["metadata"]["instance-id"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the identifier for the current instance. ")
        else:
            # Note(alexcoman): The instance-id is an integer
            return str(identifier)

    def get_host_name(self):
        """Get the hostname for the current instance."""
        try:
            hostname = self._raw_data["metadata"]["hostname"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the hostname for the current instance. ")
        else:
            return encoding.get_as_string(hostname)

    def get_admin_password(self):
        """Get the plain-text password for the admin account."""
        password = None
        try:
            password = self._raw_data["metadata"]["password-plaintext-unsafe"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the password for admin account.")

        return encoding.get_as_string(password)

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
        public_keys = []
        try:
            public_keys.extend(self._raw_data["metadata"]["public-keys"])
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the public keys for the current instance.")

        public_keys = [encoding.get_as_string(key) for key in public_keys]
        return public_keys

    def get_user_data(self):
        """Get the available user data for the current instance."""
        try:
            userdata = self._raw_data["metadata"]["userdata"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the userdata for the current instance.")

        if isinstance(userdata, six.text_type):
            return userdata.encode()
        else:
            return userdata

    def is_password_changed(self):
        """Check if a new password exists for the Administrator user."""
        password_changed = False
        try:
            password_changed = self._raw_data["metadata"]["password-changed"]
        except (KeyError, TypeError):
            LOG.debug("No information available regarding the status "
                      "of the password.")
        return password_changed

    def post_password(self, enc_password_b64):
        """Send the new password to the Bigstep metadata service."""

        # TODO(alexcoman): Add support for posting password for
        # additional users.
        try:
            endpoint = self._raw_data["metadata"]["user_password_set_url"]
        except (KeyError, TypeError):
            raise base.NotExistingMetadataException(
                "Failed to get the endpoint for posting password.")

        payload = {"username": CONF.username,
                   "password": enc_password_b64.decode()}
        action = lambda: self._http_request(url=endpoint, data=payload)
        try:
            self._exec_with_retry(action)
        except requests.HTTPError as exc:
            LOG.error("Failed to post the password to the metadata "
                      "service: %s", exc)
            raise

        return True

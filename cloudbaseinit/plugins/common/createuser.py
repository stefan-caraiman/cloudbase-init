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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants
from cloudbaseinit.plugins.common import usermanagement


CONF = cloudbaseinit_conf.CONF


class UserManager(usermanagement.BaseUserManager):

    def _get_username(self, data):
        """Get the username from the config file.

        Gets the username and also sets the username in the
        shared data.
        """
        user_name = CONF.username
        data[constants.SHARED_DATA_USERNAME] = user_name
        return user_name

    def _get_groups(self, data):
        """Get the group names from the config file."""
        return CONF.groups

    def _get_expire_status(self, data):
        """Get the password expiration status."""
        return False

    def _get_user_activity(self, data):
        """Get the user activity type for whether to create a logon session."""
        return False

    def _get_password(self, data):
        """Get a random password and sets in the shared data."""
        # Generate a temporary random password to be replaced
        # by SetUserPasswordPlugin (starting from Grizzly)
        osutils = osutils_factory.get_os_utils()
        maximum_length = osutils.get_maximum_password_length()
        password = osutils.generate_random_password(maximum_length)
        # TODO(alexpilotti): encrypt with DPAPI
        data[constants.SHARED_DATA_PASSWORD] = password
        return password


class BaseCreateUserPlugin(base.BasePlugin):
    """This is the base class for creating or modifying an user."""

    @abc.abstractmethod
    def _handle_user(self, service, shared_data):
        pass

    def execute(self, service, shared_data):
        self._handle_user(service, shared_data)
        return base.PLUGIN_EXECUTION_DONE, False

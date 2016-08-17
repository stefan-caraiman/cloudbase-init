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

import abc
import os

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory

LOG = oslo_logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseUserSSHPublicKeysManager(object):
    """This is the base class for managing ssh-keys.

    The purpose of the manager is to offer a base that only needs
    to have implemented a different data handler across plugins
    and keep any of the ssk-key handling logic in the manager, since
    it's the same across any other plugin.
    """

    def __init__(self):
        self._username = None
        self._ssh_keys = None

    @abc.abstractmethod
    def _get_username(self, data=None):
        """Gets the username for which the ssh-keys will be set.

        Gets the username in a manner specific to the plugin
        that needs to be implemented into.
        """
        pass

    @abc.abstractmethod
    def _get_ssh_public_keys(self, data=None):
        """Gets the ssh-keys that will be set on the user."""
        pass

    def load(self, data):
        """Loads all the data required for handling the ssh-keys management."""
        self._username = self._get_username(data)
        self._ssh_keys = self._get_ssh_public_keys(data)

    def manage_user_ssh_keys(self):
        """Manages the setting of the user ssh-keys."""
        if not self._ssh_keys:
            LOG.debug('Public keys not found!')
            return
        osutils = osutils_factory.get_os_utils()
        user_home = osutils.get_user_home(self._username)
        if not user_home:
            raise exception.CloudbaseInitException("User profile not found!")

        LOG.debug("User home: %s" % user_home)
        user_ssh_dir = os.path.join(user_home, '.ssh')
        if not os.path.exists(user_ssh_dir):
            os.makedirs(user_ssh_dir)
        authorized_keys_path = os.path.join(user_ssh_dir, "authorized_keys")
        LOG.info("Writing SSH public keys in: %s" % authorized_keys_path)
        with open(authorized_keys_path, 'w') as file_handler:
            for public_key in self._ssh_keys:
                # All public keys are space-stripped.
                file_handler.write(public_key + "\n")


@six.add_metaclass(abc.ABCMeta)
class BaseUserManager(object):
    """This is the base class for managing user related actions.

    The purpose of the manager is to offer a base that only needs
    to have implemented a different data handler across plugins
    and keep any of the user handling logic in the manager, since
    it will follow the same flow across any other plugin.
    """

    def __init__(self):
        self._username = None
        self._password = None
        self._expire_status = False
        self._groups = []
        self._user_inactivity = False

    @abc.abstractmethod
    def _get_username(self, data):
        """An existing user or one which will be added."""
        pass

    @abc.abstractmethod
    def _get_password(self, data):
        """The password for the found user."""
        pass

    @abc.abstractmethod
    def _get_groups(self, data):
        """The groups to which the user will be added to.

        :rtype:: list
        .. note :: The user will only be added to existing groups,
                   any given group names, that do not exist,
                   will be skipped.
        """
        pass

    @abc.abstractmethod
    def _get_expire_status(self, data):
        """Value representing the expiration date of the user's password.

        :rtype: bool
        """
        pass

    @abc.abstractmethod
    def _get_user_activity(self, data):
        """Value representing whether the user need's a post creation.

        :rtype:: bool
        """
        pass

    def load(self, data):
        """Loads all the data required for handling user creation."""
        self._username = self._get_username(data)
        self._password = self._get_password(data)
        self._expire_status = self._get_expire_status(data)
        self._groups = self._get_groups(data)
        self._user_inactivity = self._get_user_activity(data)

    def create_user(self, osutils):
        """Calls the OS specific method for creating users.

        Creates a new username, using the loaded *username*.
        """
        osutils.create_user(self._username, self._password,
                            self._expire_status)

    def post_create_user(self, osutils):
        """Manage the post creation for the user if it's required by the OS.

        This will be called after the user is created or the user
        password is updated.
        """
        pass

    def add_user_to_groups(self, osutils):
        """Adds the loaded user to the found groups, if they exist."""
        for group_name in self._groups:
            try:
                osutils.add_user_to_local_group(self._username, group_name)
            except exception.CloudbaseInitException as exc:
                LOG.exception('Cannot add user to "%(group)s": %(reason)s' %
                              {"group": group_name, "reason": exc})

    def handle_user_creation(self, osutils):
        """Used for creating or modifying the loaded user."""
        if osutils.user_exists(self._username):
            LOG.info('Setting password for existing user "%s"', self._username)
            osutils.set_user_password(self._username, self._password,
                                      self._expire_status)
        else:
            LOG.info('Creating user "%s" and setting password', self._username)
            self.create_user(osutils)

        if not self._user_inactivity:
            LOG.info('Managing user post creation.')
            self.post_create_user(osutils)

    def manage_user_information(self):
        """Manages the loaded user information."""
        osutils = osutils_factory.get_os_utils()
        self.handle_user_creation(osutils)
        self.add_user_to_groups(osutils)

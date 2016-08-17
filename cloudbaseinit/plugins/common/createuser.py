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

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import constants

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseCreateUserPlugin(base.BasePlugin):
    """This is a base class for creating or modifying an user."""

    @abc.abstractmethod
    def create_user(self, username, password, password_expires, osutils):
        """Create a new username, with the given *username*.

        This will be called by :meth:`~execute`, whenever
        a new user must be created.
        """

    @abc.abstractmethod
    def post_create_user(self, user_name, password, osutils):
        """Executes post user creation logic.

        This will be called after by :meth:`~execute`, after
        the user is created or the user password is updated.
        """

    @staticmethod
    def _get_password(osutils):
        # Generate a temporary random password to be replaced
        # by SetUserPasswordPlugin (starting from Grizzly)
        maximum_length = osutils.get_maximum_password_length()
        return osutils.generate_random_password(maximum_length)

    def _manage_user_handling(self, data, osutils, metadata_service=True):
        if metadata_service:
            user_name = CONF.username
            password = self._get_password(osutils)
            groups = CONF.groups
            inactive = expires = False
            shared_data = data
            shared_data[constants.SHARED_DATA_USERNAME] = user_name
        else:
            user_name = data['name']
            password = data['passwd']
            expires = data['expiredate']
            inactive = data['inactive']
            user_groups = data['groups']
            primary_group = data['primary-group']
            groups = primary_group + user_groups
        if osutils.user_exists(user_name):
            LOG.info('Setting password for existing user "%s"', user_name)
            osutils.set_user_password(user_name, password,
                                      password_expires=expires)
        else:
            LOG.info('Creating user "%s" and setting password', user_name)
            self.create_user(user_name, password, expires, osutils)
            if metadata_service:
                # TODO(alexpilotti): encrypt with DPAPI
                shared_data[constants.SHARED_DATA_PASSWORD] = password
        if not inactive:
            self.post_create_user(user_name, password, osutils)

        for group_name in groups:
            try:
                osutils.add_user_to_local_group(user_name, group_name)
            except Exception:
                LOG.exception('Cannot add user to group "%s"', group_name)

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()
        self._manage_user_handling(shared_data, osutils)
        return base.PLUGIN_EXECUTION_DONE, False

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

import six

from datetime import datetime
from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.osutils import factory
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)
from cloudbaseinit.plugins.common import usermanagement


LOG = oslo_logging.getLogger(__name__)


class UserManager(usermanagement.BaseUserManager):

    def _get_groups(self, data):
        """Retuns all the group names that the user should be added to.

        :rtype: list
        """
        groups = data.get('groups', None)
        primary_group = data.get('primary-group', None)
        user_groups = []
        if isinstance(groups, six.string_types):
                user_groups.extend(groups.split(', '))
        elif isinstance(groups, (list, tuple)):
                user_groups.extend(groups)
        if isinstance(primary_group, six.string_types):
                user_groups.extend(primary_group.split(', '))
        elif isinstance(primary_group, (list, tuple)):
                user_groups.extend(primary_group)
        return user_groups

    def _get_username(self, data):
        return data.get('name', None)

    def _get_password(self, data):
        osutils = factory.get_os_utils()
        password = data.get('passwd', None)
        max_size = osutils.get_maximum_password_length()
        if password is not None and len(password) > max_size:
            password = password[:max_size]
            LOG.warning("New password has been sliced to %s characters",
                        max_size)
        return password

    def _get_expire_status(self, data):
        expiredate = data.get('expiredate', None)
        if not expiredate:
            return False
        if isinstance(expiredate, six.string_types):
            year, month, day = map(int, expiredate.split('-'))
            expiredate = datetime(year=year, month=month, day=day).date()
        current_date = datetime.now().date()
        return False if expiredate <= current_date else True

    def _get_user_activity(self, data):
        activity = data.get('inactive', None)
        if not activity:
            return False
        return True if activity.lower() == "true" else False

    def post_create_user(self, osutils):
        self._create_user_logon(self._username, self._password,
                                self._expire_status, osutils)

    @staticmethod
    def _create_user_logon(user_name, password, password_expires, osutils):
        try:
            # Create a user profile in order for other plugins
            # to access the user home, etc
            token = osutils.create_user_logon_session(user_name,
                                                      password,
                                                      password_expires)
            osutils.close_user_logon_session(token)
        except Exception:
            LOG.exception('Cannot create a user logon session for user: "%s"',
                          user_name)


class SSHKeysManager(usermanagement.BaseUserSSHPublicKeysManager):

    def _get_username(self, data):
        return data.get('name', None)

    def _get_ssh_public_keys(self, data):
        return data.get('ssh-authorized-keys', None)


class UsersPlugin(base.BaseCloudConfigPlugin):
    """Creates a new user for the underlying platform."""

    def process(self, data):
        """Process the given data received from the cloud-config userdata.

        It knows to process only lists and dicts.
        """
        if not isinstance(data, (list, dict)):
            raise exception.CloudbaseInitException(
                "Can't process the type of data %r" % type(data))

        for item in data:
            if not isinstance(item, dict):
                continue
            if not {'name'}.issubset(set(item)):
                LOG.warning("Missing required keys from file information %s",
                            item)
                return
            user_manager, ssh_keys_manager = UserManager(), SSHKeysManager()
            for manager in (user_manager, ssh_keys_manager):
                manager.load(item)
            user_manager.manage_user_information()
            ssh_keys_manager.manage_user_ssh_keys()

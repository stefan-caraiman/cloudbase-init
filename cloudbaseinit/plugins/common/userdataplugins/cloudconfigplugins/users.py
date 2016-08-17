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
from cloudbaseinit.plugins.windows import createuser
from cloudbaseinit.utils import sshkeys

LOG = oslo_logging.getLogger(__name__)


class UsersPlugin(base.BaseCloudConfigPlugin):
    """Creates a new user for the underlying platform."""

    def _is_expired(self, expiredate):
        """Checks if the provided expiredate is expired or not.

        :rtype: bool
        """
        if isinstance(expiredate, six.string_types):
            year, month, day = map(int, expiredate.split('-'))
            expiredate = datetime(year=year, month=month, day=day).date()
        current_date = datetime.now().date()
        return False if expiredate <= current_date else True

    def _inactive_user_type(self, content):
        """Checks the activity type of the user

        :rtype: bool
        """
        return True if content.lower() == "true" else False

    def _get_groups(self, group):
        """Retuns all the group names that the user should be added to.

        :rtype: list
        """
        user_groups = []
        if isinstance(group, six.string_types):
                user_groups.extend(group.split(', '))
        elif isinstance(group, (list, tuple)):
                user_groups.extend(group)
        return user_groups

    def _slice_password(self, password, osutils):
        """Slices the password if its longer than the maximum size.

        :rtype: str
        """
        if password is None:
            return ''
        max_size = osutils.get_maximum_password_length()
        if len(password) > max_size:
            password = password[:max_size]
            LOG.debug("New password has been sliced to %s characters",
                        max_size)
        return password

    def _set_ssh_keys(self, public_keys, username, osutils):
        """Sets the ssh keys for the underlying user."""
        if not public_keys:
            return
            LOG.info("No ssh keys have been found.")
        sshkeys.set_ssh_keys(osutils, public_keys, username)

    def _process_item(self, item, osutils):
        if not {'name'}.issubset(set(item)):
            LOG.warning("Missing required keys from file information %s",
                        item)
            return
        required_fields = ('name passwd expiredate inactive '
                           'groups primary-group '
                           'ssh-authorized-keys').split()
        user_args = {item_name: item.get(item_name, None) for item_name in required_fields}
        user_args['passwd'] = self._slice_password(user_args['passwd'], osutils)
        user_args['expiredate'] = (False if user_args['expiredate'] is None else
                                   self._is_expired(user_args['expiredate']))
        user_args['inactive'] = (False if user_args['inactive'] is None
                         else self._inactive_user_type(user_args['inactive']))
        user_args['groups'] = self._get_groups(user_args['groups'])
        user_args['primary-group'] = self._get_groups(user_args['primary-group'])
        create_user = createuser.CreateUserPlugin()
        create_user.process_user_data(user_args, osutils)
        self._set_ssh_keys(user_args['ssh-authorized-keys'],
                           user_args['name'], osutils)

    def process(self, data):
        """Process the given data received from the cloud-config userdata.

        It knows to process only lists and dicts.
        """
        osutils = factory.get_os_utils()
        if not isinstance(data, (list, dict)):
            raise exception.CloudbaseInitException(
                "Can't process the type of data %r" % type(data))

        for item in data:
            if not isinstance(item, dict):
                continue
            self._process_item(item, osutils)

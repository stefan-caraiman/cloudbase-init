# Copyright 2015 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging

from cloudbaseinit.plugins.common import createuser


LOG = oslo_logging.getLogger(__name__)


class CreateUserManager(createuser.UserManager):

    @staticmethod
    def _create_user_logon(user_name, password, osutils):
        try:
            # Create an user profile in order for other plugins
            # to access the user home, etc
            token = osutils.create_user_logon_session(user_name,
                                                      password,
                                                      True)
            osutils.close_user_logon_session(token)
        except Exception as exc:
            LOG.exception('Cannot create a user logon session for %(user)s'
                          ': %(reason)s' % {"user": user_name, "reason": exc})

    def post_create_user(self, osutils):
        self._create_user_logon(self._username, self._password, osutils)


class CreateUserPlugin(createuser.BaseCreateUserPlugin):

    def __init__(self):
        super(CreateUserPlugin, self).__init__()
        self._usermanager = CreateUserManager()

    def _handle_user(self, service, shared_data):
        """Handles the user creation.

        Handles the user creation/updating by using a manager object.
        """
        self._usermanager.load(shared_data)
        self._usermanager.manage_user_information()

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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import usermanagement


CONF = cloudbaseinit_conf.CONF


class SSHKeysManager(usermanagement.BaseUserSSHPublicKeysManager):

    def _get_username(self, data):
        return CONF.username

    def _get_ssh_public_keys(self, data):
        return data.get_public_keys()


class SetUserSSHPublicKeysPlugin(base.BasePlugin):

    def execute(self, service, shared_data):
        keysmanager = SSHKeysManager()
        keysmanager.load(service)
        keysmanager.manage_user_ssh_keys()
        return base.PLUGIN_EXECUTION_DONE, False

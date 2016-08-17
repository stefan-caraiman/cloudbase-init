# Copyright 2013 Cloudbase Solutions Srl
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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import sshpublickeys
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class TestSSHKeysManager(unittest.TestCase):

    def setUp(self):
        self.keysmanager = sshpublickeys.SSHKeysManager()

    @testutils.ConfPatcher('username', "fake_username")
    def test_get_username(self):
        data = "fake_data"
        result = self.keysmanager._get_username(data)
        self.assertEqual(result, CONF.username)

    def test_get_ssh_public_keys(self):
        mock_data = mock.Mock()
        mock_data.get_public_keys.return_value = "fake_keys"
        result = self.keysmanager._get_ssh_public_keys(mock_data)
        self.assertEqual(result, "fake_keys")
        self.assertEqual(mock_data.get_public_keys.call_count, 1)


class SetUserSSHPublicKeysPluginTests(unittest.TestCase):

    def setUp(self):
        self._set_ssh_keys_plugin = sshpublickeys.SetUserSSHPublicKeysPlugin()

    @testutils.ConfPatcher('username', 'fake_username')
    @mock.patch('cloudbaseinit.plugins.common.sshpublickeys.'
                'SSHKeysManager.load')
    @mock.patch('cloudbaseinit.plugins.common.sshpublickeys.'
                'SSHKeysManager.manage_user_ssh_keys')
    def test_execute(self, mock_manage_user_ssh, mock_load):
        fake_shared_data = "fake_shared_data"
        fake_service = "fake_service"
        response = self._set_ssh_keys_plugin.execute(fake_service,
                                                     fake_shared_data)
        self.assertEqual(mock_manage_user_ssh.call_count, 1)
        mock_load.assert_called_once_with(fake_service)
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

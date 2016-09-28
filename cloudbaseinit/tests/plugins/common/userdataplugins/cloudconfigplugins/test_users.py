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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo_config import cfg

from cloudbaseinit import exception
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    users
)
from cloudbaseinit.tests import testutils

CONF = cfg.CONF
MODPATH = ("cloudbaseinit.plugins.common.userdataplugins."
           "cloudconfigplugins.users")


class UserManagerTests(unittest.TestCase):

    def setUp(self):
        self.user_manager = users.UserManager()

    def test__get_groups(self):
        fake_data = {'groups': ['fake1'], 'primary-group': ('fake2',)}
        res = self.user_manager._get_groups(fake_data)
        self.assertEqual(res, ['fake1', 'fake2'])

    def test__get_groups_string(self):
        fake_data = {'groups': 'fake1, fake2', 'primary-group': 'fake3'}
        res = self.user_manager._get_groups(fake_data)
        self.assertEqual(res, ['fake1', 'fake2', 'fake3'])

    def test__get_username(self):
        name = 'fake_username'
        fake_data = {'name': name}
        res = self.user_manager._get_username(fake_data)
        self.assertEqual(res, name)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test__get_password(self, mock_get_os_utils):
        mock_utils = mock.Mock()
        mock_utils.get_maximum_password_length.return_value = 20
        mock_get_os_utils.return_value = mock_utils
        fake_data = {'passwd': 'fake_pass'}
        res = self.user_manager._get_password(fake_data)
        self.assertEqual(res, 'fake_pass')
        mock_utils.get_maximum_password_length.return_value = 4
        res = self.user_manager._get_password(fake_data)
        self.assertEqual(res, 'fake')

    def test__get_expire_status(self):
        fake_data = {'expiredate': '1900-1-1'}
        self.assertFalse(self.user_manager._get_expire_status({}))
        self.assertFalse(self.user_manager._get_expire_status(fake_data))
        fake_data['expiredate'] = '2100-1-1'
        self.assertTrue(self.user_manager._get_expire_status(fake_data))

    def test__get_user_activity(self):
        self.assertFalse(self.user_manager._get_user_activity({}))
        fake_data = {'inactive': 'TruE'}
        self.assertTrue(self.user_manager._get_user_activity(fake_data))


class UsersPluginTests(unittest.TestCase):

    def setUp(self):
        self.user_plugin = users.UsersPlugin()

    def test_process_exception(self):
        fake_data = "some-string"
        self.assertRaises(exception.CloudbaseInitException,
                          self.user_plugin.process, fake_data)

    def test_process_not_valid(self):
        fake_data = [{'passwd': 'fake_pass'}]
        with testutils.LogSnatcher(MODPATH) as snatcher:
            res = self.user_plugin.process(fake_data)
        expected_logging = [
            "Missing required keys from file information %s" % fake_data[0]]
        self.assertFalse(res)
        self.assertEqual(snatcher.output, expected_logging)

    @mock.patch(MODPATH + '.SSHKeysManager.manage_user_ssh_keys')
    @mock.patch(MODPATH + '.UserManager.manage_user_information')
    @mock.patch(MODPATH + '.UserManager.load')
    def test_process_valid(self, mock_load, mock_manage_user,
                           mock_ssh_keys):
        fake_data = [{'passwd': 'fake_pass', 'name': 'fake_name'}]
        self.user_plugin.process(fake_data)
        mock_load.assert_called_once_with(fake_data[0])
        self.assertEqual(mock_manage_user.call_count, 1)
        self.assertEqual(mock_ssh_keys.call_count, 1)

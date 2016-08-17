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

import datetime
import string
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


class CreateUserPluginTests(unittest.TestCase):

    def setUp(self):
        self.user_plugin = users.UsersPlugin()

    def test_convert_expiredate(self):
        expired_date = datetime.date(2000, 1, 1)
        nonexpired_date = '2100-12-12'
        self.assertFalse(self.user_plugin._is_expired(expired_date))
        self.assertTrue(self.user_plugin._is_expired(nonexpired_date))

    def test_inactive_user_type(self):
        false_type = "False"
        true_type = "TRUE"
        self.assertTrue(self.user_plugin._inactive_user_type(true_type))
        self.assertFalse(self.user_plugin._inactive_user_type(false_type))

    def test_get_groups(self):
        fake_primary_group = 'Administrators'
        fake_groups = 'Guests, Others'
        expected_group = fake_groups.split(', ')
        expected_group.append(fake_primary_group)
        res = self.user_plugin._get_groups(fake_groups, fake_primary_group)
        self.assertEqual(res, expected_group)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_add_users_to_group_fail(self, mock_osutils):
        mock_username = "fake_user"
        mock_group = "fake_group"
        exc = exception.CloudbaseInitException
        mock_osutils.add_user_to_local_group.side_effect = exc
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            self.user_plugin._add_users_to_group(mock_username,
                                                 mock_group,
                                                 mock_osutils)
        expected_logging = ('Cannot add user to group "%s"'
                            % mock_group)
        self.assertEqual(snatcher.output[0], expected_logging)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_add_users_to_group(self, mock_osutils):
        mock_username = "fake_user"
        mock_group = "fake_group"
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            self.user_plugin._add_users_to_group(mock_username,
                                                 mock_group,
                                                 mock_osutils)
        expected_logging = [
            "Successfully added {} to {}.".format(mock_username, mock_group)
        ]
        self.assertEqual(snatcher.output, expected_logging)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_slice_password(self, mock_osutils):
        mock_passwd = 'fake'
        mock_osutils.get_maximum_password_length.return_value = 20
        res = self.user_plugin._slice_password(mock_passwd, mock_osutils)
        self.assertEqual(res, mock_passwd)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_slice_password_sliced(self, mock_osutils):
        mock_passwd = string.ascii_uppercase
        max_size = 20
        mock_osutils.get_maximum_password_length.return_value = max_size
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            res = self.user_plugin._slice_password(mock_passwd, mock_osutils)
        expected_logging = [
            "New password has been sliced to %s characters" % max_size
        ]
        self.assertEqual(res, mock_passwd[:max_size])
        self.assertEqual(snatcher.output, expected_logging)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_set_ssh_keys_not_found(self, mock_osutils):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users'):
            res = self.user_plugin._set_ssh_keys(None, None, mock_osutils)
        self.assertIsNone(res)
        mock_osutils.get_user_home.return_value = None
        self.assertRaises(exception.CloudbaseInitException,
                          self.user_plugin._set_ssh_keys, 'fake_key',
                          'fake_user', mock_osutils)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_manage_user_data(self, mock_osutils):
        mock_osutils.user_exists.return_value = False
        mock_username = 'fake_user'
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            self.user_plugin._manage_user_data(mock_username, 'pass', True,
                                               False, mock_osutils)
        expected_logging = [
            "Creating user '%s'" % mock_username,
            "Creating user logon for %s" % mock_username
        ]
        mock_osutils.user_exists.assert_called_once()
        mock_osutils.create_user.assert_called_once_with(mock_username,
                                                         "pass", True)
        self.assertEqual(snatcher.output, expected_logging)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_missing_item(self, mock_osutils):
        fake_item = {"fake_key": "fake_val"}
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            res = self.user_plugin._process_item(fake_item, mock_osutils)
        expected_output = ["Missing required keys from file "
                           "information %s" % fake_item]
        self.assertIsNone(res)
        self.assertEqual(snatcher.output, expected_output)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_process_item(self, mock_osutils):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users') as snatcher:
            user_name = 'fake_user'
            self.user_plugin._process_item({'name': user_name}, mock_osutils)
        item_names = ["ssh-authorized-keys", 'expiredate', 'passwd', 'groups',
                      'primary-group', 'inactive']
        expected_logging = [("Setting password for existing user '%s'"
                            % user_name)]
        expected_logging.append([
            "%s not found, passing None" % item for item in item_names
        ])
        self.assertEqual(snatcher.output, expected_logging[0::-1])

    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.users.UsersPlugin._process_item')
    @mock.patch('cloudbaseinit.plugins.common.userdataplugins.'
                'cloudconfigplugins.users.factory')
    def test_process(self, mock_osutils_factory, mock_process_item):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfigplugins.'
                                   'users'):
            self.assertRaises(exception.CloudbaseInitException,
                              self.user_plugin.process,
                              mock.sentinel.user_data)
        mock_osutils_factory.get_os_utils.assert_called_once()
        mock_user_data = [{"fake_key": "fake_data"}]
        self.user_plugin.process(mock_user_data)
        mock_process_item.assert_called_once()

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
from cloudbaseinit.plugins.common import constants
from cloudbaseinit.plugins.common import createuser
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class UserManagerTest(unittest.TestCase):

    def setUp(self):
        self.user_manager = createuser.UserManager()

    @testutils.ConfPatcher('username', 'fake_username')
    def test_get_username(self):
        fake_data = {constants.SHARED_DATA_USERNAME: None}
        result = self.user_manager._get_username(fake_data)
        self.assertEqual('fake_username', result)
        self.assertEqual(fake_data[constants.SHARED_DATA_USERNAME], result)

    @testutils.ConfPatcher('groups', ['Group 1', 'Group 2'])
    def test_get_groups(self):
        expected_groups = ['Group 1', 'Group 2']
        result = self.user_manager._get_groups({})
        self.assertEqual(result, expected_groups)

    def test_get_expire_status(self):
        result = self.user_manager._get_expire_status(None)
        self.assertEqual(False, result)

    def test_get_user_activity(self):
        result = self.user_manager._get_user_activity(None)
        self.assertEqual(False, result)

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def test_get_password(self, mock_get_os_utils):
        mock_utils = mock.Mock()
        expected_password = "fake_password"
        fake_shared_data = {constants.SHARED_DATA_PASSWORD: "fake"}
        mock_utils.get_maximum_password_length.return_value = mock.sentinel.len
        mock_utils.generate_random_password.return_value = expected_password
        mock_get_os_utils.return_value = mock_utils
        result = self.user_manager._get_password(fake_shared_data)
        self.assertEqual(expected_password, result)
        self.assertEqual(mock_utils.get_maximum_password_length.call_count, 1)
        self.assertEqual(mock_utils.generate_random_password.call_count, 1)
        self.assertEqual(expected_password, fake_shared_data[
                         constants.SHARED_DATA_PASSWORD])


class CreateUserPluginTests(unittest.TestCase):

    def setUp(self):
        self._create_user = createuser.BaseCreateUserPlugin()

    def test_execute(self):
        fake_service = "fake_service"
        fake_shared_data = "fake_shared_data"
        response = self._create_user.execute(fake_service, fake_shared_data)
        self.assertEqual((base.PLUGIN_EXECUTION_DONE, False), response)

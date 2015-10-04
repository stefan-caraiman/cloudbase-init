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

from cloudbaseinit.metadata import factory
from cloudbaseinit.tests import testutils


class MetadataServiceFactoryTests(unittest.TestCase):

    @testutils.ConfPatcher('metadata_services',
                           [mock.sentinel.first, mock.sentinel.second])
    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader')
    def test_load_services(self, mock_class_loader):
        loader = mock_class_loader.return_value
        loader.load_class.return_value.side_effect = (
            mock.sentinel.first, mock.sentinel.second)

        services = factory.load_services()

        self.assertEqual([mock.sentinel.first, mock.sentinel.second],
                         services)

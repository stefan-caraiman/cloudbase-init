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

import collections
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins import factory
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class TestPluginFactory(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_load_plugins(self, mock_load_class,
                           stage=base.PLUGIN_STAGE_MAIN):
        def func(arg):
            loaded = mock.MagicMock()
            loaded.return_value = arg
            return loaded

        mock_load_class.side_effect = func
        expected_plugins = collections.defaultdict(list)
        plugins = factory.PLUGINS_BY_STAGES.get(stage, {})
        expected_load = list(map(mock.call, plugins.keys()))
        for plugin, priority in plugins.items():
            expected_plugins[priority].append(plugin)
        by_priority = sorted(expected_plugins.items(), reverse=False)
        expected_plugins = [values for (_, values) in by_priority]

        response = factory.load_plugins(stage)

        self.assertEqual(sorted(expected_load),
                         sorted(mock_load_class.call_args_list))
        for expected_group, actual_group in zip(expected_plugins, response):
            self.assertEqual(sorted(expected_group), sorted(actual_group))

    def test_load_plugins(self):
        self._test_load_plugins()

    def test_load_plugins_main(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_MAIN)

    def test_load_plugins_networking(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_PRE_NETWORKING)

    def test_load_plugins_metadata(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY)

    def test_load_plugins_stage_missing(self):
        with self.assertRaises(KeyError):
            factory.load_plugins(mock.Mock())

    @testutils.ConfPatcher('plugins', ['missing.plugin'])
    def test_load_plugins_plugin_failed(self):
        plugins = factory.load_plugins(base.PLUGIN_STAGE_MAIN)
        self.assertEqual([], plugins)

    @testutils.ConfPatcher('plugins', ["cloudbaseinit.plugins.windows."
                                       "localscripts.LocalScriptsPlugin"])
    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def test_old_plugin_mapping(self, mock_load_class):
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'factory') as snatcher:
            plugins = list(factory._new_plugin_names(CONF.plugins))

        expected = [
            "Old plugin module 'cloudbaseinit.plugins.windows."
            "localscripts.LocalScriptsPlugin' was found. "
            "The new name is 'cloudbaseinit.plugins.common."
            "localscripts.LocalScriptsPlugin'. The old name will not "
            "be supported starting with cloudbaseinit 1.0",
        ]
        expected_plugin = ('cloudbaseinit.plugins.common.'
                           'localscripts.LocalScriptsPlugin')
        self.assertEqual(expected, snatcher.output)
        self.assertEqual([expected_plugin], plugins)

    @mock.patch.object(factory, '_DEPENDENCIES', {'a': ('b', )})
    def _test_check_dependencies(self, expected):
        with self.assertRaises(exception.CloudbaseInitException) as cm:
            factory.check_dependencies()
        self.assertEqual(expected, str(cm.exception))

    @testutils.ConfPatcher('plugins', ['b'])
    def test_check_dependencies_parent_not_found(self):
        msg = "Plugin 'b' found, but it depends on 'a'."
        self._test_check_dependencies(msg)

    @testutils.ConfPatcher('plugins', ['b', 'a'])
    def test_check_dependencies_child_before_parent(self):
        msg = "Child plugin 'b' found before parent plugin 'a'"
        self._test_check_dependencies(msg)

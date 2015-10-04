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

import abc

import six


PLUGIN_EXECUTION_DONE = 1
PLUGIN_EXECUTE_ON_NEXT_BOOT = 2

PLUGIN_STAGE_PRE_NETWORKING = "PRE_NETWORKING"
PLUGIN_STAGE_PRE_METADATA_DISCOVERY = "PRE_METADATA_DISCOVERY"
PLUGIN_STAGE_MAIN = "MAIN"


@six.add_metaclass(abc.ABCMeta)
class BasePlugin(object):

    @abc.abstractmethod
    def required_capabilities(self):
        """Define the list of the required capabilities

        The required capabilities are the capabilities
        without which the plugin can't even execute.
        """

    @abc.abstractmethod
    def optional_capabilities(self):
        """Get the optional capabilities that this plugin needs

        This list contains the capabilities that might be useful
        for the execution of this plugin, but they aren't
        mandatory for its execution.
        """

    def get_name(self):
        return self.__class__.__name__

    def get_os_requirements(self):
        return None, None

    def execute(self, service_group, shared_data):
        pass

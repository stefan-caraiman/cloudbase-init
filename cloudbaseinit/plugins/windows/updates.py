# Copyright (c) 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import updates

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class WindowsAutoUpdatesPlugin(base.BasePlugin):
    def execute(self, service, shared_data):
        updates_map = {
            constant.AUTOMATIC_UPDATES_ENABLE: True,
            constant.DISABLE_UPDATES: False}
        enable_updates = service.get_enable_automatic_updates()

        if (enable_updates is not None or
                CONF.enable_automatic_updates is not None):
            enable_updates = (enable_updates or
                              updates_map[CONF.enable_automatic_updates])
            LOG.info("Configuring automatic updates: %s", enable_updates)
            updates.set_automatic_updates(enable_updates)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (5, 2)

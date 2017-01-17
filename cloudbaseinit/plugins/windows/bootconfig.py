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
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows import bootconfig

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class BootConfigPlugin(base.BasePlugin):
    def execute(self, service, shared_data):
        if CONF.boot_status_policy:
            LOG.info("Configure boot policy: %s", CONF.boot_status_policy)
            bootconfig.set_boot_status_policy(CONF.boot_status_policy)

        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

    def get_os_requirements(self):
        return 'win32', (5, 2)

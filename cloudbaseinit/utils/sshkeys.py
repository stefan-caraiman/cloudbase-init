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

import os

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


def set_ssh_keys(osutils, public_keys=None, username=None):
    username = username or CONF.username
    user_home = osutils.get_user_home(username)
    if not user_home:
        raise exception.CloudbaseInitException("User profile not found!")

    LOG.debug("User home: %s" % user_home)
    user_ssh_dir = os.path.join(user_home, '.ssh')
    if not os.path.exists(user_ssh_dir):
        os.makedirs(user_ssh_dir)
    authorized_keys_path = os.path.join(user_ssh_dir, "authorized_keys")
    LOG.info("Writing SSH public keys in: %s" % authorized_keys_path)
    with open(authorized_keys_path, 'w') as file_handler:
        for public_key in public_keys:
            # All public keys are space-stripped.
            file_handler.write(public_key + "\n")

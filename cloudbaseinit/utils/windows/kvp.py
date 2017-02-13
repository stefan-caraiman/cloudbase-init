# Copyright 2017 Cloudbase Solutions Srl
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

from six.moves import winreg

from oslo_log import log as oslo_logging

from cloudbaseinit import exception

KVP_REGISTRY_KEY = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest"

LOG = oslo_logging.getLogger(__name__)


def set_key_value_pair(name, value):
    LOG.debug("Setting KVP: %(name)s = %(value)s",
              {"name": name, "value": value})
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KVP_REGISTRY_KEY,
                        0, winreg.KEY_ALL_ACCESS) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))


def get_key_value_pair(name):
    LOG.debug("Getting KVP value for: %s", name)
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KVP_REGISTRY_KEY) as key:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except WindowsError as ex:
            if ex.winerror == 2:
                raise exception.ItemNotFoundException(
                    'KVP key not found: %s' % name)
            else:
                raise


def delete_key_value_pair(name):
    LOG.debug("Deleting KVP: %s", name)
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KVP_REGISTRY_KEY,
                        0, winreg.KEY_ALL_ACCESS) as key:
        try:
            winreg.DeleteValue(key, name)
        except WindowsError as ex:
            if ex.winerror == 2:
                raise exception.ItemNotFoundException(
                    'KVP key not found: %s' % name)
            else:
                raise


def get_key_value_pairs():
    LOG.debug("Getting KVPs")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KVP_REGISTRY_KEY) as key:
        kvps = {}
        try:
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                kvps[name] = value
                i += 1
        except WindowsError as ex:
            if ex.winerror != 259:
                raise
        return kvps

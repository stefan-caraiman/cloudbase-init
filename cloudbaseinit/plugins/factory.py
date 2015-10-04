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

import collections

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils import classloader


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

# Some plugins were moved to plugins.common, in order to
# better reflect the fact that they are not platform specific.
# Unfortunately, there are a lot of users out there with old
# config files which are using the old plugin names.
# So in order not to crash cloudbaseinit for their cases,
# we provide this explicit mapping. This will be removed
# when we'll reach 1.0 though.

OLD_PLUGINS = {
    'cloudbaseinit.plugins.windows.mtu.MTUPlugin':
    'cloudbaseinit.plugins.common.mtu.MTUPlugin',

    'cloudbaseinit.plugins.windows.sethostname.SetHostNamePlugin':
    'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',

    'cloudbaseinit.plugins.windows.networkconfig.NetworkConfigPlugin':
    'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',

    'cloudbaseinit.plugins.windows.sshpublickeys.SetUserSSHPublicKeysPlugin':
    'cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin',

    'cloudbaseinit.plugins.windows.userdata.UserDataPlugin':
    'cloudbaseinit.plugins.common.userdata.UserDataPlugin',

    'cloudbaseinit.plugins.windows.setuserpassword.SetUserPasswordPlugin':
    'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin',

    'cloudbaseinit.plugins.windows.localscripts.LocalScriptsPlugin':
    'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin',
}


PLUGINS_BY_STAGES = {
    base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY: {
        'cloudbaseinit.plugins.common.mtu.MTUPlugin': 10,
    },

    base.PLUGIN_STAGE_PRE_NETWORKING: {
        'cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin': 10,
    },

    base.PLUGIN_STAGE_MAIN: {
        'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin': 10,
        'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin': 10,
        'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin': 10,
        'cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin': 10,
        'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin': 10,

        'cloudbaseinit.plugins.common.setuserpassword.'
        'SetUserPasswordPlugin': 20,

        'cloudbaseinit.plugins.common.sshpublickeys.'
        'SetUserSSHPublicKeysPlugin': 30,
        'cloudbaseinit.plugins.windows.winrmlistener.'
        'ConfigWinRMListenerPlugin': 30,

        'cloudbaseinit.plugins.windows.winrmcertificateauth.'
        'ConfigWinRMCertificateAuthPlugin': 40,
        'cloudbaseinit.plugins.common.userdata.UserDataPlugin': 40,

        'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin': 50,
    },
}


_DEPENDENCIES = {
    'cloudbaseinit.plugins.windows.winrmlistener.'
    'ConfigWinRMListenerPlugin': ('cloudbaseinit.plugins.windows.'
                                  'winrmcertificateauth.'
                                  'ConfigWinRMCertificateAuthPlugin', ),

    'cloudbaseinit.plugins.windows.createuser.'
    'CreateUserPlugin': ('cloudbaseinit.plugins.common.sshpublickeys.'
                         'SetUserSSHPublicKeysPlugin',
                         'cloudbaseinit.plugins.common.setuserpassword.'
                         'SetUserPasswordPlugin'),
}


def check_dependencies():
    """Try to check the dependencies between the given plugins

    A dependency is satisfied if a plugin that needs another plugin
    to run first is found together with it and if the order is respected.
    """

    for parent, children in _DEPENDENCIES.items():
        try:
            parent_index = CONF.plugins.index(parent)
        except ValueError:
            parent_index = None
        for child in children:
            try:
                child_index = CONF.plugins.index(child)
            except ValueError:
                continue
            if parent_index is None:
                msg = "Plugin {!r} found, but it depends on {!r}.".format(
                    child, parent)
                raise exception.CloudbaseInitException(msg)
            if child_index < parent_index:
                _msg = "Child plugin {!r} found before parent plugin {!r}"
                msg = _msg.format(child, parent)
                raise exception.CloudbaseInitException(msg)


def _new_plugin_names(plugins):
    for class_path in plugins:
        if class_path in OLD_PLUGINS:
            new_class_path = OLD_PLUGINS[class_path]
            LOG.warn("Old plugin module %r was found. The new name is %r. "
                     "The old name will not be supported starting with "
                     "cloudbaseinit 1.0", class_path, new_class_path)
            yield new_class_path
        else:
            yield class_path


def load_plugins(stage=base.PLUGIN_STAGE_MAIN):
    """Load all the plugins specific to the given stage

    It will return a dictionary of lists, where the keys
    correspond to a priority group and the list correspond
    to the plugins specific for that group.
    """

    cl = classloader.ClassLoader()
    plugins = collections.defaultdict(list)
    stage_plugins = PLUGINS_BY_STAGES[stage]
    new_plugins = set(_new_plugin_names(CONF.plugins))
    current_plugins = set(six.viewkeys(stage_plugins)) & new_plugins

    for class_path in current_plugins:
        priority = stage_plugins[class_path]
        try:
            plugin_cls = cl.load_class(class_path)
        except ImportError:
            LOG.error("Could not import plugin module %r", class_path)
            continue
        else:
            plugin = plugin_cls()
            plugins[priority].append(plugin)

    by_priority = sorted(plugins.items(), reverse=False)
    return [values for (_, values) in by_priority]

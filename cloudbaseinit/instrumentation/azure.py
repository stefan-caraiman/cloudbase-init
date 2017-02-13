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

import datetime
import re

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.instrumentation import base
from cloudbaseinit.utils.windows import kvp

DATETIME_FORMAT_STR = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_ERROR_CODE = 1

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class AzureInstrumentation(base.BaseInstrumentation):
    _PLUGIN_NAME_MAP = {
        (constant.CONFIGURATION_PASS_SPECIALIZE,
         constant.INSTRUMENT_PROVISIONING_STARTED):
        "PA_specialize_0_ReportNotReady",
        (constant.CONFIGURATION_PASS_SPECIALIZE, "PageFilesPlugin"):
        "PA_specialize_1_ConfigurePageFile",
        (constant.CONFIGURATION_PASS_SPECIALIZE, "BootStatusPolicyPlugin"):
        "PA_specialize_2_ConfigureBootStatusPolicy",
        (constant.CONFIGURATION_PASS_SPECIALIZE, "NTPClientPlugin"):
        "PA_specialize_3_ConfigureTimeSettings",
        (constant.CONFIGURATION_PASS_SPECIALIZE, "SANPolicyPlugin"):
        "PA_specialize_4_ConfigureSanPolicy",
        (constant.CONFIGURATION_PASS_SPECIALIZE, "RDPSettingsPlugin"):
        "PA_specialize_5_ConfigureRdpKeepAlive",
        # "PA_specialize_6_CopyCustomData"
        # "PA_specialize_7_CopyTempDriveWarningReadme"
        # "PA_specialize_8_ReportNotReady",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         constant.INSTRUMENT_PROVISIONING_STARTED):
        "PA_oobeSystem_0_ReportNotReady",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE, "CreateUserPlugin"):
        "PA_oobeSystem_1_ConfigureAdministratorUsername",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE, "SetUserPasswordPlugin"):
        "PA_oobeSystem_1_ConfigureAdministratorUsername",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         "ServerCerificatesPlugin"):
        "PA_oobeSystem_2_ConfigureCertificates",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         "ConfigWinRMListenerPlugin"):
        "PA_oobeSystem_3_ConfigureWinRm",
        # "PA_oobeSystem_4_ReportNotReady"
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE, "BCDConfigPlugin"):
        "PA_oobeSystem_5_ConfigureBCD",
        # "PA_oobeSystem_6_ConfigureTimeService"
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE, "WindowsLicensingPlugin"):
        "PA_oobeSystem_7_ConfigureLicensing",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         "RDPPostCertificateThumbprintPlugin"):
        "PA_oobeSystem_8_UpdateRDPCertificateThumbprint",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         "WindowsAutoUpdatesPlugin"):
        "PA_oobeSystem_9_ConfigureAutomaticUpdates",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE, "AzureGuestAgentPlugin"):
        "PA_oobeSystem_11_ConfigureGuestAgentService",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         constant.INSTRUMENT_REBOOT):
        "PA_oobeSystem_12_RestartMachine",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         constant.INSTRUMENT_PROVISIONING_COMPLETED):
        "PA_oobeSystem_13_ReportReady",
        (constant.CONFIGURATION_PASS_SETUP_COMPLETE,
         constant.INSTRUMENT_PROVISIONING_FAILED):
        "PA_errorHandler_0_ReportNotReady",
        (constant.CONFIGURATION_PASS_ERROR_HANDLER,
         constant.INSTRUMENT_PROVISIONING_FAILED):
        "PA_errorHandler_0_ReportNotReady",
        # "PA_roleReady_0_ReportReady"
    }

    def initialize(self):
        if CONF.configuration_pass == constant.CONFIGURATION_PASS_SPECIALIZE:
            self._delete_old_entries()

    @staticmethod
    def _delete_old_entries():
        LOG.debug("Deleting existing KVP instrumentation values")
        for name, _ in kvp.get_key_value_pairs().items():
            if re.search(
                    "specialize|oobeSystem|reportReady|errorHandler", name):
                kvp.delete_key_value_pair(name)

    def instrument_call(self, name, callable):
        ex = None
        error_code = 0

        try:
            start_time = datetime.datetime.utcnow()
            ret_val = callable()
        except exception.WindowsCloudbaseInitException as ex2:
            error_code = ex2.error_code
            ex = ex2
        except WindowsError as ex2:
            error_code = ex2.winerror
            ex = ex2
        except Exception as ex2:
            # In this case a matching Windows error code cannot be determined
            error_code = DEFAULT_ERROR_CODE
            ex = ex2
        finally:
            end_time = datetime.datetime.utcnow()

        key = self._PLUGIN_NAME_MAP.get((CONF.configuration_pass, name))
        if not key:
            LOG.debug("No instrumentation key defined for: %s",
                      (CONF.configuration_pass, name))
        else:
            value = ("Called=%(start_time)s;"
                     "Returned=%(end_time)s;"
                     "ErrorCode=%(error_code)s" %
                     {"start_time": start_time.strftime(DATETIME_FORMAT_STR),
                      "end_time": end_time.strftime(DATETIME_FORMAT_STR),
                      "error_code": error_code})
            try:
                kvp.set_key_value_pair(key, value)
            except Exception as ex:
                LOG.execption(ex)

        if ex is not None:
            raise ex
        return ret_val

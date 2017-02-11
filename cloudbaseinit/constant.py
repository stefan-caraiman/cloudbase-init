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

# Config Drive types and possible locations.
CD_TYPES = {
    "vfat",    # Visible device (with partition table).
    "iso",     # "Raw" format containing ISO bytes.
}
CD_LOCATIONS = {
    # Look into optical units devices. Only an ISO format could
    # be used here (vfat ignored).
    "cdrom",
    # Search through physical disks for raw ISO content or vfat filesystems
    # containing configuration drive's content.
    "hdd",
    # Search through partitions for raw ISO content or through volumes
    # containing configuration drive's content.
    "partition",
}

CLEAR_TEXT_INJECTED_ONLY = 'clear_text_injected_only'
ALWAYS_CHANGE = 'always'
NEVER_CHANGE = 'no'
LOGON_PASSWORD_CHANGE_OPTIONS = [CLEAR_TEXT_INJECTED_ONLY, NEVER_CHANGE,
                                 ALWAYS_CHANGE]

SAN_POLICY_ONLINE_STR = 'OnlineAll'
SAN_POLICY_OFFLINE_STR = 'OfflineAll'
SAN_POLICY_OFFLINE_SHARED_STR = 'OfflineShared'

VOL_ACT_KMS = "KMS"
VOL_ACT_AVMA = "AVMA"

CERT_LOCATION_LOCAL_MACHINE = "LocalMachine"
CERT_LOCATION_CURRENT_USER = "CurrentUser"

INSTRUMENT_REBOOT = "instrument_reboot"
INSTRUMENT_PROVISIONING_STARTED = "instrument_provisioning_started"
INSTRUMENT_PROVISIONING_COMPLETED = "instrument_provisioning_completed"
INSTRUMENT_PROVISIONING_FAILED = "instrument_provisioning_failed"

CONFIGURATION_PASS_SPECIALIZE = "specialize"
CONFIGURATION_PASS_SETUP_COMPLETE = "setup_complete"
CONFIGURATION_PASS_SERVICE = "service"
CONFIGURATION_PASS_ERROR_HANDLER = "error_handler"

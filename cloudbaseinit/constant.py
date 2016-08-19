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

# Network types
IPV4 = 4
IPV6 = 6

# Different types of interfaces
PHY = "phy"
BOND = "bond"
VIF = "vif"
VLAN = "vlan"

# Different types of subnetworks
STATIC = "static"
MANUAL = "manual"

# Field names related to network configuration
ASSIGNED_TO = "assigned_to"
BOND_LINKS = "bond_links"
BOND_MODE = "bond_mode"
BOND_MIIMON = "bond_miimon"
BOND_HASH_POLICY = "bond_xmit_hash_policy"
BROADCAST = "broadcast"
DNS = "dns_nameservers"
GATEWAY = "gateway"
ID = "id"
LINK_ID = "link_id"
LINK_TYPE = "link_type"
SUBNET_ID = "subnet_id"
ROUTE_ID = "route_id"
IP_ADDRESS = "ip_address"
IP_VERSION = "ip_version"
NAME = "name"
MAC_ADDRESS = "mac_address"
MTU = "mtu"
NETWORK = "network"
NETWORK_TYPE = "network_type"
NETMASK = "netmask"
NEUTRON_NETWORK_ID = "neutron_network_id"
NEUTRON_PORT_ID = "neutron_port_id"
TYPE = "type"
VERSION = "version"
VIF_ID = "vif_id"
VLAN_ID = "vlan_id"
VLAN_LINK = "vlan_link"
VLAN_MAC_ADDRESS = "vlan_mac_address"
PRIORITY = "priority"

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

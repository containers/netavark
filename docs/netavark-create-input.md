# Netavark Create Input

## Overview

The `netavark create` command accepts a JSON configuration with three main sections:
- `network`: Network configuration details
- `used`: Information about already used resources
- `options`: Creation options and settings

## Network Fields

The `network` object contains the network configuration.

| Field | Description | Required |
|-------|-------------|----------|
| `name` | Name of the network. Must match the pattern `[a-zA-Z0-9][a-zA-Z0-9_.-]*` and cannot be empty. | Yes |
| `id` | Network ID. Must be 64-bit hexadecimal | Yes |
| `driver` | Network driver type (e.g., "bridge", "macvlan", "ipvlan") | Yes |
| `dns_enabled` | Boolean indicating whether DNS should be enabled for this network | Yes |
| `internal` | Boolean indicating whether the network should be internal | Yes |
| `ipv6_enabled` | Boolean indicating if IPv6 is enabled | Yes |
| `network_interface` | Name of the network interface on the host| No |
| `options` | Key-value map of driver-specific network options (e.g., "mtu", "vlan", "isolate", "metric", "vrf", "mode"). | No |
| `ipam_options` | Key-value map of IPAM (IP Address Management) options. Supported drivers: "host-local", "dhcp", "none". | No |
| `subnets` | Array of subnet configurations. Each subnet can include a subnet CIDR, optional gateway, and optional lease range. | No |
| `routes` | Array of static routes for the network. Each route includes destination (CIDR), gateway, and optional metric. | No |
| `network_dns_servers` | Array of IP addresses for DNS servers used by aardvark-dns. | No |
| `labels` | Key-value map of labels associated with the network. | No |

## Used Fields

The `used` object contains information about resources that are already in use and should be avoided.

| Field | Description | Required |
|-------|-------------|----------|
| `interfaces` | Array of network interface names that are already in use on the host. | Yes |
| `names` | Map of network names to their IDs for networks that already exist. Used to prevent duplicate network names. | Yes |
| `subnets` | Array of subnet CIDR ranges that are already in use on the host or by other network configurations. | Yes |

## Options Fields

The `options` object contains creation options and settings.

| Field | Description | Required |
|-------|-------------|----------|
| `subnet_pools` | Array of subnet pools from which to allocate subnets. Each pool contains a `base` (CIDR) and `size` (subnet size in bits). | Yes |
| `default_interface_name` | Default prefix for auto-generated interface names (e.g., "podman" will generate "podman0", "podman1", etc.). | No |
| `check_used_subnets` | Boolean flag indicating whether to check if subnets conflict with already used subnets. | Yes |

## Example

```json
{
  "network": {
    "name": "example-network",
    "id": "abc123def4567890123456789012345678901234567890123456789012345678",
    "driver": "bridge",
    "dns_enabled": false,
    "internal": false,
    "ipv6_enabled": false,
    "subnets": [
      {
        "subnet": "10.100.0.0/24"
      }
    ],
    "options": {
      "mtu": "1500"
    },
    "labels": {
      "key1": "value1",
      "key2": "value2"
    }
  },
  "used": {
    "interfaces": [],
    "names": {},
    "subnets": []
  },
  "options": {
    "subnet_pools": [
      {
        "base": "10.89.0.0/16",
        "size": 24
      }
    ],
    "default_interface_name": "podman",
    "check_used_subnets": false
  }
}
```
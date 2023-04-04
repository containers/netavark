# Description of the netavark plugin API

A netavark plugin is a external binary which must implement a specific set of subcommands that will be called by podman and netavark.
 - `create`: creates a network config
 - `setup`: setup the network configuration
 - `teardown`: tear down the network configuration
 - `info`: show info about this plugin

## Create subcommand

The create subcommand creates a new network config for podman.
The subcommand will receive the JSON network config via STDIN. Podman will populate
the network name and ID before calling the plugin. The name and ID cannot be changed
by the plugin. The driver name must also not be changed. All other config
fields can be changed in the plugin.

Other fields such as subnet and options will also be populated by podman when
these options are set on the podman network create command, i.e. `--subnet`
and `--option`. The plugin validates the given values and errors out for
invalid values.

On success the plugin should print the generated config as JSON to STDOUT.

Example JSON input and output format:
```
{
    "name": "example1",
    "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
    "driver": "mydriver",
    "network_interface": "enp1",
    "subnets": [
        {
            "subnet": "10.0.0.0/16",
            "gateway": "10.0.0.1"
        }
    ],
    "ipv6_enabled": false,
    "internal": false,
    "dns_enabled": false,
    "ipam_options": {
        "driver": "host-local"
    },
    "options": {
        "custom": "opt"
    }
}
```

## Setup subcommand

The setup subcommand sets-up the network configuration. This command is called when
a container is started or network connect is used, assuming the container uses
a network which was created by the plugin, see the create command above.

On STDIN it receives a JSON config which contains the network config and container options.
ON STDOUT the plugin must return a JSON status block. This contains information about the
created interface, the assigned ip and mac address. This information will be visible in the
podman inspect output.

Also this command accepts one argument which is the path to the container network namespace.

Example JSON input:
```
{
    "container_id": "752947ff91f961eb3cb47ffe9315016979f3ffbec09e4d96a4fae3fb03391697",
    "container_name": "testctr",
    "port_mappings": [
        {
            "container_port": 80,
            "host_ip": "127.0.0.1",
            "host_port": 8080,
            "protocol": "tcp",
            "range": 1
        }
    ],
    "network": {
        "dns_enabled": false,
        "driver": "bridge",
        "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
        "internal": false,
        "ipv6_enabled": false,
        "name": "podman",
        "network_interface": "podman0",
        "options": null,
        "ipam_options": {
            "driver": "host-local"
        },
        "subnets": [
            {
                "gateway": "10.88.0.1",
                "lease_range": null,
                "subnet": "10.88.0.0/16"
            }
        ],
        "network_dns_servers": null
    },
    "network_options": {
        "aliases": [
            "752947ff91f9"
        ],
        "interface_name": "eth0",
        "static_ips": [
            "10.88.0.50"
        ],
        "static_mac": "aa:bb:cc:dd:aa:00"
    }
}
```

Example JSON output:
```
{
    "dns_search_domains": [],
    "dns_server_ips": [],
    "interfaces": {
        "eth0": {
            "mac_address": "aa:bb:cc:dd:aa:00",
            "subnets": [
                {
                    "gateway": "10.88.0.1",
                    "ipnet": "10.88.0.50/16"
                }
            ]
        }
    }
}
```


## Teardown subcommand

The teardown command is basically the reverse of the setup command. It should
revert what the plugin did in setup.
It accepts the same input as setup but it should not return anything on success.

## Info subcommand

Used to output information about this plugin. It must contain the version of your plugin and the API version.
Extra fields can be added. The API version must be set to `1.0.0` at the moment, it is not used the moment
but could be used in the future to allow for backwards compatibility in case the plugin types change.

```
{
    "version": "0.1.0",
    "api_version": "1.0.0"
}
```

## Error handling

If the plugin encounters an error it should return a special json message with the following format:
```
{"error": "message"}
```
where message should be replace with your actual error message. This message will be returned by
netavark and will be visible to podman users.


## Rust types

Rust types can be found in [./src/network/types.rs](./src/network/types.rs), see the documentation
[here](https://docs.rs/netavark/latest/netavark/network/types).
Fields that are wrapped by an `Option<T>` can be omitted from the json, otherwise they must be set
to allow proper deserialization.

## Rust plugin interface

There is a simple ready to use interface for writing your plugin in rust, see [./src/plugin.rs](./src/plugin.rs)
```rust
use netavark::{
    network::types,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};

fn main() {
    // change the version to the version of your plugin
    let info = Info::new("0.1.0".to_owned(), API_VERSION.to_owned(), None);

    PluginExec::new(Exec {}, info).exec();
}

struct Exec {}

impl Plugin for Exec {
    fn create(
        &self,
        network: types::Network,
    ) -> Result<types::Network, Box<dyn std::error::Error>> {
        // your logic here
    }

    fn setup(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        // your logic here
    }

    fn teardown(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // your logic here
    }
}
```
Also see the examples in [./examples](./examples/).

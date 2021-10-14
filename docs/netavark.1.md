% netavark(1)
 
## NAME
netavark - Configure a given network namespace for use by a container
 
## SYNOPSIS
**netavark** [*options*] *command* *network namespace path*
 
## DESCRIPTION
Netavark configures a network namespace according to a configuration read from STDIN. The configuration is JSON formatted.

## GLOBAL OPTIONS
#### **--file**, **-f**
 
Instead of reading from STDIN, read the configuration to be applied from the given file. **-f -** may also be used to flag reading from STDIN.

## COMMANDS

### netavark setup

The setup command configures the given network namespace with the given configuration, creating any interfaces and firewall rules necessary.

### netavark teardown

The teardown command is the inverse of the setup command, undoing any configuration applied. Some interfaces may not be deleted (bridge interfaces, for example, will not be removed). 

### CONFIGURATION FORMAT

The configuration accepted is the same for both setup and teardown. It is JSON formatted.

Format is https://github.com/containers/podman/blob/cd7b48198c38c5028540e85dc72dd3406f4318f0/libpod/network/types/network.go#L164-L173 but we will also send a Networks array including all the network definitions (https://github.com/containers/podman/blob/cd7b48198c38c5028540e85dc72dd3406f4318f0/libpod/network/types/network.go#L32-L62)
TODO: Transcribe configuration into here in a nice tabular format

## EXAMPLE
 
netavark setup /run/user/1000/podman/netns/d11d1f9c499d

netavark -f /run/podman/828b0508ae64.conf teardown /run/podman/netns/828b0508ae64
 
## SEE ALSO
podman(1)
 
## HISTORY
September 2021, Originally compiled by Matt Heon <mheon@redhat.com>


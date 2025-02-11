# -*- bash -*-

# Netavark binary to run
NETAVARK=${NETAVARK:-./bin/netavark}
TEST_PLUGINS=${TEST_PLUGINS:-./targets/release/examples}

TESTSDIR=${TESTSDIR:-$(dirname ${BASH_SOURCE})}

# export RUST_BACKTRACE so that we get a helpful stack trace
export RUST_BACKTRACE=full

# this will cause tests to fail because stdou/stderr are not separate
# export RUST_LOG=netavark=debug

HOST_NS_PID=
CONTAINER_NS_PIDS=()

function create_container_ns() {
    CONTAINER_NS_PIDS+=("$(create_netns)")
}

function basic_setup() {
    HOST_NS_PID=$(create_netns)
    create_container_ns

    # make sure to set DBUS_SYSTEM_BUS_ADDRESS to an empty value
    # netavark will try to use firewalld connection when possible
    # because we run in a separate netns we cannot use firewalld
    # firewalld run in the host netns and not our custom netns
    # thus the firewall rules end up in the wrong netns
    # unsetting does not work, it would use the default address
    export DBUS_SYSTEM_BUS_ADDRESS=

    NETAVARK_TMPDIR=$(mktemp -d --tmpdir=${BATS_TMPDIR:-/tmp} netavark_bats.XXXXXX)

    # hack to make aardvark-dns run when really root or when running as user with
    # podman unshare --rootless-netns; since netavark runs aardvark with systemd-run
    # it needs to know if it should use systemd user instance or not.
    # iptables are still setup identically.
    rootless=false
    if [[ ! -e "/run/dbus/system_bus_socket" ]]; then
        rootless=true
    fi

    mkdir -p "$NETAVARK_TMPDIR/config"

    run_in_host_netns ip link set lo up
}

function basic_teardown() {
    teardown_firewalld
    kill -9 $HOST_NS_PID
    for i in "${!CONTAINER_NS_PIDS[@]}"; do
        kill -9 "${CONTAINER_NS_PIDS[$i]}"
    done
    rm -rf "$NETAVARK_TMPDIR"
}

function setup_firewalld() {
    # first, create a new dbus session
    DBUS_SYSTEM_BUS_ADDRESS=unix:path=$NETAVARK_TMPDIR/netavark-firewalld
    run_in_host_netns dbus-daemon --address="$DBUS_SYSTEM_BUS_ADDRESS" --print-pid --config-file="${TESTSDIR}/testfiles/firewalld-dbus.conf"
    DBUS_PID="$output"
    # export DBUS_SYSTEM_BUS_ADDRESS so firewalld and netavark will use the correct socket
    export DBUS_SYSTEM_BUS_ADDRESS

    # second, start firewalld in the netns with the dbus socket
    # do not use run_in_host_netns because we want to run this in background
    # use --nopid (we cannot change the pid file location), --nofork do not run as daemon so we can kill it by pid
    # change --system-config to make sure that we do not write any config files to the host location
    nsenter -n -t $HOST_NS_PID firewalld --nopid --nofork --system-config "$NETAVARK_TMPDIR" &>"$NETAVARK_TMPDIR/firewalld.log" &
    FIREWALLD_PID=$!
    echo "firewalld pid: $FIREWALLD_PID"

    # wait for firewalld to become ready
    timeout=5
    while [ $timeout -gt 0 ]; do
        # query firewalld with firewall-cmd
        expected_rc="?" run_in_host_netns firewall-cmd --state
        if [ "$status" -eq 0 ]; then
            break
        fi
        sleep 1
        timeout=$(($timeout - 1))
        if [ $timeout -eq 0 ]; then
            cat "$NETAVARK_TMPDIR/firewalld.log"
            die "failed to start firewalld - timeout"
        fi
    done
}

function teardown_firewalld() {
    if [ -n "${NETAVARK_FIREWALLD_RELOAD_PID}" ]; then
        kill -9 $NETAVARK_FIREWALLD_RELOAD_PID
    fi
    if [ -n "${FIREWALLD_PID}" ]; then
        kill -9 $FIREWALLD_PID
    fi
    if [ -n "${DBUS_PID}" ]; then
        kill -9 $DBUS_PID
    fi
    unset DBUS_SYSTEM_BUS_ADDRESS
}

# Provide the above as default methods.
function setup() {
    basic_setup
}

function teardown() {
    basic_teardown
}

function create_netns() {
    # create a new netns and mountns and run a sleep process to keep it alive
    # we have to redirect stdout/err to /dev/null otherwise bats will hang
    unshare -nm sleep inf &>/dev/null &
    echo $!
}

function get_container_netns_path() {
    local which="0"
    if [[ $# -eq 1 ]]; then
        which=$1
    fi
    echo /proc/"${CONTAINER_NS_PIDS[$which]}"/ns/net
}

################
#  run_netavark  #  Invoke $NETAVARK, with timeout, using BATS 'run'
################
#
# This is the preferred mechanism for invoking netavark: first, it
# it joins the test network namespace before it invokes $NETAVARK,
# which may be 'netavark' or '/some/path/netavark'.
function run_netavark() {
    run_in_host_netns $NETAVARK --rootless "$rootless" \
    --config "$NETAVARK_TMPDIR/config" "$@"
}

function run_netavark_firewalld_reload() {
    # need to use nsetner as this will be run in the background
    nsenter -n -t $HOST_NS_PID $NETAVARK --config "$NETAVARK_TMPDIR/config" firewalld-reload &
    NETAVARK_FIREWALLD_RELOAD_PID=$!
}


################
#  run_in_container_netns  #  Run args in container netns
################
#
function run_in_container_netns() {
    local i="0"
    isnum='^[0-9]+$'
    if [[ $1 =~ $isnum ]]; then
        i=$1
        shift 1
    fi
    run_helper nsenter -n -m -w -t "${CONTAINER_NS_PIDS[$i]}" "$@"

}

################
#   run_in_host_netns  #  Run args in host netns
################
function run_in_host_netns() {
    run_helper nsenter -n -m -w -t $HOST_NS_PID "$@"
}

#### Functions below are taken from podman and buildah and adapted to netavark.

################
#  run_helper  #  Invoke args, with timeout, using BATS 'run'
################
#
# Second, we use 'timeout' to abort (with a diagnostic) if something
# takes too long; this is preferable to a CI hang.
#
# Third, we log the command run and its output. This doesn't normally
# appear in BATS output, but it will if there's an error.
#
# Next, we check exit status. Since the normal desired code is 0,
# that's the default; but the expected_rc var can override:
#
#     expected_rc=125 run_helper nonexistent-subcommand
#     expected_rc=?   run_helper some-other-command       # let our caller check status
#
# Since we use the BATS 'run' mechanism, $output and $status will be
# defined for our caller.
#
function run_helper() {
    # expected_rc if unset set default to 0
    expected_rc="${expected_rc-0}"
    if [ "$expected_rc" == "?" ]; then
        expected_rc=
    fi
    # Remember command args, for possible use in later diagnostic messages
    MOST_RECENT_COMMAND="$*"

    # stdout is only emitted upon error; this echo is to help a debugger
    echo "$_LOG_PROMPT $*"

    # BATS hangs if a subprocess remains and keeps FD 3 open; this happens
    # if a process crashes unexpectedly without cleaning up subprocesses.
    run timeout --foreground -v --kill=10 10 "$@" 3>/dev/null
    # without "quotes", multiple lines are glommed together into one
    if [ -n "$output" ]; then
        echo "$output"
    fi
    if [ "$status" -ne 0 ]; then
        echo -n "[ rc=$status "
        if [ -n "$expected_rc" ]; then
            if [ "$status" -eq "$expected_rc" ]; then
                echo -n "(expected) "
            else
                echo -n "(** EXPECTED $expected_rc **) "
            fi
        fi
        echo "]"
    fi

    if [ "$status" -eq 124 ]; then
        if expr "$output" : ".*timeout: sending" >/dev/null; then
            # It's possible for a subtest to _want_ a timeout
            if [[ "$expected_rc" != "124" ]]; then
                echo "*** TIMED OUT ***"
                false
            fi
        fi
    fi

    if [ -n "$expected_rc" ]; then
        if [ "$status" -ne "$expected_rc" ]; then
            die "exit code is $status; expected $expected_rc"
        fi
    fi

    # unset
    unset expected_rc
}

#########
#  die  #  Abort with helpful message
#########
function die() {
    # FIXME: handle multi-line output
    echo "#/vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" >&2
    echo "#| FAIL: $*" >&2
    echo "#\\^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" >&2
    false
}

############
#  assert  #  Compare actual vs expected string; fail if mismatch
############
#
# Compares string (default: $output) against the given string argument.
# By default we do an exact-match comparison against $output, but there
# are two different ways to invoke us, each with an optional description:
#
#      xpect               "EXPECT" [DESCRIPTION]
#      xpect "RESULT" "OP" "EXPECT" [DESCRIPTION]
#
# The first form (one or two arguments) does an exact-match comparison
# of "$output" against "EXPECT". The second (three or four args) compares
# the first parameter against EXPECT, using the given OPerator. If present,
# DESCRIPTION will be displayed on test failure.
#
# Examples:
#
#   xpect "this is exactly what we expect"
#   xpect "${lines[0]}" =~ "^abc"  "first line begins with abc"
#
function assert() {
    local actual_string="$output"
    local operator='=='
    local expect_string="$1"
    local testname="$2"

    case "${#*}" in
    0) die "Internal error: 'assert' requires one or more arguments" ;;
    1 | 2) ;;
    3 | 4)
        actual_string="$1"
        operator="$2"
        expect_string="$3"
        testname="$4"
        ;;
    *) die "Internal error: too many arguments to 'assert'" ;;
    esac

    # Comparisons.
    # Special case: there is no !~ operator, so fake it via '! x =~ y'
    local not=
    local actual_op="$operator"
    if [[ $operator == '!~' ]]; then
        not='!'
        actual_op='=~'
    fi
    if [[ $operator == '=' || $operator == '==' ]]; then
        # Special case: we can't use '=' or '==' inside [[ ... ]] because
        # the right-hand side is treated as a pattern... and '[xy]' will
        # not compare literally. There seems to be no way to turn that off.
        if [ "$actual_string" = "$expect_string" ]; then
            return
        fi
    elif [[ $operator == '!=' ]]; then
        # Same special case as above
        if [ "$actual_string" != "$expect_string" ]; then
            return
        fi
    else
        if eval "[[ $not \$actual_string $actual_op \$expect_string ]]"; then
            return
        elif [ $? -gt 1 ]; then
            die "Internal error: could not process 'actual' $operator 'expect'"
        fi
    fi

    # Test has failed. Get a descriptive test name.
    if [ -z "$testname" ]; then
        testname="${MOST_RECENT_BUILDAH_COMMAND:-[no test name given]}"
    fi

    # Display optimization: the typical case for 'expect' is an
    # exact match ('='), but there are also '=~' or '!~' or '-ge'
    # and the like. Omit the '=' but show the others; and always
    # align subsequent output lines for ease of comparison.
    local op=''
    local ws=''
    if [ "$operator" != '==' ]; then
        op="$operator "
        ws=$(printf "%*s" ${#op} "")
    fi

    # This is a multi-line message, which may in turn contain multi-line
    # output, so let's format it ourself, readably
    local actual_split
    IFS=$'\n' read -rd '' -a actual_split <<<"$actual_string" || true
    printf "#/vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n" >&2
    printf "#|     FAIL: %s\n" "$testname" >&2
    printf "#| expected: %s'%s'\n" "$op" "$expect_string" >&2
    printf "#|   actual: %s'%s'\n" "$ws" "${actual_split[0]}" >&2
    local line
    for line in "${actual_split[@]:1}"; do
        printf "#|         > %s'%s'\n" "$ws" "$line" >&2
    done
    printf "#\\^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n" >&2
    false
}

#################
#  assert_json  #  Compare actual json vs expected string; fail if mismatch
#################
# assert_json works like assert except that it accepts one extra parameter,
# the jq query string.
# There are two different ways to invoke us, each with an optional description:
#
#      xpect               "JQ_QUERY"      "EXPECT" [DESCRIPTION]
#      xpect "JSON_STRING" "JQ_QUERY" "OP" "EXPECT" [DESCRIPTION]
# Important this function will overwrite $output, so if you need to use the value
# more than once you need to safe it in another variable.
function assert_json() {
    local actual_json="$output"
    local operator='=='
    local jq_query="$1"
    local expect_string="$2"
    local testname="$3"

    case "${#*}" in
    0 | 1) die "Internal error: 'assert_json' requires two or more arguments" ;;
    2 | 3) ;;
    4 | 5)
        actual_json="$1"
        jq_query="$2"
        operator="$3"
        expect_string="$4"
        testname="$5"
        ;;
    *) die "Internal error: too many arguments to 'assert_json'" ;;
    esac
    run_helper jq -r "$jq_query" <<<"$actual_json"
    assert "$output" "$operator" "$expect_string" "$testname"
}

##################
#  test_port_fw  # test port forwarding
##################
# test port forwarding
# by default this will create a ipv4 config with tcp as protocol
#
# The following arguments are supported, the order does not matter:
#     ip={4, 6, dual}
#     proto={tcp,udp,sctp} or some comma separated list of the protocols
#     hostip=$ip the ip which is used for binding on the host
#     hostport=$port the port which is binded on the host
#     containerport=$port the port which is binded in the container
#     range=$num >=1 specify a port range which will forward hostport+range ports
#     connectip=$ip the ip which is used to connect to in the ncat test
#     firewalld_reload={false,true} call firewall-cmd --reload to check for port rules
#
function test_port_fw() {
    local ipv4=true
    local ipv6=false
    local proto=tcp
    local host_ip=""
    local host_port=""
    local container_port=""
    local range=1
    local connect_ip=""
    local firewalld_reload=false

    # parse arguments
    while [[ "$#" -gt 0 ]]; do
        IFS='=' read -r arg value <<<"$1"
        case "$arg" in
        ip)
            case "$value" in
            4) ipv4=true ;;
            6)
                ipv6=true
                ipv4=false
                ;;
            dual) ipv6=true ;;
            *) die "unknown argument '$value' for ip=" ;;
            esac
            ;;
        proto)
            proto="$value"
            ;;
        hostip)
            host_ip="$value"
            ;;
        connectip)
            connect_ip="$value"
            ;;
        hostport)
            host_port="$value"
            ;;
        containerport)
            container_port="$value"
            ;;
        range)
            range="$value"
            ;;
        firewalld_reload)
            firewalld_reload="$value"
            ;;
        *) die "unknown argument for '$arg' test_port_fw" ;;
        esac
        shift
    done

    if [ -z "$host_port" ]; then
        host_port=$(random_port)
    fi

    if [ -z "$container_port" ]; then
        container_port=$(random_port)
    fi

    local container_id=$(random_string 64)
    local container_name="name-$(random_string 10)"

    local static_ips=""
    local subnets=""

    if [ $ipv4 = true ]; then
        ipv4_subnet=$(random_subnet)
        ipv4_gateway=$(gateway_from_subnet $ipv4_subnet)
        ipv4_container_ip=$(random_ip_in_subnet $ipv4_subnet)

        static_ips="\"$ipv4_container_ip\""
        subnets="{\"subnet\":\"$ipv4_subnet\",\"gateway\":\"$ipv4_gateway\"}"
    fi

    if [ $ipv6 = true ]; then
        ipv6_subnet=$(random_subnet 6)
        ipv6_gateway=$(gateway_from_subnet $ipv6_subnet)
        ipv6_container_ip=$(random_ip_in_subnet $ipv6_subnet)

        if [ $ipv4 = true ]; then
            # add comma for the json
            static_ips="$static_ips, "
            subnets="$subnets, "
        fi
        static_ips="$static_ips\"$ipv6_container_ip\""
        subnets="$subnets {\"subnet\":\"$ipv6_subnet\",\"gateway\":\"$ipv6_gateway\"}"
    fi

    read -r -d '\0' config <<EOF
{
  "container_id": "$container_id",
  "container_name": "$container_name",
  "port_mappings": [
    {
      "host_ip": "$host_ip",
      "container_port": $container_port,
      "host_port": $host_port,
      "range": $range,
      "protocol": "$proto"
    }
  ],
  "networks": {
    "podman1": {
      "static_ips": [
        $static_ips
      ],
      "interface_name": "eth0"
    }
  },
  "network_info": {
    "podman1": {
      "name": "podman1",
      "id": "ed82e3a703682a9c09629d3cf45c1f1e7da5b32aeff3faf82837ef4d005356e6",
      "driver": "bridge",
      "network_interface": "podman1",
      "subnets": [
        $subnets
      ],
      "ipv6_enabled": true,
      "internal": false,
      "dns_enabled": false,
      "ipam_options": {
        "driver": "host-local"
      }
    }
  }
}\0
EOF

    # echo the config here this is useful for debugging in case a test fails
    echo "$config"

    if [ $firewalld_reload = true ]; then
        setup_firewalld
        run_netavark_firewalld_reload
    fi

    run_netavark setup $(get_container_netns_path) <<<"$config"
    result="$output"

    if [ $firewalld_reload = true ]; then
        run_in_host_netns firewall-cmd --reload
        sleep 1
    fi

    # protocol can be a comma separated list of protocols names
    # split it into an array
    IFS=',' read -ra protocols <<<"$proto"

    for proto in "${protocols[@]}"; do

        # ports can be a range, we have to check the full range
        i=0
        while [ $i -lt $range ]; do
            ((cport = container_port + i))
            ((hport = host_port + i))

            if [ $ipv4 = true ]; then
                if [[ -z "$connect_ip" ]]; then
                    connect_ip=$ipv4_gateway
                    if [[ -n "$host_ip" ]]; then
                        connect_ip=$host_ip
                    fi
                fi

                run_nc_test "0" "$proto" $cport $connect_ip $hport
            fi


            if [ $ipv6 = true ]; then
                if [[ -z "$connect_ip" ]]; then
                    connect_ip=$ipv6_gateway
                    if [[ -n "$host_ip" ]]; then
                        connect_ip=$host_ip
                    fi
                fi

                run_nc_test "0" "$proto" $cport $connect_ip $hport
            fi

            ((i = i + 1))

        done

    done

    run_netavark teardown $(get_container_netns_path) <<<"$config"
}

#################
#  is_ipv6      # check if the given arg is a ipv6 address
#################
# Note that this only checks for a colon so it does not validate the ip address.
# This should only be used if you have a valid ip but do not know if it is ipv4 or ipv6.
function is_ipv6() {
    [[ "$1" == *":"* ]]
}

#################
#  is_ipv4      # check if the given arg is a ipv4 address
#################
# Note that this only checks for a dot so it does not validate the ip address.
# This should only be used if you have a valid ip but do not know if it is ipv4 or ipv6.
function is_ipv4() {
    [[ "$1" == *"."* ]]
}

#################
#  run_nc_test  # run ncat connection test between the namespaces
#################
# $1 == common nc args which are added to both the server and client nc command
# $2 == container port, the nc server will listen on it in the container ns
# $3 == connection ip, the ip address which is used by the client nc to connect to the server
# $4 == host port, the nc client will connect to this port
function run_nc_test() {
    local container_ns=$1
    local proto=$2
    local container_port=$3
    local connect_ip=$4
    local host_port=$5

    local nc_common_args=""
    exec {stdin}<>/dev/null

    case $proto in
    tcp) ;; # nothing to do (default)
    udp) nc_common_args=--udp ;;
    sctp)
        nc_common_args=--sctp
        # For some reason we have to attach a empty STDIN (not /dev/null and not something with data in it)
        # to the server only for the sctp proto otherwise it will just exit for weird reasons.
        # As such create a empty anonymous pipe to work around that.
        # https://github.com/nmap/nmap/issues/2829
        exec {stdin}<> <(:)
        ;;
    *) die "unknown port proto '$proto'" ;;
    esac

    if is_ipv4 "$connect_ip"; then
        nc_common_args="-4 $nc_common_args"
    fi
    if is_ipv6 "$connect_ip"; then
        nc_common_args="-6 $nc_common_args"
    fi

    nsenter -n -t "${CONTAINER_NS_PIDS[$container_ns]}" timeout --foreground -v --kill=10 5 \
        nc $nc_common_args -l -p $container_port &>"$NETAVARK_TMPDIR/nc-out" <&$stdin &

    # make sure to wait until port is bound otherwise test can flake
    # https://github.com/containers/netavark/issues/433
    if [ "$proto" = "tcp" ] || [ "$proto" = "udp" ]; then
        wait_for_port "${CONTAINER_NS_PIDS[$container_ns]}" $container_port $proto
    else
        # TODO add support for sctp port reading from /proc/net/sctp/eps,
        # for now just sleep
        sleep 0.5
    fi

    data=$(random_string)
    run_in_host_netns nc $nc_common_args $connect_ip $host_port <<<"$data"

    got=$(cat "$NETAVARK_TMPDIR/nc-out")
    assert "$got" == "$data" "ncat received data"

    # close the fd
    exec {stdin}>&-
}

#################
#  random_port  # get a random port number between 1-32768
#################
function random_port() {
    printf $(($RANDOM + 1))
}

###################
#  random_string  #  Pseudorandom alphanumeric string of given length
###################
function random_string() {
    local length=${1:-10}
    head /dev/urandom | tr -dc a-zA-Z0-9 | head -c$length
}

###################
#  random_subnet  # generate a random private subnet
###################
#
# by default it will return a 10.x.x.0/24 ipv4 subnet
# if "6" is given as first argument it will return a "fdx:x:x:x::/64" ipv6 subnet
function random_subnet() {
    if [[ "$1" == "6" ]]; then
        printf "fd%x:%x:%x:%x::/64" $((RANDOM % 256)) $((RANDOM % 65535)) $((RANDOM % 65535)) $((RANDOM % 65535))
    else
        printf "10.%d.%d.0/24" $((RANDOM % 256)) $((RANDOM % 256))
    fi
}

#########################
#  random_ip_in_subnet  # get a random from a given subnet
#########################
# the first arg must be an subnet created by random_subnet
# otherwise this function might return an invalid ip
function random_ip_in_subnet() {
    # first trim subnet
    local net_ip=${1%/*}
    local num=
    # if ip has colon it is ipv6
    if [[ "$net_ip" == *":"* ]]; then
        # make sure to not get 0 or 1
        num=$(printf "%x" $((RANDOM % 65533 + 2)))
    else
        # if ipv4 we have to trim the final 0
        net_ip=${net_ip%0}
        # make sure to not get 0, 1 or 255
        num=$(printf "%d" $((RANDOM % 252 + 2)))
    fi
    printf "$net_ip%s" $num
}

#########################
#  random_ip_in_subnet  # get the first ip from a given subnet
#########################
# the first arg must be an subnet created by random_subnet
# otherwise this function might return an invalid ip
function gateway_from_subnet() {
    # first trim subnet
    local net_ip=${1%/*}
    # set first ip in network as gateway
    local num=1
    # if ip has dor it is ipv4
    if [[ "$net_ip" == *"."* ]]; then
        # if ipv4 we have to trim the final 0
        net_ip=${net_ip%0}
    fi
    printf "$net_ip%s" $num
}

##############################
#  setup_sctp_kernel_module  #
##############################
# tries to load the sctp kernel module if possible
# otherwise it will skip the test
function setup_sctp_kernel_module() {
    modprobe sctp || skip "cannot load sctp kernel module"
}

#################################
#  add_dummy_interface_on_host  #
#################################
# create a dummy interface with the given name and subnet
# the first arg is the name
# the second arg is the subnet (optional)
function add_dummy_interface_on_host() {
    name="$1"
    ipaddr="$2"
    run_in_host_netns ip link add "$name" type dummy
    if [ -n "$ipaddr" ]; then
        run_in_host_netns ip addr add "$ipaddr" dev "$name"
    fi
    run_in_host_netns ip link set "$name" up
}


### Below functions are taken from podman system tests,
### see Stefano Brivio's commit  https://github.com/containers/podman/pull/16141/commits/ea4f168b3a6603991f2cbdc2dcfe6268a46bf1ba

# ipv6_to_procfs() - RFC 5952 IPv6 address text representation to procfs format
# $1:	Address in any notation described by RFC 5952
function ipv6_to_procfs() {
    local addr="${1}"

    # Add leading zero if missing
    case ${addr} in
        "::"*) addr=0"${addr}" ;;
    esac

    # Double colon can mean any number of all-zero fields. Expand to fill
    # as many colons as are missing. (This will not be a valid IPv6 form,
    # but we don't need it for long). E.g., 0::1 -> 0:::::::1
    case ${addr} in
        *"::"*)
            # All the colons in the address
            local colons
            colons=$(tr -dc : <<<$addr)
            # subtract those from a string of eight colons; this gives us
            # a string of two to six colons...
            local pad
            pad=$(sed -e "s/$colons//" <<<":::::::")
            # ...which we then inject in place of the double colon.
            addr=$(sed -e "s/::/::$pad/" <<<$addr)
            ;;
    esac

    # Print as a contiguous string of zero-filled 16-bit words
    # (The additional ":" below is needed because 'read -d x' actually
    # means "x is a TERMINATOR, not a delimiter")
    local group
    while read -d : group; do
        printf "%04X" "0x${group:-0}"
    done <<<"${addr}:"
}

# __ipv4_to_procfs() - Print bytes in hexadecimal notation reversing arguments
# $@:	IPv4 address as separate bytes
function __ipv4_to_procfs() {
    printf "%02X%02X%02X%02X" ${4} ${3} ${2} ${1}
}

# ipv4_to_procfs() - IPv4 address representation to big-endian procfs format
# $1:	Text representation of IPv4 address
function ipv4_to_procfs() {
    IFS='.' __ipv4_to_procfs ${1}
}

# port_is_bound() - Check if TCP or UDP port is bound for a given address
# $1:   Netns PID
# $2:	Port number
# $3:	Optional protocol, or optional IPv4 or IPv6 address, default: tcp
# $4:	Optional IPv4 or IPv6 address, or optional protocol, default: any
function port_is_bound() {
    local pid=$1
    local port=${2?Usage: port_is_bound PORT [tcp|udp] [ADDRESS]}

    if   [ "${3}" = "tcp" ] || [ "${3}" = "udp" ]; then
        local address="${4}"
        local proto="${3}"
    elif [ "${4}" = "tcp" ] || [ "${4}" = "udp" ]; then
        local address="${3}"
        local proto="${4}"
    else
        local address="${3}"	# Might be empty
        local proto="tcp"
    fi

    port=$(printf %04X ${port})
    case "${address}" in
    *":"*)
        nsenter -n -t $pid grep -e "^[^:]*: $(ipv6_to_procfs "${address}"):${port} .*" \
             -e "^[^:]*: $(ipv6_to_procfs "::0"):${port} .*"        \
             -q "/proc/net/${proto}6"
        ;;
    *"."*)
        nsenter -n -t $pid grep -e "^[^:]*: $(ipv4_to_procfs "${address}"):${port}"    \
             -e "^[^:]*: $(ipv4_to_procfs "0.0.0.0"):${port}"       \
             -q "/proc/net/${proto}"
        ;;
    *)
        # No address: check both IPv4 and IPv6, for any bound address
        nsenter -n -t $pid grep "^[^:]*: [^:]*:${port} .*" -q "/proc/net/${proto}6" || \
        nsenter -n -t $pid grep "^[^:]*: [^:]*:${port} .*" -q "/proc/net/${proto}"
        ;;
    esac
}

# port_is_free() - Check if TCP or UDP port is free to bind for a given address
# $1:   Netns PID
# $2:	Port number
# $3:	Optional protocol, or optional IPv4 or IPv6 address, default: tcp
# $4:	Optional IPv4 or IPv6 address, or optional protocol, default: any
function port_is_free() {
    ! port_is_bound ${@}
}

# wait_for_port() - Return when port is binded
# $1:   Netns PID
# $2:	Port number
# $3:	Optional protocol, or optional IPv4 or IPv6 address, default: tcp
# $4:	Optional IPv4 or IPv6 address, or optional protocol, default: any
# $5:	Optional timeout, 5 seconds if not given
function wait_for_port() {
    local pid=$1
    local port=$2
    local proto=$3
    local host=$4
    local _timeout=${5:-5}

    # Wait
    while [ $_timeout -gt 0 ]; do
        port_is_bound ${pid} ${port} ${proto} ${host} && return
        sleep 1
        _timeout=$(( $_timeout - 1 ))
    done

    die "Timed out waiting for $host:$port"
}

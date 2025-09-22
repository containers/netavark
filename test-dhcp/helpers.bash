# -*- bash -*-

CONTAINER_MAC=
DNSMASQ_PIDFILE=
NS_NAME=
NS_PATH=
PROXY_PID=
SUBNET_CIDR=
TMP_TESTDIR=


# Netavark binary to run
NETAVARK=${NETAVARK:-./bin/netavark}

TESTSDIR=${TESTSDIR:-$(dirname ${BASH_SOURCE})}

# export RUST_BACKTRACE so that we get a helpful stack trace
export RUST_BACKTRACE=full


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

################
#  run_in_container_netns  #  Run args in container netns
################
#
function run_in_container_netns() {
    run_helper ip netns exec "${NS_NAME}" "$@"
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

function setup() {
  echo "### Setup ###"
  NS_PATH="/var/run/netns/$(random_string)"
  NS_NAME=$(basename "$NS_PATH")
  ip netns add "${NS_NAME}"
  #If the test name contains the word "ipv6", it automatically calls 
  #basic_setup 6 to create an IPv6 environment. Otherwise, it defaults to 
  #basic_setup 4 for IPv4. This is the key change that allows new 
  #IPv6 tests to work without breaking existing ones.
  if [[ "$BATS_TEST_DESCRIPTION" == *"ipv6"* ]]; then
      basic_setup 6
  else
      basic_setup 4
  fi
}

function teardown() {
  echo "### Teardown ###"
  basic_teardown
  ip netns delete "${NS_NAME}"
}

function basic_teardown(){
  # TODO
  # Make dynamic
  stop_proxy
  remove_veth "veth0" "br0"
  remove_bridge "br0"
  stop_dhcp "$DNSMASQ_PID"
  run_in_container_netns ip link set lo down
  rm -rf "$TMP_TESTDIR"
}


function basic_setup() {
  local version=${1:-4}
  SUBNET_CIDR=$(random_subnet "$version")
  set_tmpdir
  add_bridge "br0"
  add_veth "veth0" "br0"
  run_in_container_netns ip -j link show veth0
  CONTAINER_MAC=$(echo "$output" | jq -r .[0].address)
  add_veth "veth1" "br0"
  # Assign a link-local IPv6 address to the veth1 interface in the host namespace
  #run_in_container_netns ip addr add fe80::1/64 dev veth1
  #we need to give some time for the DAD process to finish 
  sleep 2
  run_in_container_netns ip link set lo up
  run_dhcp "$version"
  start_proxy
}

#
# add_bridge <name>
#
function add_bridge() {
  local bridge_name="$1"
  br_cidr=$(gateway_from_subnet "$SUBNET_CIDR")
  run_in_container_netns ip link add $bridge_name type bridge
  run_in_container_netns ip addr add $br_cidr dev $bridge_name
  run_in_container_netns ip link set $bridge_name up
}

#
# remove_bridge <name>
#
function remove_bridge() {
  local bridge_name="$1"
  run_in_container_netns ip link set "$bridge_name" down
  # shellcheck disable=SC2086
  run_in_container_netns ip link del $bridge_name
}

#
# remove_veth veth0 br0
#
function remove_veth() {
  local veth_name="$1"
  local bridge_name="$2"
  local veth_br_name="${veth_name}br"

  run_in_container_netns ip link del "$veth_br_name"
}

#
# add_veth veth0 br0
#
function add_veth() {
  local veth_name="$1"
  local bridge_name="$2"
  local veth_br_name="${veth_name}br"
  run_in_container_netns ip link add "$veth_br_name" type veth peer name "$veth_name"
  run_in_container_netns ip link set "$veth_br_name" master "$bridge_name"
  run_in_container_netns ip link set "$veth_br_name" up
  run_in_container_netns ip link set "$veth_name" up
}

#
# run_dhcp <ip_version>
#
function run_dhcp() {
    local version=${1:-4}
    local gw
    gw=$(gateway_from_subnet "$SUBNET_CIDR")
    local dnsmasq_config=""

    if [ "$version" == "6" ]; then
        # Get the IPv6 network prefix from the full CIDR.
        # For example, turn "fd1d:5139:5cb5:1a99::/64" into "fd1d:5139:5cb5:1a99::"
        local stripped_subnet_v6
        stripped_subnet_v6=$(echo "$SUBNET_CIDR" | sed 's#::/64#::#')

        read -r -d '\0' dnsmasq_config <<EOF
interface=br0
port=0
enable-ra
# Use the dynamically generated subnet for the DHCPv6 range
dhcp-range=${stripped_subnet_v6}100,${stripped_subnet_v6}200,12h
dhcp-option=option6:dns-server,[::1]
log-facility=/var/log/dnsmasq.log
log-async
log-queries
log-dhcp
\0
EOF
    else
        local stripped_subnet
        stripped_subnet=$(strip_last_octet_from_subnet)
        read -r -d '\0' dnsmasq_config <<EOF
interface=br0
port=0
dhcp-range=${stripped_subnet}50,${stripped_subnet}59,255.255.255.0,2m
dhcp-option=3,$gw
dhcp-option=6,$gw
log-facility=/var/log/dnsmasq.log
log-async
log-queries
log-dhcp
\0
EOF
    fi

    local dnsmasq_testdir="${TMP_TESTDIR}/dnsmasq"
    mkdir -p "$dnsmasq_testdir"
    echo "$dnsmasq_config" > "$dnsmasq_testdir/test.conf"

    echo "--- dnsmasq config files in $dnsmasq_testdir ---"
    for file in "$dnsmasq_testdir"/*; do
        if [ -f "$file" ]; then
            echo "--- Contents of $file ---"
            cat "$file"
        fi
    done
    echo "------------------------------------------------"

    echo "--- Initial contents of $TMP_TESTDIR/dnsmasq.log ---"
    # touch the file to make sure it exists
    touch "$TMP_TESTDIR/dnsmasq.log"
    cat "$TMP_TESTDIR/dnsmasq.log"
    echo "----------------------------------------------------"
    #ip netns exec "${NS_NAME}" dnsmasq --log-debug --log-dhcp --no-daemon --conf-dir "${dnsmasq_testdir}" --conf-file= -
    ip netns exec "${NS_NAME}" dnsmasq --log-debug --log-dhcp --no-daemon --conf-dir "${dnsmasq_testdir}" &>>"$TMP_TESTDIR/dnsmasq.log" &
    #ip netns exec "${NS_NAME}" dnsmasq --log-debug --log-dhcp --no-daemon --conf-dir "${dnsmasq_testdir}" --conf-file=/dev/null &>>"$TMP_TESTDIR/dnsmasq.log" &
    #ip netns exec "${NS_NAME}" dnsmasq --log-debug --log-dhcp --no-daemon -C "${dnsmasq_conf_file}" &>>"$TMP_TESTDIR/dnsmasq.log" &
    DNSMASQ_PID=$!
}

#
#  stop_dhcp 27231
#
function stop_dhcp() {
  echo "dnsmasq log:"
  cat "${TMP_TESTDIR}/dnsmasq.log"
  kill -9 "$DNSMASQ_PID"
}

function start_proxy() {
  RUST_LOG=info ip netns exec "$NS_NAME" $NETAVARK dhcp-proxy --dir "$TMP_TESTDIR" --uds "$TMP_TESTDIR" &>"$TMP_TESTDIR/proxy.log" &
  PROXY_PID=$!
}

function stop_proxy(){
  echo "proxy log:"
  cat "$TMP_TESTDIR/proxy.log"
  kill -9 $PROXY_PID
}


function run_setup(){
  local conf=$1
  NS_PATH=$(echo "${conf}" | jq -r .ns_path)
  NS_NAME=$(basename "$NS_PATH")
  echo "$conf"  > "$TMP_TESTDIR/setup.json"
  run_client "setup" "${TMP_TESTDIR}/setup.json"
}

function run_teardown(){
  local conf=$1
  echo "$conf"  > "$TMP_TESTDIR/teardown.json"
  run_client "teardown" "${TMP_TESTDIR}/teardown.json"
}

# The first arg is the incoming config from "netavark"
###################
#  run_client # use test client
###################
function run_client(){
  local verb=$1
  local conf=$2
  run_in_container_netns "./bin/netavark-dhcp-proxy-client" --uds "$TMP_TESTDIR/nv-proxy.sock" -f "${conf}" "${verb}"
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
#  gateway_from_subnet  # get the first ip from a given subnet
#########################
# the first arg must be an subnet created by random_subnet
# otherwise this function might return an invalid ip
function gateway_from_subnet() {
   local num=1
    net_ip=$(strip_last_octet_from_subnet "$SUBNET_CIDR")
    printf "$net_ip%s" $num
}



function strip_last_octet_from_subnet() {
    # first trim subnet
    local net_ip=${SUBNET_CIDR%/*}
    # set first ip in network as gateway
    # if ip has dor it is ipv4
    if [[ "$net_ip" == *"."* ]]; then
        # if ipv4 we have to trim the final 0
        net_ip=${net_ip%0}
    fi
    printf "$net_ip"
}


#########################
#  generate_mac # random generated mac address
#########################
# No args required
function generate_mac(){
  openssl rand -hex 6 | sed 's/\(..\)/\1:/g; s/.$//'
}

function set_tmpdir(){
  TMP_TESTDIR=$(mktemp -d /tmp/nv-proxyXXX)
}

###################
#  random_string  #  Pseudorandom alphanumeric string of given length
###################
function random_string() {
    local length=${1:-10}
    head /dev/urandom | tr -dc a-zA-Z0-9 | head -c$length
}

function has_ip() {
  local container_ip=$1
  local interface=$2
  run_in_container_netns ip -j address show $interface
  addr_info=$(jq '.[0].addr_info' <<<"$output")
  assert "$addr_info" =~ "$container_ip" "ip not set on interface $interface"
}

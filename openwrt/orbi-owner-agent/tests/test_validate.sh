#!/bin/sh
# Offline unit tests for validate.sh.  Does not call ubus or touch UCI.
# Runs the validators against a fixed in-script UCI mock.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LIB="$HERE/../files/usr/share/orbi-owner-agent/lib"

# Mock the UCI helpers from common.sh so we do not need a real uci binary.
uci_get_default() { case "$1" in
    agent_main_enabled)       echo "${MOCK_ENABLED:-1}" ;;
    agent_main_audit_log)     echo "${MOCK_AUDIT_LOG:-/tmp/t.log}" ;;
    agent_main_audit_max_bytes) echo 262144 ;;
    agent_main_max_tail_lines)  echo 500 ;;
    *) echo "${2:-}" ;;
esac; }
uci_list_get() { case "$1" in
    agent_main_allowed_bridge) echo "${MOCK_BRIDGES:-br-lan}" ;;
    policy_vlan_reserved_id)   echo "${MOCK_RESERVED:-1 4093 4094}" ;;
    *) echo "" ;;
esac; }

. "$LIB/validate.sh"

PASS=0
FAIL=0
fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }
ok()   { PASS=$((PASS+1)); }

# valid_int
valid_int 1        && ok || fail "valid_int 1"
valid_int 1234567  && fail "valid_int 1234567 (too long)" || ok
valid_int ""       && fail "valid_int empty"              || ok
valid_int abc      && fail "valid_int abc"                || ok
valid_int "1 2"    && fail "valid_int spaces"             || ok

# valid_bool
valid_bool 0      && ok || fail "valid_bool 0"
valid_bool true   && ok || fail "valid_bool true"
valid_bool yes    && fail "valid_bool yes (not accepted)" || ok

# valid_vlan_id
valid_vlan_id 1     && fail "valid_vlan_id 1 (too low)" || ok
valid_vlan_id 2     && ok || fail "valid_vlan_id 2"
valid_vlan_id 100   && ok || fail "valid_vlan_id 100"
valid_vlan_id 4094  && ok || fail "valid_vlan_id 4094"
valid_vlan_id 4095  && fail "valid_vlan_id 4095 (too high)" || ok
valid_vlan_id -1    && fail "valid_vlan_id -1"          || ok
valid_vlan_id abc   && fail "valid_vlan_id abc"         || ok

# is_reserved_vlan_id
is_reserved_vlan_id 4093 && ok || fail "is_reserved_vlan_id 4093"
is_reserved_vlan_id 4094 && ok || fail "is_reserved_vlan_id 4094"
is_reserved_vlan_id 1    && ok || fail "is_reserved_vlan_id 1"
is_reserved_vlan_id 100  && fail "is_reserved_vlan_id 100 (not reserved)" || ok

# valid_vlan_name
valid_vlan_name owner_a       && ok || fail "valid_vlan_name owner_a"
valid_vlan_name owner_12345678 && ok || fail "valid_vlan_name owner_12345678"
valid_vlan_name owner_         && fail "valid_vlan_name owner_ empty tail" || ok
valid_vlan_name owner_123456789 && fail "valid_vlan_name owner_123456789 (too long)" || ok
valid_vlan_name owner_a.b      && fail "valid_vlan_name has dot" || ok
valid_vlan_name owner_A        && fail "valid_vlan_name uppercase" || ok
valid_vlan_name "owner_a b"    && fail "valid_vlan_name space" || ok
valid_vlan_name "owner_$(printf '\n')" && fail "valid_vlan_name newline" || ok
valid_vlan_name "owner_;id"    && fail "valid_vlan_name semicolon" || ok

# valid_bridge
valid_bridge br-lan         && ok || fail "valid_bridge br-lan (allowed)"
valid_bridge br-guest       && fail "valid_bridge br-guest (not allowed)" || ok
valid_bridge "br-lan;id"    && fail "valid_bridge shellchar" || ok
valid_bridge ""             && fail "valid_bridge empty"     || ok

# Longer custom bridge allowlist
MOCK_BRIDGES="br-lan br-ownr1"
valid_bridge br-ownr1       && ok || fail "valid_bridge br-ownr1 (second allowed)"

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]

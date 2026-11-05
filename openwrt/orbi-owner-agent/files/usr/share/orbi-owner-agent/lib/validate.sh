# orbi-owner-agent: input validation.
# Every validator returns 0 on valid, non-zero otherwise.
# Caps enforce bounded input even before regex evaluates.

valid_int() {
    v="${1:-}"
    [ -z "$v" ] && return 1
    case ${#v} in
        1|2|3|4|5|6) : ;;
        *) return 1 ;;
    esac
    case "$v" in
        *[!0-9]*) return 1 ;;
    esac
    return 0
}

valid_bool() {
    v="${1:-}"
    case "$v" in
        0|1|true|false) return 0 ;;
    esac
    return 1
}

valid_vlan_id() {
    v="${1:-}"
    valid_int "$v" || return 1
    if [ "$v" -lt 2 ]; then return 1; fi
    if [ "$v" -gt 4094 ]; then return 1; fi
    return 0
}

is_reserved_vlan_id() {
    v="${1:-}"
    for r in $(uci_list_get policy_vlan_reserved_id); do
        [ "$r" = "$v" ] && return 0
    done
    return 1
}

# Allow "owner_" followed by 1-8 lowercase letters/digits.
valid_vlan_name() {
    v="${1:-}"
    [ -z "$v" ] && return 1
    [ ${#v} -gt 14 ] && return 1
    case "$v" in
        owner_[a-z0-9]) : ;;
        owner_[a-z0-9]*) : ;;
        *) return 1 ;;
    esac
    # Strip prefix and ensure the tail is 1..8 chars of [a-z0-9]
    tail="${v#owner_}"
    [ -z "$tail" ] && return 1
    [ ${#tail} -gt 8 ] && return 1
    case "$tail" in
        *[!a-z0-9]*) return 1 ;;
    esac
    return 0
}

valid_bridge() {
    v="${1:-}"
    [ -z "$v" ] && return 1
    [ ${#v} -gt 16 ] && return 1
    case "$v" in
        *[!a-zA-Z0-9_-]*) return 1 ;;
    esac
    for b in $(uci_list_get agent_main_allowed_bridge); do
        [ "$b" = "$v" ] && return 0
    done
    return 1
}

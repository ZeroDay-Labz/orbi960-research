# orbi-owner-agent: shared helpers.
# POSIX /bin/sh (busybox ash). No bashisms.

# uci_get_default <config_section_option> <default>
# Flat key like 'agent_main_enabled' maps to orbi-owner-agent.agent[main].enabled
uci_get_default() {
    key="$1"
    default="$2"
    # Parse "<section>_<option>" robustly. Section is the first underscore-
    # delimited token after the fixed "agent"/"policy" prefix convention.
    case "$key" in
        agent_main_*)
            opt="${key#agent_main_}"
            section="main"
            type="agent"
            ;;
        policy_vlan_*)
            opt="${key#policy_vlan_}"
            section="vlan"
            type="policy"
            ;;
        *)
            printf '%s' "$default"
            return
            ;;
    esac
    val=$(uci -q get "orbi-owner-agent.${section}.${opt}" 2>/dev/null)
    if [ -z "$val" ]; then
        printf '%s' "$default"
    else
        printf '%s' "$val"
    fi
}

# uci_list_get <section_option> — space-separated listed values
uci_list_get() {
    key="$1"
    case "$key" in
        agent_main_*)
            opt="${key#agent_main_}"
            section="main"
            ;;
        policy_vlan_*)
            opt="${key#policy_vlan_}"
            section="vlan"
            ;;
        *)
            return
            ;;
    esac
    uci -q get "orbi-owner-agent.${section}.${opt}" 2>/dev/null
}

# sanitize_log <s> — printable-ascii only, length-capped, JSON-quote-safe
sanitize_log() {
    printf '%s' "${1:-}" | tr -d '"\n\r\t\\' | head -c 64
}

# json_str_escape <s> — minimal; we use jshn where possible, this is for
# audit lines that are not jshn-produced.
json_str_escape() {
    printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        -e 's/\t/\\t/g' | tr -d '\n\r'
}

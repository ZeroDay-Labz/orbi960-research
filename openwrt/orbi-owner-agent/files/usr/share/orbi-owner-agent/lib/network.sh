# orbi-owner-agent: network helpers.
# All functions populate the current jshn object; caller invoked json_init.

network_summary_to_jshn() {
    json_add_array interfaces
    # Iterate over interfaces via /sys/class/net (no caller input).
    for iface_path in /sys/class/net/*; do
        iface=$(basename "$iface_path")
        # Filter noise.
        case "$iface" in
            lo|bonding_masters) continue ;;
        esac
        oper=$(cat "$iface_path/operstate" 2>/dev/null)
        mtu=$(cat "$iface_path/mtu" 2>/dev/null)
        kind=$(cat "$iface_path/uevent" 2>/dev/null | awk -F= '/^DEVTYPE=/ {print $2}')
        [ -z "$kind" ] && kind="unknown"

        json_add_object ""
        json_add_string name "$iface"
        json_add_string operstate "${oper:-unknown}"
        json_add_int mtu "${mtu:-0}"
        json_add_string kind "$kind"

        # VLAN parent, if any
        if [ -L "$iface_path/upper_"* ] 2>/dev/null; then :; fi
        vlan_file="/proc/net/vlan/$iface"
        if [ -r "$vlan_file" ]; then
            vlan_id=$(awk '/VID:/ {print $3}' "$vlan_file" 2>/dev/null)
            vlan_parent=$(awk '/Device:/ {print $2}' "$vlan_file" 2>/dev/null)
            if [ -n "$vlan_id" ]; then
                json_add_int vlan_id "$vlan_id"
            fi
            if [ -n "$vlan_parent" ]; then
                json_add_string vlan_parent "$vlan_parent"
            fi
        fi

        # Bridge membership (which bridge is this port on)
        if [ -L "$iface_path/master" ]; then
            master_target=$(readlink "$iface_path/master" 2>/dev/null)
            master_name=$(basename "$master_target")
            json_add_string bridge_master "$master_name"
        fi

        json_close_object
    done
    json_close_array
}

# List 802.1Q VLAN interfaces. Reads /proc/net/vlan/config, which is a
# plain-text table emitted by the kernel 8021q module.
vlan_list_to_jshn() {
    json_add_array vlans
    if [ -r /proc/net/vlan/config ]; then
        # Skip first two header lines of /proc/net/vlan/config
        tail -n +3 /proc/net/vlan/config 2>/dev/null | while IFS='|' read -r name vid parent; do
            n=$(printf '%s' "$name" | tr -d ' \t')
            v=$(printf '%s' "$vid"  | tr -d ' \t')
            p=$(printf '%s' "$parent" | tr -d ' \t')
            [ -z "$n" ] && continue
            json_add_object ""
            json_add_string name "$n"
            json_add_int id   "${v:-0}"
            json_add_string parent "$p"
            json_close_object
        done
    fi
    json_close_array
}

# vlan_create <vlan_id> <owner_name> <bridge>
# Creates two UCI network sections, commits atomically. Returns 0 on success.
vlan_create() {
    vid="$1"
    name="$2"
    bridge="$3"

    # UCI section names must be alphanumeric+underscore; validated upstream.
    # We author sections under the owner namespace so they are easy to find
    # and remove later.
    ucidev="owner_v${vid}"
    uciif="$name"

    # Guard: do not clobber an existing section that is not ours.
    existing_dev=$(uci -q get "network.${ucidev}")
    existing_if=$(uci -q get "network.${uciif}")
    if [ -n "$existing_dev" ] && [ "$existing_dev" != "device" ]; then
        return 1
    fi
    if [ -n "$existing_if" ] && [ "$existing_if" != "interface" ]; then
        return 1
    fi

    # Resolve the physical device for the bridge. We only create VLAN-on-
    # physical; attaching to bridges is a separate step owner can do via
    # vendor mechanism. Here we add the 802.1Q sub-interface to the bridge
    # that was allowlisted, mirroring NETGEAR's own stock pattern where
    # eth0.4093 is attached to br-guest.
    #
    # Pick the first bridge member that carries vendor VLANs (or if none,
    # default to eth0). This is a conservative default that matches live
    # topology on this firmware.
    parent="$(default_vlan_parent_for "$bridge")"
    [ -z "$parent" ] && return 1

    # Use discrete uci argv, never a shell template with caller input.
    if ! uci -q set "network.${ucidev}=device"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${ucidev}.name=${parent}.${vid}"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${ucidev}.type=8021q"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${ucidev}.ifname=${parent}"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${ucidev}.vid=${vid}"; then uci -q revert network; return 1; fi

    if ! uci -q set "network.${uciif}=interface"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${uciif}.proto=none"; then uci -q revert network; return 1; fi
    if ! uci -q set "network.${uciif}.ifname=${parent}.${vid}"; then uci -q revert network; return 1; fi

    if ! uci -q commit network; then uci -q revert network; return 1; fi
    return 0
}

# vlan_delete <owner_name>
vlan_delete() {
    name="$1"
    # Find the matching device section (name convention: owner_v<id>)
    ifname=$(uci -q get "network.${name}.ifname")
    if [ -z "$ifname" ]; then
        return 1
    fi
    vid="${ifname##*.}"
    if ! valid_int "$vid"; then
        return 1
    fi
    ucidev="owner_v${vid}"

    if ! uci -q delete "network.${name}" 2>/dev/null; then uci -q revert network; return 1; fi
    uci -q delete "network.${ucidev}" 2>/dev/null
    if ! uci -q commit network; then uci -q revert network; return 1; fi
    return 0
}

default_vlan_parent_for() {
    bridge="$1"
    # Walk /sys/class/net/<bridge>/brif/* and pick the first non-VLAN member
    # whose name matches eth[0-9]+ — the NETGEAR pattern is to tag eth0..3
    # into guest VLAN 4093 alongside the existing stock config.
    brif_dir="/sys/class/net/${bridge}/brif"
    if [ -d "$brif_dir" ]; then
        for m in "$brif_dir"/*; do
            mn=$(basename "$m")
            case "$mn" in
                eth[0-9]) printf '%s' "$mn"; return ;;
            esac
        done
    fi
    # Fallback (should not happen if bridge is allowlisted and populated)
    printf '%s' "eth0"
}

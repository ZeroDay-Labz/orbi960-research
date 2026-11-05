# orbi-owner-agent: audit logger.
# Emits one line per call to the audit log path. Rotates when size exceeded.

audit_log() {
    method="${1:-unknown}"
    args_json="${2:-{}}"
    status="${3:-?}"
    code="${4:-0}"

    log_path=$(uci_get_default agent_main_audit_log /tmp/orbi-owner-agent.log)
    max_bytes=$(uci_get_default agent_main_audit_max_bytes 262144)

    # Rotate (truncate) if oversized.
    if [ -f "$log_path" ]; then
        size=$(wc -c < "$log_path" 2>/dev/null)
        if [ -n "$size" ] && [ "$size" -gt "$max_bytes" ]; then
            : > "$log_path"
        fi
    fi

    # ISO-8601 UTC timestamp (busybox date supports -u).
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    # caller_uid: rpcd invokes us as root; we log the effective uid for
    # paper-trail transparency.
    uid=$(id -u 2>/dev/null)
    # args_json is already JSON-safe (produced by our own code, not caller).
    printf '%s method=%s caller_uid=%s args=%s result=%s code=%s\n' \
        "${ts:-unknown}" "$method" "${uid:-?}" "$args_json" \
        "$status" "$code" >> "$log_path" 2>/dev/null || true
}

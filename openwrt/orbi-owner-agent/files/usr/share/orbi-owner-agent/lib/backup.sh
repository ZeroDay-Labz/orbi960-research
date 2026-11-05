# orbi-owner-agent: config backup helper.
# Produces a tarball of owner-authored config and streams it base64-encoded.

backup_tarball_base64() {
    tmp_tar=$(mktemp /tmp/owner-backup.XXXXXX.tar 2>/dev/null)
    [ -z "$tmp_tar" ] && return 1

    # Explicit allowlist of paths. No caller input.
    paths="/etc/config/orbi-owner-agent"
    if [ -r /etc/config/network ]; then
        paths="$paths /etc/config/network"
    fi

    # tar with explicit argv; no shell interpolation of caller content.
    if ! tar -cf "$tmp_tar" $paths 2>/dev/null; then
        rm -f "$tmp_tar"
        return 1
    fi

    if [ ! -s "$tmp_tar" ]; then
        rm -f "$tmp_tar"
        return 1
    fi

    base64 "$tmp_tar" 2>/dev/null | tr -d '\n'
    rm -f "$tmp_tar"
    return 0
}

#!/bin/sh
# Offline structural checks on the package source tree.  No compilation,
# no device contact.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE/.."

FAIL=0
fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }

# All expected files exist.
for f in \
    Makefile \
    LICENSE \
    files/usr/libexec/rpcd/orbi-owner-agent \
    files/usr/share/rpcd/acl.d/orbi-owner-agent.json \
    files/usr/share/orbi-owner-agent/lib/common.sh \
    files/usr/share/orbi-owner-agent/lib/validate.sh \
    files/usr/share/orbi-owner-agent/lib/network.sh \
    files/usr/share/orbi-owner-agent/lib/backup.sh \
    files/usr/share/orbi-owner-agent/lib/audit.sh \
    files/usr/share/orbi-owner-agent/VERSION \
    files/etc/config/orbi-owner-agent \
    files/etc/init.d/orbi-owner-agent \
    files/etc/uci-defaults/80-orbi-owner-agent \
    docs/architecture.md \
    docs/security-model.md
do
    [ -r "$ROOT/$f" ] || fail "missing $f"
done

# Shell scripts parse under sh -n (busybox ash dialect).
for f in \
    files/usr/libexec/rpcd/orbi-owner-agent \
    files/usr/share/orbi-owner-agent/lib/common.sh \
    files/usr/share/orbi-owner-agent/lib/validate.sh \
    files/usr/share/orbi-owner-agent/lib/network.sh \
    files/usr/share/orbi-owner-agent/lib/backup.sh \
    files/usr/share/orbi-owner-agent/lib/audit.sh \
    files/etc/init.d/orbi-owner-agent \
    files/etc/uci-defaults/80-orbi-owner-agent
do
    if ! /bin/sh -n "$ROOT/$f" 2>&1; then
        fail "$f fails /bin/sh -n syntax check"
    fi
done

# ACL JSON parses.
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; json.load(open('$ROOT/files/usr/share/rpcd/acl.d/orbi-owner-agent.json'))" \
        || fail "ACL JSON invalid"
elif command -v jq >/dev/null 2>&1; then
    jq -e . "$ROOT/files/usr/share/rpcd/acl.d/orbi-owner-agent.json" >/dev/null \
        || fail "ACL JSON invalid"
fi

# Executable bits.
for f in \
    files/usr/libexec/rpcd/orbi-owner-agent \
    files/etc/init.d/orbi-owner-agent \
    files/etc/uci-defaults/80-orbi-owner-agent
do
    [ -x "$ROOT/$f" ] || fail "$f should be executable"
done

# No dangerous keywords (word-boundary where the term has a plain form).
# Flag only command-usage, not substrings in comments/identifiers.
for grep_target in '\beval[[:space:]]' '\bsystem(' '\bpopen(' '\bcurl[[:space:]]' '\bwget[[:space:]]'; do
    if grep -nE -R "$grep_target" "$ROOT/files" >/dev/null 2>&1; then
        echo "note: '$grep_target' appears in source — audit by hand"
        grep -nE -R "$grep_target" "$ROOT/files"
    fi
done

echo
echo "FAIL=$FAIL"
[ "$FAIL" -eq 0 ]

#!/bin/sh
# Offline integration tests that invoke the plugin in a controlled env.
# The plugin reads from UCI and from /usr/share/orbi-owner-agent/lib/*,
# so we stage a temporary install root and run against it.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE/../files"
PLUGIN="$ROOT/usr/libexec/rpcd/orbi-owner-agent"

if [ ! -x "$PLUGIN" ]; then
    echo "plugin not executable at $PLUGIN"
    exit 2
fi

# `list` verb must always succeed and produce valid JSON that enumerates
# every method the ACL exposes.
echo "-- list verb --"
out=$("$PLUGIN" list 2>&1)
rc=$?
if [ "$rc" != "0" ]; then
    echo "list rc=$rc out=$out"
    exit 1
fi
echo "$out" | grep -q '"vlan_create"' || { echo "list missing vlan_create"; exit 1; }
echo "$out" | grep -q '"audit_tail"'  || { echo "list missing audit_tail";  exit 1; }
echo "$out" | grep -q '"backup"'      || { echo "list missing backup";      exit 1; }

# Unknown verb must produce err JSON and exit 0 (rpcd pattern).
echo "-- unknown verb --"
out=$("$PLUGIN" nope 2>&1)
echo "$out" | grep -q '"code":"ERR_UNKNOWN_VERB"' || { echo "unknown verb: $out"; exit 1; }

# Unknown method must produce err JSON and exit 0.  Must run with uci
# available in some form; on a Fedora dev host uci is absent, so we skip
# the deeper call paths here.  Offline we can still check the plugin's
# routing for the unknown-method branch using `uci` stubbed to return
# non-zero on the enable check (so the agent reports ERR_DISABLED), OR
# we export MOCK_ENABLED=1 and shim uci below.
echo "-- unknown method (shimmed uci) --"
tmpdir=$(mktemp -d)
cat > "$tmpdir/uci" <<'EOF'
#!/bin/sh
# Minimal uci shim for tests.
case "$*" in
    "-q get orbi-owner-agent.main.enabled") echo 1 ;;
    "-q get orbi-owner-agent.main.audit_log") echo "/tmp/orbi-owner-agent-test.log" ;;
    "-q get orbi-owner-agent.main.audit_max_bytes") echo 262144 ;;
    "-q get orbi-owner-agent.main.max_tail_lines") echo 500 ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$tmpdir/uci"
PATH="$tmpdir:$PATH" "$PLUGIN" call does_not_exist </dev/null > "$tmpdir/out" 2>&1
grep -q '"code":"ERR_UNKNOWN_METHOD"' "$tmpdir/out" || { echo "unknown method: $(cat "$tmpdir/out")"; rm -rf "$tmpdir"; exit 1; }

echo "OK — plugin interface tests pass"
rm -rf "$tmpdir"

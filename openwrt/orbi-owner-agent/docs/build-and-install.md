# orbi-owner-agent — Build and install

The device target is NETGEAR Orbi RBRE960 running vendor-modified
OpenWrt Chaos Calmer 15.05.1 with:

- Kernel: Linux 4.4.60 SMP PREEMPT armv7l
- libc:   musl 1.1.16
- opkg arch: `ipq`
- opkg:  `check_signature` enabled in `/etc/opkg.conf`
- procd-based init with `procd-nand`
- lua 5.1.5, lighttpd 1.4.58 (mod-magnet, mod-cgi, mod-fastcgi)

Because the Phase-A agent is pure shell + UCI + JSON, the package is
`arch: all` (noarch). No cross-compilation is strictly required.

## 1. Build

### 1a. Simplest path — build an ipk by hand

The package layout already matches the on-device install layout under
`files/`. An `ar`-archived `.ipk` can be produced with any Linux host:

```
cd openwrt/orbi-owner-agent
TMP=$(mktemp -d)
mkdir -p "$TMP/pkg"
cp -r files/. "$TMP/pkg/"

# control files
mkdir -p "$TMP/control"
cat > "$TMP/control/control" <<EOF
Package: orbi-owner-agent
Version: 0.1.0-1
Depends: rpcd, ubus, uci, libubox, jshn
Section: net
Architecture: all
Maintainer: Orbi owner-research project
Description: Owner-controlled rpcd ubus agent for NETGEAR Orbi RBRE960.
EOF
cp files/etc/config/orbi-owner-agent > /dev/null 2>&1 || true
echo "/etc/config/orbi-owner-agent" > "$TMP/control/conffiles"

# optional scripts
cat > "$TMP/control/postinst" <<'EOF'
#!/bin/sh
[ -z "$IPKG_INSTROOT" ] && /etc/init.d/rpcd reload >/dev/null 2>&1 || true
exit 0
EOF
chmod +x "$TMP/control/postinst"

# assemble
(cd "$TMP/pkg" && tar --owner=0 --group=0 -czf "$TMP/data.tar.gz" .)
(cd "$TMP/control" && tar --owner=0 --group=0 -czf "$TMP/control.tar.gz" .)
echo "2.0" > "$TMP/debian-binary"

(cd "$TMP" && ar r "../orbi-owner-agent_0.1.0-1_all.ipk" debian-binary control.tar.gz data.tar.gz)
```

Resulting artifact: `orbi-owner-agent_0.1.0-1_all.ipk`.

### 1b. OpenWrt SDK path (reproducible)

If an OpenWrt Chaos Calmer 15.05.1 SDK is available (preferably one
aligned with r49254 and the NETGEAR vendor patches):

```
cp -r openwrt/orbi-owner-agent <SDK>/package/orbi-owner-agent
cd <SDK>
./scripts/feeds update -a
./scripts/feeds install -a
make menuconfig           # enable "Network → Management → orbi-owner-agent"
make package/orbi-owner-agent/compile V=s
# → bin/.../orbi-owner-agent_0.1.0-1_all.ipk
```

The `arch: all` flag in the Makefile means the SDK's ipq807x cross
toolchain is not required — any SDK that includes `rpcd`, `ubus`,
`uci`, and `jshn` produces an installable artifact.

### 1c. Required build environment (if producing a C variant later)

Documented for completeness:

- OpenWrt 15.05.1 SDK for ipq/ipq807x (closest upstream match).
- NETGEAR GPL source bundle for 7.2.7.15 or 7.2.8.8 — **not present
  locally**, must be downloaded separately from NETGEAR's GPL portal.
- Toolchain: GCC 5.2.0 and binutils compatible with r49254 (per
  `readelf -p .comment` on the live `/usr/sbin/httpd`).
- libc: musl 1.1.16-1. ABI-compatible build is NOT guaranteed by
  arbitrary musl 1.1.x — stick to 1.1.16 or a vetted 1.1.x patchlevel.

## 2. Install options on the device

The device's opkg has `option check_signature` set. There are three
ways to install our unsigned `.ipk`:

### 2a. Pre-staged install (RECOMMENDED)

NETGEAR itself pre-stages two packages at `/ipk/qca-hyd-init.ipk` and
`/ipk/qca-hyd-son.ipk` and installs them at runtime. We follow the
same model:

```
# From owner workstation (dev machine):
scp -i ~/.ssh/orbi_rbre960_rsa orbi-owner-agent_0.1.0-1_all.ipk \
    root@10.0.0.1:/ipk/

# On the device (via SSH):
opkg install --force-signature /ipk/orbi-owner-agent_0.1.0-1_all.ipk
```

`--force-signature` instructs opkg to skip the signature check for
this install; no permanent change to `/etc/opkg.conf` is made.

### 2b. Add owner signing key (more robust, more effort)

If the owner wants signed packages for all future installs:

```
# On a dev host:
usign -G -s owner.sec -p owner.pub -c "Orbi owner key"
usign -S -m orbi-owner-agent_0.1.0-1_all.ipk -s owner.sec

# Copy pubkey to device:
scp -i ~/.ssh/orbi_rbre960_rsa owner.pub root@10.0.0.1:/etc/opkg/keys/

# Install normally:
scp -i ~/.ssh/orbi_rbre960_rsa orbi-owner-agent_0.1.0-1_all.ipk \
    root@10.0.0.1:/tmp/
ssh -i ~/.ssh/orbi_rbre960_rsa root@10.0.0.1 \
    "opkg install /tmp/orbi-owner-agent_0.1.0-1_all.ipk"
```

### 2c. Bypass opkg entirely (fastest for iteration)

Not recommended for production, but simplest for development:

```
# Build a tar instead of an .ipk:
cd openwrt/orbi-owner-agent
tar --owner=0 --group=0 -cf /tmp/orbi-owner-agent.tar -C files .

# Push to device and extract into the overlay:
scp /tmp/orbi-owner-agent.tar root@10.0.0.1:/tmp/
ssh root@10.0.0.1 "tar -xf /tmp/orbi-owner-agent.tar -C / && \
                   /etc/init.d/orbi-owner-agent enable && \
                   /etc/init.d/orbi-owner-agent start"
```

opkg will NOT know about this install; uninstall must be manual. Use
this only during active development.

## 3. First-boot behavior

Regardless of install path, the `uci-defaults/80-orbi-owner-agent`
script runs once:

- Creates `/etc/config/orbi-owner-agent` with safe defaults.
- Reserves VLAN IDs 1, 4093, 4094.
- Runs `/etc/init.d/orbi-owner-agent enable` and `start`.
- Reloads rpcd so the ACL takes effect.

After that, the agent is reachable via ubus:

```
ssh root@10.0.0.1 "ubus call orbi.owner.agent info"
ssh root@10.0.0.1 "ubus call orbi.owner.agent status"
ssh root@10.0.0.1 "ubus call orbi.owner.agent network"
```

## 4. Uninstall

Via opkg (if installed through opkg):

```
ssh root@10.0.0.1 "opkg remove orbi-owner-agent"
```

opkg's conffiles behavior keeps `/etc/config/orbi-owner-agent`
unless `--autoremove` is passed. Owner-created VLAN sections under
`/etc/config/network` are left untouched (they represent owner-authored
state); to remove them, call `ubus call orbi.owner.agent vlan_delete`
first for each.

Manual uninstall (if installed via method 2c):

```
ssh root@10.0.0.1 '
    /etc/init.d/orbi-owner-agent disable 2>/dev/null
    /etc/init.d/orbi-owner-agent stop    2>/dev/null
    rm -f /usr/libexec/rpcd/orbi-owner-agent
    rm -f /usr/share/rpcd/acl.d/orbi-owner-agent.json
    rm -rf /usr/share/orbi-owner-agent
    rm -f /etc/init.d/orbi-owner-agent
    rm -f /etc/uci-defaults/80-orbi-owner-agent
    rm -f /tmp/orbi-owner-agent.log
    /etc/init.d/rpcd reload
'
```

`/etc/config/orbi-owner-agent` is preserved intentionally — delete it
by hand if you want a clean slate.

## 5. Offline tests

```
cd openwrt/orbi-owner-agent
bash tests/test_package_layout.sh
bash tests/test_validate.sh

# plugin interface test needs a staged lib dir and a jshn stub:
mkdir -p /tmp/orbi-stage
cp -r files/usr/share/orbi-owner-agent /tmp/orbi-stage/
# put a minimal jshn.sh at /tmp/orbi-stage/jshn.sh (see test harness)
ORBI_OWNER_AGENT_ROOT=/tmp/orbi-stage/orbi-owner-agent \
ORBI_OWNER_AGENT_JSHN=/tmp/orbi-stage/jshn.sh \
    bash tests/test_plugin_interface.sh
```

Expected output:
- `test_package_layout.sh` → `FAIL=0`, exit 0
- `test_validate.sh` → `PASS=33 FAIL=0`, exit 0
- `test_plugin_interface.sh` → `OK — plugin interface tests pass`

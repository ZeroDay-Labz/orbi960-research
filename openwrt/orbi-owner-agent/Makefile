#
# OpenWrt package Makefile — orbi-owner-agent
#
# Target: NETGEAR Orbi RBRE960, vendor-modified OpenWrt Chaos Calmer 15.05.1
# Arch:   ipq  (musl 1.1.16, ARMv7, kernel 4.4.60)
#
# This package contains only shell scripts, UCI configuration, and an rpcd
# ACL. There is no compiled binary, so no cross-toolchain is required and
# the package is Architecture: all (noarch-equivalent for OpenWrt).
#
# To build with a matching OpenWrt 15.05.1 Chaos Calmer SDK:
#     cp -r <this_dir> <SDK>/package/orbi-owner-agent
#     cd <SDK>
#     make package/orbi-owner-agent/compile V=s
#
# See docs/build-and-install.md for the full build-and-install story,
# including the pre-staged /ipk/ install path and the signature-check
# considerations on the stock firmware.

include $(TOPDIR)/rules.mk

PKG_NAME:=orbi-owner-agent
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Orbi owner-research project
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/orbi-owner-agent
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Management
    TITLE:=Owner-controlled rpcd ubus agent for NETGEAR Orbi
    URL:=https://github.com/ZeroDay-Labz/orbi960-research
    DEPENDS:=+rpcd +ubus +uci +libubox +jshn
    PKGARCH:=all
endef

define Package/orbi-owner-agent/description
 Small device-side management agent for NETGEAR Orbi RBRE960 that
 piggybacks on the stock rpcd/ubus authentication boundary.  Callers
 must SSH as root before they can reach the agent; no new network
 listener is created.  The agent exposes an explicit allowlist of
 methods under the ubus namespace "orbi.owner.agent".

 Intended to be driven by an external Proxmox-hosted management
 controller over SSH; see architecture.md for details.
endef

# No sources to build; everything is shell + UCI + JSON.
Build/Compile :=
Build/Configure :=

define Package/orbi-owner-agent/conffiles
/etc/config/orbi-owner-agent
endef

define Package/orbi-owner-agent/install
    $(INSTALL_DIR)  $(1)/usr/libexec/rpcd
    $(INSTALL_BIN)  ./files/usr/libexec/rpcd/orbi-owner-agent \
                    $(1)/usr/libexec/rpcd/orbi-owner-agent

    $(INSTALL_DIR)  $(1)/usr/share/rpcd/acl.d
    $(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/orbi-owner-agent.json \
                    $(1)/usr/share/rpcd/acl.d/orbi-owner-agent.json

    $(INSTALL_DIR)  $(1)/usr/share/orbi-owner-agent/lib
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/lib/common.sh    $(1)/usr/share/orbi-owner-agent/lib/
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/lib/validate.sh  $(1)/usr/share/orbi-owner-agent/lib/
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/lib/network.sh   $(1)/usr/share/orbi-owner-agent/lib/
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/lib/backup.sh    $(1)/usr/share/orbi-owner-agent/lib/
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/lib/audit.sh     $(1)/usr/share/orbi-owner-agent/lib/
    $(INSTALL_DATA) ./files/usr/share/orbi-owner-agent/VERSION          $(1)/usr/share/orbi-owner-agent/VERSION

    $(INSTALL_DIR)  $(1)/etc/config
    $(INSTALL_CONF) ./files/etc/config/orbi-owner-agent                 $(1)/etc/config/orbi-owner-agent

    $(INSTALL_DIR)  $(1)/etc/init.d
    $(INSTALL_BIN)  ./files/etc/init.d/orbi-owner-agent                 $(1)/etc/init.d/orbi-owner-agent

    $(INSTALL_DIR)  $(1)/etc/uci-defaults
    $(INSTALL_BIN)  ./files/etc/uci-defaults/80-orbi-owner-agent        $(1)/etc/uci-defaults/80-orbi-owner-agent
endef

define Package/orbi-owner-agent/postinst
#!/bin/sh
# Called at install time on the device.  uci-defaults/80-orbi-owner-agent
# does the real bootstrap and is removed by /etc/init.d/boot after a
# successful first-boot run.
if [ -z "$${IPKG_INSTROOT}" ]; then
    /etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/orbi-owner-agent/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    /etc/init.d/orbi-owner-agent disable >/dev/null 2>&1 || true
    /etc/init.d/orbi-owner-agent stop    >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/orbi-owner-agent/postrm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    rm -f /tmp/orbi-owner-agent.log 2>/dev/null || true
    /etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi
exit 0
endef

$(eval $(call BuildPackage,orbi-owner-agent))

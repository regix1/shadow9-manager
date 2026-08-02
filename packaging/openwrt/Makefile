#
# OpenWrt package for the shadow9 node client.
#
# The binary is cross-compiled outside the SDK by node/Makefile, so Build/Compile
# is empty and this only installs the file. Build it against the release branch
# the router runs: 24.10 produces an .ipk and 25.12 produces an .apk from this
# same Makefile, and the two are not interchangeable artifacts.
#
#   cp -r packaging/openwrt <sdk>/package/shadow9-node
#   cp node/dist/shadow9-node-linux-* <sdk>/package/shadow9-node/files/
#   make package/shadow9-node/compile V=s
#

SHADOW9_VERSION_FILE:=$(dir $(lastword $(MAKEFILE_LIST)))VERSION
ifeq ($(wildcard $(SHADOW9_VERSION_FILE)),)
$(error missing VERSION beside the shadow9-node package Makefile)
endif
SHADOW9_VERSION:=$(strip $(shell cat $(SHADOW9_VERSION_FILE)))
ifeq ($(SHADOW9_VERSION),)
$(error VERSION beside the shadow9-node package Makefile is empty)
endif

include $(TOPDIR)/rules.mk

PKG_NAME:=shadow9-node
PKG_VERSION:=$(SHADOW9_VERSION)
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

# OpenWrt ARCH to the GOARCH the binary was built for. Anything not listed here
# has no prebuilt binary, and the install below fails loudly rather than
# packaging the wrong architecture.
GOARCH_x86_64:=amd64
GOARCH_aarch64:=arm64
GOARCH_mipsel:=mipsle
NODE_GOARCH:=$(GOARCH_$(ARCH))

define Package/shadow9-node
  SECTION:=net
  CATEGORY:=Network
  TITLE:=shadow9 WireGuard node client
  # luci-app-pbr is the web UI for the pbr service, and it is a separate
  # package that depends on pbr rather than the other way round. Without it a
  # policy-ready join leaves the operator no way to write the policy that
  # selects tunnel traffic except uci over SSH.
  DEPENDS:=+wireguard-tools +luci-proto-wireguard +ca-bundle +pbr +luci-app-pbr
endef

define Package/shadow9-node/description
  Enrolls this router as a node on a shadow9 WireGuard hub and writes the
  matching UCI network, firewall and policy-routing configuration, so the
  tunnel appears in LuCI as a real WireGuard interface with status and a peer
  list.
endef

# Nothing to fetch and nothing to build. PKGARCH is deliberately left alone:
# this is a compiled binary, so there is one package per architecture, and
# PKGARCH:=all would produce a package that installs the wrong ELF.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

# Only files listed here survive a sysupgrade. Everything else the package owns,
# including the binary itself, is left out of the overlay backup on purpose.
define Package/shadow9-node/conffiles
/etc/config/shadow9
/etc/shadow9.token
endef

# A package upgrade keeps the enrolled tunnel. A real removal runs the same
# ownership-checked cleanup available to the operator from the command line.
#
# default_prerm sources this first and only then walks the package's own
# /etc/init.d entries to disable and stop them, so nothing here may delete a
# packaged file: removing /etc/init.d/shadow9-node early makes that walk fail
# and strands /etc/rc.d/S95shadow9-node. The package manager deletes its own
# files after this runs.
#
# A refused cleanup warns and lets removal continue. Keeping unproven router
# configuration is right, but default_prerm returns this script's status and
# opkg aborts on a nonzero one, which would leave the package unremovable.
# Direct "shadow9-node uninstall" still exits nonzero.
define Package/shadow9-node/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ "$${PKG_UPGRADE}" = "1" ] && exit 0
if [ -x /usr/sbin/shadow9-node ]; then
	/usr/sbin/shadow9-node uninstall -quiet || \
		echo "shadow9-node: the router configuration could not be proven to belong to Shadow9 and was left in place; run 'shadow9-node uninstall' once it is resolved" >&2
fi
exit 0
endef

# No /etc/uci-defaults script is shipped on purpose. default_postinst runs a
# bare "uci commit" after sourcing any uci-defaults file a package owns, and
# that commits every package's staged changes, including ones an operator left
# pending in LuCI. The boot service does the same first-boot enrollment, and
# default_postinst enables and starts it here anyway.
define Package/shadow9-node/install
	$(if $(NODE_GOARCH),,$(error no prebuilt shadow9-node binary for ARCH=$(ARCH)))
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/shadow9-node-linux-$(NODE_GOARCH) $(1)/usr/sbin/shadow9-node
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadow9-node.init $(1)/etc/init.d/shadow9-node
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/shadow9.config $(1)/etc/config/shadow9
	$(INSTALL_CONF) ./files/shadow9.token $(1)/etc/shadow9.token
endef

$(eval $(call BuildPackage,shadow9-node))

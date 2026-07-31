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

include $(TOPDIR)/rules.mk

PKG_NAME:=shadow9-node
PKG_VERSION:=0.1.0
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
  DEPENDS:=+wireguard-tools +luci-proto-wireguard +ca-bundle
endef

define Package/shadow9-node/description
  Enrolls this router as a node on a shadow9 WireGuard hub and writes the
  matching UCI network and firewall configuration, so the tunnel appears in
  LuCI as a real WireGuard interface with status and a peer list.
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

define Package/shadow9-node/install
	$(if $(NODE_GOARCH),,$(error no prebuilt shadow9-node binary for ARCH=$(ARCH)))
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/shadow9-node-linux-$(NODE_GOARCH) $(1)/usr/sbin/shadow9-node
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadow9-node.init $(1)/etc/init.d/shadow9-node
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/shadow9.config $(1)/etc/config/shadow9
	$(INSTALL_CONF) ./files/shadow9.token $(1)/etc/shadow9.token
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-shadow9-node $(1)/etc/uci-defaults/99-shadow9-node
endef

$(eval $(call BuildPackage,shadow9-node))

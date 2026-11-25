include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-xbox-capture
PKG_VERSION:=1.6.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-xbox-capture
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Xbox traffic capture and Clash rule export
  DEPENDS:=+luci-base +rpcd +tcpdump +python3-light +python3-urllib +python3-openssl +python3-codecs +ca-bundle
  PKGARCH:=all
endef

define Package/luci-app-xbox-capture/description
  Record per-device DNS questions, TLS hostnames and public destination
  addresses on a LAN interface. Export selected entries as Clash rules.
endef

define Build/Compile
endef

define Package/luci-app-xbox-capture/install
	$(CP) ./root/. $(1)/
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/. $(1)/www/
endef

$(eval $(call BuildPackage,luci-app-xbox-capture))

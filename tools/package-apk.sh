#!/bin/sh
# Build an unsigned APK v3 using the OpenWrt host apk tool.
set -eu
umask 022

project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
out=${1:-"$project/dist"}
mkdir -p "$out"
out=$(CDPATH='' cd -- "$out" && pwd)
name=luci-app-xbox-capture
version=$(awk -F ':=' '/^PKG_VERSION:=/{print $2}' "$project/Makefile")
release=$(awk -F ':=' '/^PKG_RELEASE:=/{print $2}' "$project/Makefile")
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT

mkdir -p "$build/data/www" "$build/data/lib/apk/packages"
cp -R "$project/root"/. "$build/data/"
cp -R "$project/htdocs"/. "$build/data/www/"
chmod -R a+rX "$build/data"
(cd "$build/data" && find . -type f -print | sed 's/^\.//' | LC_ALL=C sort) > "$build/files.list"
mv "$build/files.list" "$build/data/lib/apk/packages/$name.list"

apk_script() {
	printf '%s\n' '#!/bin/sh' "export pkgname=$name"
	if [ "$1" = post-upgrade ]; then
		printf '%s\n' 'export PKG_UPGRADE=1'
	fi
	sed '1d' "$project/tools/ipk-control/$2"
}
apk_script post-install postinst > "$build/post-install"
apk_script post-upgrade postinst > "$build/post-upgrade"
apk_script pre-deinstall prerm > "$build/pre-deinstall"

file="$out/$name-$version-r$release.apk"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} "${XBOX_FAKEROOT:-fakeroot}" -- \
	"${XBOX_APK:-apk}" mkpkg \
	--info "name:$name" --info "version:$version-r$release" --info 'arch:noarch' \
	--info 'description:Xbox traffic capture and Clash rule export' \
	--info 'depends:luci-base rpcd tcpdump python3-light python3-urllib python3-openssl python3-codecs ca-bundle' \
	--script "post-install:$build/post-install" --script "post-upgrade:$build/post-upgrade" \
	--script "pre-deinstall:$build/pre-deinstall" --script "post-deinstall:$project/tools/ipk-control/postrm" \
	--files "$build/data" --output "$file"
chmod 644 "$file"
printf '%s\n' "$file"

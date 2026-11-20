#!/bin/sh
# Build the architecture-independent package without an OpenWrt SDK.
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

mkdir -p "$build/control" "$build/data/www" "$build/package"
cp -R "$project/root"/. "$build/data/"
cp -R "$project/htdocs"/. "$build/data/www/"
cp -R "$project/tools/ipk-control"/. "$build/control/"
installed_size=$(find "$build/data" -type f -exec wc -c {} + | awk 'END{print $1}')
cat > "$build/control/control" <<EOF
Package: $name
Version: $version-$release
Depends: luci-base, rpcd, tcpdump, python3-light, python3-urllib, python3-openssl, ca-bundle
Section: luci
Architecture: all
Installed-Size: $installed_size
Description: Xbox traffic capture and Clash rule export
EOF
printf '2.0\n' > "$build/package/debian-binary"

archive() {
	tar --format=gnu --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" \
		--owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' -C "$1" -czf "$2" -T "$3"
}

printf '.\n' > "$build/tree"
printf './debian-binary\n./data.tar.gz\n./control.tar.gz\n' > "$build/members"
archive "$build/control" "$build/package/control.tar.gz" "$build/tree"
archive "$build/data" "$build/package/data.tar.gz" "$build/tree"
file="$out/${name}_${version}-${release}_all.ipk"
archive "$build/package" "$file" "$build/members"
printf '%s\n' "$file"

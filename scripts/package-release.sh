#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <signed-release-binary>\n' "$0" >&2
    exit 2
fi

staging=$(mktemp -d "${TMPDIR:-/tmp}/keychain-api-dist.XXXXXX")
trap 'rm -rf "$staging"' 0
trap 'exit 1' HUP INT TERM
install -m 0755 "$1" "$staging/keychain-api"
codesign --verify --strict "$staging/keychain-api"

version=$("$staging/keychain-api" --version)
case "$version" in
    ''|*[!0-9A-Za-z.+-]*)
        printf 'The executable returned an invalid release version.\n' >&2
        exit 1
        ;;
esac

architecture=$(lipo -archs "$staging/keychain-api")
case "$architecture" in
    arm64|x86_64) ;;
    *)
        printf 'Release packaging requires one arm64 or x86_64 architecture.\n' >&2
        exit 1
        ;;
esac

archive="keychain-api-$version-macos-$architecture.tar.gz"
mkdir -p dist
tar -czf "dist/$archive" --format ustar --uid 0 --gid 0 --numeric-owner \
    --no-mac-metadata --no-xattrs --no-acls --no-fflags \
    -C "$staging" keychain-api
(
    cd dist
    shasum -a 256 "$archive" > "$archive.sha256"
)
printf 'dist/%s\ndist/%s.sha256\n' "$archive" "$archive"

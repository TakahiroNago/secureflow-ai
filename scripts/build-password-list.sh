#!/usr/bin/env bash
# SecureFlow AI — rebuild the bundled common password list (docs/security-design.md §12.1).
#
# Downloads one pinned file, verifies it, applies the documented processing and verifies the
# result. Nothing from the download is executed. To update, change the pins here, review the
# diff, re-check the license and origin, run the secret scans and update §12.1.
set -euo pipefail
cd "$(dirname "$0")/.."

COMMIT=35d74839e66f44d116e694369d86a5bf07aaed6f
SOURCE=Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt
SOURCE_SHA256=424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51
OUTPUT=backend/resources/security/common-passwords.txt
OUTPUT_SHA256=2ce4934bf860d3d348a9f4ea646df42e8e65c292c734f0633635148c53a73e86

export LC_ALL=C
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL --proto '=https' "https://raw.githubusercontent.com/danielmiessler/SecLists/$COMMIT/$SOURCE" -o "$work/source"
echo "$SOURCE_SHA256  $work/source" | sha256sum -c --quiet -

# At least 12 characters (the password policy minimum), no line containing "@" (keeps out anything
# shaped like an address), lowercase, unique, sorted.
tr -d '\r' < "$work/source" | awk 'length($0) >= 12' | grep -v '@' | tr 'A-Z' 'a-z' | sort -u > "$work/output"
echo "$OUTPUT_SHA256  $work/output" | sha256sum -c --quiet -

mkdir -p "$(dirname "$OUTPUT")"
cp "$work/output" "$OUTPUT"
chmod 644 "$OUTPUT"
echo "$OUTPUT: $(wc -l < "$OUTPUT") entries"

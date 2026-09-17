#!/bin/sh
set -eu
cd "$(dirname "$0")"
version=${1:-v2.11.3}
case "$version" in
  v2.11.3|v2.11.4) ;;
  *) echo "Usage: $0 [v2.11.3|v2.11.4]" >&2; exit 2 ;;
esac
# Keep test dependency changes outside the production module and checked-in files.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
cp go.mod "$scratch/matrix.mod"
cp go.sum "$scratch/matrix.sum"
go mod edit -modfile="$scratch/matrix.mod" -require="github.com/caddyserver/caddy/v2@$version"
go mod tidy -modfile="$scratch/matrix.mod"
go version
go list -modfile="$scratch/matrix.mod" -m github.com/caddyserver/caddy/v2 github.com/caddyserver/certmagic
# Caddy cmd installs bundled fallback roots at init. The integration child needs
# its own ephemeral CA pool; remove only that import in a disposable test overlay.
# Production sources/module cache and production builds remain unchanged.
# Go refuses overlays beneath GOMODCACHE. Copy the exact resolved module into
# scratch, then use only the scratch modfile to point at that unmodified copy.
caddy_source_dir=$(go list -modfile="$scratch/matrix.mod" -m -f '{{.Dir}}' github.com/caddyserver/caddy/v2)
cp -R "$caddy_source_dir" "$scratch/caddy-source"
chmod -R u+w "$scratch/caddy-source"
go mod edit -modfile="$scratch/matrix.mod" -replace="github.com/caddyserver/caddy/v2=$scratch/caddy-source"
caddy_cmd_dir="$scratch/caddy-source/cmd"
python3 - "$caddy_cmd_dir/x509rootsfallback.go" "$scratch" <<'PYOVERLAY'
import json, pathlib, sys
source, scratch = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
text = source.read_text()
expected = '\t_ "golang.org/x/crypto/x509roots/fallback"\n'
if text.count(expected) != 1 or 'package caddycmd' not in text:
    raise SystemExit('Caddy fallback import changed; review test trust overlay before running')
overlay = scratch / 'x509rootsfallback.go'
overlay.write_text(text.replace(expected, ''))
(scratch / 'overlay.json').write_text(json.dumps({'Replace': {str(source): str(overlay)}}))
PYOVERLAY
APX_REDIS_INTEGRATION=1 APX_CERTIFICATE_TEST_OVERLAY=1 go test -modfile="$scratch/matrix.mod" -overlay="$scratch/overlay.json" -race -count=1 -v ./...

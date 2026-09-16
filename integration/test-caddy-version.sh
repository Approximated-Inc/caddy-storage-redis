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
APX_REDIS_INTEGRATION=1 go test -modfile="$scratch/matrix.mod" -race -count=1 -v ./...

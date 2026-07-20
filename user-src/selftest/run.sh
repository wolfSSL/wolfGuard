#!/bin/sh
# Build and run the portable wolfGuard selftests. These are self-contained
# regression checks for the userland tools and host-side models of kernel fixes.
set -eu

cd "$(dirname "$0")"
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--Wall -Wextra -O2}"
RUNNER="${RUNNER:-}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
for f in *.c; do
	name="$(basename "$f" .c)"
	case "$name" in
	sanitize) src="$f ../terminal.c"; extra="" ;;
	base64)   src="$f ../encoding.c"; extra="-DIPC_SUPPORTS_KERNEL_INTERFACE" ;;
	*)        src="$f"; extra="" ;;
	esac

	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -I.. $extra $src -o "$tmp/$name"; then
		echo "BUILD FAIL: $f"
		fail=1
		continue
	fi
	# shellcheck disable=SC2086
	if out="$($RUNNER "$tmp/$name")"; then
		echo "ok   - $out"
	else
		echo "FAIL - $f"
		fail=1
	fi
done

if [ "$fail" -eq 0 ]; then
	echo "all selftests passed"
fi
exit "$fail"

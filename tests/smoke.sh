#!/bin/sh
set -eu

program=${1:-./securepm}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
trap 'exit 1' HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

"$program" --help >"$test_dir/help" 2>"$test_dir/err"
test ! -s "$test_dir/err" || fail 'help wrote to stderr'
grep -F 'Usage:' "$test_dir/help" >/dev/null || fail 'missing usage'
grep -F 'Planned commands after login:' "$test_dir/help" >/dev/null || fail 'missing planned-command label'

for option in none short; do
    if [ "$option" = none ]; then
        "$program" >"$test_dir/out" 2>"$test_dir/err"
    else
        "$program" -h >"$test_dir/out" 2>"$test_dir/err"
    fi
    cmp -s "$test_dir/help" "$test_dir/out" || fail 'inconsistent help output'
    test ! -s "$test_dir/err" || fail 'help wrote to stderr'
done

check_rejected() {
    status=0
    "$program" "$@" >"$test_dir/out" 2>"$test_dir/err" || status=$?
    test "$status" -eq 1 || fail 'invalid arguments must exit with status 1'
    test ! -s "$test_dir/out" || fail 'invalid arguments wrote to stdout'
    grep -Fx 'Unknown option. Use --help.' "$test_dir/err" >/dev/null || fail 'missing argument error'
}

check_rejected --unknown
check_rejected --help extra
check_rejected add
check_rejected ''

printf 'PASS: CLI help and argument validation (7 cases)\n'

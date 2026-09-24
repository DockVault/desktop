#!/usr/bin/env bash
# Start a PACKAGED DockVault in its headless smoke mode (DOCKVAULT_SMOKE: the boot crypto self-test, the
# UI loaded over the app scheme, the renderer's secure context) and require it to pass: the result file
# must say ok and the exit code must be 0. A crash, a refusal to launch or a hang all fail.
#
#   scripts/smoke-packaged.sh run <label> <command...>   start the app with this command
#   scripts/smoke-packaged.sh dmg <label> <file.dmg>     mount the .dmg, report its signature and
#                                                        Gatekeeper's verdict, and start the app in it
#
# SMOKE_LIMIT is the time allowed, in seconds (default 120). Results go to the GitHub step summary when
# there is one.
set -euo pipefail

tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

run_smoke() {
  local label="$1"; shift
  local result="$tmp/smoke-$label.json" log="$tmp/smoke-$label.log" code=0 pid
  local limit="${SMOKE_LIMIT:-120}"
  rm -f "$result"
  DOCKVAULT_SMOKE=1 DOCKVAULT_SMOKE_RESULT="$result" "$@" --user-data-dir="$tmp/smoke-profile-$label" > "$log" 2>&1 &
  pid=$!
  for _ in $(seq 1 "$limit"); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    echo "::error::$label: the packaged app did not finish its smoke check within $limit s"
    tail -40 "$log"
    return 1
  fi
  wait "$pid" || code=$?
  if [ "$code" -ne 0 ] || ! grep -q '"ok": true' "$result" 2>/dev/null; then
    echo "::error::$label: the packaged app failed its smoke check (exit $code)"
    cat "$result" 2>/dev/null || echo "(no result file)"
    tail -40 "$log"
    return 1
  fi
  echo "$label: smoke check passed"
  echo "- $label: the packaged app starts and passes its smoke check" >> "$summary"
}

smoke_dmg() {
  local label="$1" dmg="$2"
  [ -f "$dmg" ] || { echo "::error::$label: no .dmg at $dmg"; return 1; }
  local mnt="$tmp/dmg-$label" dest="$tmp/app-$label" sig kind gk
  mkdir -p "$mnt" "$dest"
  hdiutil attach -nobrowse -readonly -mountpoint "$mnt" "$dmg" >/dev/null
  cp -R "$mnt/DockVault.app" "$dest/"
  hdiutil detach "$mnt" >/dev/null
  local app="$dest/DockVault.app"
  # Reported as they are: an unsigned preview is expected to be refused by Gatekeeper. What must hold
  # is that the signature is intact (an Apple-silicon binary with a broken one is killed) and it runs.
  if codesign --verify --deep --strict "$app" 2>"$tmp/codesign-$label.txt"; then sig="valid"
  else sig="INVALID: $(tr '\n' ' ' < "$tmp/codesign-$label.txt")"; fi
  kind=$(codesign -dv "$app" 2>&1 | grep -E '^(Signature|Authority)' | tr '\n' ' ' || true)
  gk=$(spctl --assess --type execute "$app" 2>&1 | tr '\n' ' ' || true)
  echo "$label: signature $sig | $kind | Gatekeeper: ${gk:-accepted} | $(uname -m)"
  echo "- $label: signature $sig; $kind; Gatekeeper: ${gk:-accepted}; on $(uname -m)" >> "$summary"
  run_smoke "$label" "$app/Contents/MacOS/DockVault"
}

mode="${1:-}"; shift || true
case "$mode" in
  run) run_smoke "$@" ;;
  dmg) smoke_dmg "$@" ;;
  *) echo "usage: $0 run <label> <command...> | dmg <label> <file.dmg>" >&2; exit 2 ;;
esac

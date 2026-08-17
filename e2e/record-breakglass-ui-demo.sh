#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RECORDING_FILE="${BREAKGLASS_UI_DEMO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-ui-flow.webm}"
UI_BROWSER_RECORDING="${BREAKGLASS_UI_BROWSER_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-ui-browser-flow.webm}"
CONSOLE_CAST="${BREAKGLASS_CONSOLE_DEMO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-console-flow.cast}"
CONSOLE_WEBM="${BREAKGLASS_CONSOLE_VIDEO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-console-flow.webm}"
TEMP_DIR="$(mktemp -d)"
VIDEO_DIR="${TEMP_DIR}/segments"
SEGMENTS_FILE="${TEMP_DIR}/segments.txt"
UI_SLOWDOWN="${BREAKGLASS_UI_SLOWDOWN:-2}"
TERMINAL_SPEED="${BREAKGLASS_TERMINAL_SPEED:-0.425}"
KEEP_TEMP="${BREAKGLASS_UI_KEEP_TEMP:-false}"

cleanup() {
  if [[ "$KEEP_TEMP" == "true" ]]; then
    printf 'ui-demo temporary artifacts retained at %s\n' "$TEMP_DIR" >&2
  else
    rm -rf "$TEMP_DIR"
  fi
}
trap cleanup EXIT

command -v ffmpeg >/dev/null 2>&1 || {
  printf 'ui-demo: required command not found: ffmpeg\n' >&2
  exit 1
}
command -v agg >/dev/null 2>&1 || {
  printf 'ui-demo: required command not found: agg (install with: brew install agg)\n' >&2
  exit 1
}

curl -fsS "${BREAKGLASS_API_URL:-http://localhost:8080}/api/config" >/dev/null || {
  printf 'ui-demo: Breakglass API is not reachable\n' >&2
  exit 1
}

mkdir -p "$(dirname "$RECORDING_FILE")"
mkdir -p "$(dirname "$UI_BROWSER_RECORDING")" "$(dirname "$CONSOLE_CAST")" "$(dirname "$CONSOLE_WEBM")"
(
  cd "$ROOT_DIR/frontend"
  BREAKGLASS_RECORD_UI=true \
    BREAKGLASS_UI_VIDEO_DIR="$VIDEO_DIR" \
    BREAKGLASS_UI_SEGMENTS_FILE="$SEGMENTS_FILE" \
    BREAKGLASS_RECORD_UI_PAUSE_MS="${BREAKGLASS_RECORD_UI_PAUSE_MS:-2000}" \
    BREAKGLASS_UI_URL="${BREAKGLASS_UI_URL:-http://localhost:8080}" \
    BREAKGLASS_API_URL="${BREAKGLASS_API_URL:-http://localhost:8080}" \
    MAILHOG_URL="${MAILHOG_URL:-http://localhost:8025}" \
    KEYCLOAK_URL="${KEYCLOAK_URL:-https://localhost:8443}" \
    npx playwright test tests/e2e/recording-ui.spec.ts \
      --config=playwright.e2e.config.ts \
      --project=chromium-e2e
)

[[ -s "$SEGMENTS_FILE" ]] || {
  printf 'ui-demo: no video segments were produced\n' >&2
  exit 1
}

CONCAT_FILE="${TEMP_DIR}/concat.txt"
while IFS=$'\t' read -r name path; do
  [[ -n "$name" && -f "$path" ]] || {
    printf 'ui-demo: missing segment %s at %s\n' "$name" "$path" >&2
    exit 1
  }
  printf "file '%s'\n" "$path" >>"$CONCAT_FILE"
done <"$SEGMENTS_FILE"

UI_RAW="${TEMP_DIR}/ui-raw.webm"
TERMINAL_GIF="${TEMP_DIR}/terminal.gif"

BREAKGLASS_UI_SEGMENTS_FILE="$SEGMENTS_FILE" \
  BREAKGLASS_UI_SLOWDOWN="$UI_SLOWDOWN" \
  BREAKGLASS_SYNC_CONSOLE_CAST="$CONSOLE_CAST" \
  "$ROOT_DIR/e2e/record-breakglass-sync-console.sh"

ffmpeg -hide_banner -loglevel error -y \
  -f concat \
  -safe 0 \
  -i "$CONCAT_FILE" \
  -c copy \
  "$UI_RAW"

ffmpeg -hide_banner -loglevel error -y \
  -i "$UI_RAW" \
  -vf "setpts=${UI_SLOWDOWN}*PTS,format=yuv420p" \
  -an \
  -c:v libvpx-vp9 \
  -crf 30 \
  -b:v 0 \
  "$UI_BROWSER_RECORDING"

agg \
  --quiet \
  --no-loop \
  --cols 90 \
  --rows 32 \
  --font-size 13 \
  --idle-time-limit 5 \
  --speed "$TERMINAL_SPEED" \
  "$CONSOLE_CAST" \
  "$TERMINAL_GIF"

ffmpeg -hide_banner -loglevel error -y \
  -i "$TERMINAL_GIF" \
  -vf "fps=20,scale=640:480:force_original_aspect_ratio=increase,crop=640:480,setsar=1,format=yuv420p" \
  -an \
  -c:v libvpx-vp9 \
  -crf 30 \
  -b:v 0 \
  "$CONSOLE_WEBM"

PAIR_DIR="${TEMP_DIR}/pairs"
PAIR_LIST="${TEMP_DIR}/pairs.txt"
TERMINAL_PAIR_LIST="${TEMP_DIR}/terminal-pairs.txt"
mkdir -p "$PAIR_DIR"
: >"$PAIR_LIST"
: >"$TERMINAL_PAIR_LIST"
terminal_offset=0
segment_index=0
while IFS=$'\t' read -r name path; do
  raw_duration="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$path")"
  segment_duration="$(python3 - "$raw_duration" "$UI_SLOWDOWN" <<'PY'
import sys

print(float(sys.argv[1]) * float(sys.argv[2]))
PY
)"
  ui_segment="${PAIR_DIR}/${segment_index}-ui.webm"
  terminal_segment="${PAIR_DIR}/${segment_index}-terminal.webm"
  pair_segment="${PAIR_DIR}/${segment_index}-pair.webm"

  ffmpeg -hide_banner -loglevel error -y \
    -nostdin \
    -i "$path" \
    -vf "setpts=${UI_SLOWDOWN}*PTS,scale=640:480:force_original_aspect_ratio=increase,crop=640:480,setsar=1,format=yuv420p" \
    -t "$segment_duration" \
    -an \
    -c:v libvpx-vp9 \
    -crf 30 \
    -b:v 0 \
    "$ui_segment"

  ffmpeg -hide_banner -loglevel error -y \
    -nostdin \
    -ss "$terminal_offset" \
    -i "$CONSOLE_WEBM" \
    -t "$segment_duration" \
    -vf "scale=640:480:force_original_aspect_ratio=increase,crop=640:480,setsar=1,format=yuv420p,tpad=stop_mode=clone:stop_duration=2" \
    -an \
    -c:v libvpx-vp9 \
    -crf 30 \
    -b:v 0 \
    "$terminal_segment"

  ffmpeg -hide_banner -loglevel error -y \
    -nostdin \
    -i "$ui_segment" \
    -i "$terminal_segment" \
    -t "$segment_duration" \
    -filter_complex "[0:v][1:v]hstack=inputs=2,format=yuv420p[video]" \
    -map "[video]" \
    -an \
    -c:v libvpx-vp9 \
    -crf 30 \
    -b:v 0 \
    "$pair_segment"

  printf "file '%s'\n" "$pair_segment" >>"$PAIR_LIST"
  printf "file '%s'\n" "$terminal_segment" >>"$TERMINAL_PAIR_LIST"
  terminal_offset="$(python3 - "$terminal_offset" "$segment_duration" <<'PY'
import sys

print(float(sys.argv[1]) + float(sys.argv[2]))
PY
)"
  segment_index=$((segment_index + 1))
done <"$SEGMENTS_FILE"

ffmpeg -hide_banner -loglevel error -y \
  -f concat \
  -safe 0 \
  -i "$TERMINAL_PAIR_LIST" \
  -c copy \
  "$CONSOLE_WEBM"

ffmpeg -hide_banner -loglevel error -y \
  -f concat \
  -safe 0 \
  -i "$PAIR_LIST" \
  -c copy \
  "$RECORDING_FILE"

printf 'Recording written to %s\n' "$RECORDING_FILE"
printf 'Browser recording written to %s\n' "$UI_BROWSER_RECORDING"
printf 'Console cast written to %s\n' "$CONSOLE_CAST"
printf 'Console video written to %s\n' "$CONSOLE_WEBM"

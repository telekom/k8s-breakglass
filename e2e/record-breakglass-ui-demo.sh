#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RECORDING_FILE="${BREAKGLASS_UI_DEMO_RECORDING:-${ROOT_DIR}/docs/demos/breakglass-ui-flow.webm}"
TEMP_DIR="$(mktemp -d)"
VIDEO_DIR="${TEMP_DIR}/segments"
SEGMENTS_FILE="${TEMP_DIR}/segments.txt"
UI_SLOWDOWN="${BREAKGLASS_UI_SLOWDOWN:-2}"

cleanup() {
  rm -rf "$TEMP_DIR"
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
"$ROOT_DIR/e2e/record-breakglass-cli-demo.sh"
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
UI_SLOW="${TEMP_DIR}/ui-slow.webm"
TERMINAL_GIF="${TEMP_DIR}/terminal.gif"
TERMINAL_WEBM="${TEMP_DIR}/terminal.webm"

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
  "$UI_SLOW"

agg \
  --quiet \
  --no-loop \
  --cols 90 \
  --rows 32 \
  --font-size 13 \
  --idle-time-limit 5 \
  "${ROOT_DIR}/docs/demos/breakglass-user-flow.cast" \
  "$TERMINAL_GIF"

ffmpeg -hide_banner -loglevel error -y \
  -i "$TERMINAL_GIF" \
  -vf "fps=20,scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,format=yuv420p" \
  -an \
  -c:v libvpx-vp9 \
  -crf 30 \
  -b:v 0 \
  "$TERMINAL_WEBM"

ffmpeg -hide_banner -loglevel error -y \
  -i "$UI_SLOW" \
  -stream_loop -1 \
  -i "$TERMINAL_WEBM" \
  -filter_complex "[0:v]scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,format=yuv420p[ui];[1:v]scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,format=yuv420p[terminal];[ui][terminal]hstack=inputs=2:shortest=1,format=yuv420p[video]" \
  -map "[video]" \
  -an \
  -c:v libvpx-vp9 \
  -crf 30 \
  -b:v 0 \
  "$RECORDING_FILE"

printf 'Recording written to %s\n' "$RECORDING_FILE"

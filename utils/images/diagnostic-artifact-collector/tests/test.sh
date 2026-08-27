#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
image=diagnostic-artifact-collector:test
test_dir=$(mktemp -d /tmp/diagnostic-artifact-test.XXXXXX)
root_volume=diagnostic-artifact-test-${test_dir##*/}
upload_volume=diagnostic-artifact-upload-${test_dir##*/}
https_pid=
proxy_pid=
cleanup() {
	if [ -n "$https_pid" ]; then
		kill "$https_pid" >/dev/null 2>&1 || true
	fi
	if [ -n "$proxy_pid" ]; then
		kill "$proxy_pid" >/dev/null 2>&1 || true
	fi
	rm -rf "$test_dir"
	docker volume rm "$root_volume" "$upload_volume" >/dev/null 2>&1 || true
	docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || {
	echo "Docker is required for behavioral utility-image tests" >&2
	exit 1
}
command -v python3 >/dev/null 2>&1 || {
	echo "Python 3 is required to validate extracted JSON semantics" >&2
	exit 1
}
command -v openssl >/dev/null 2>&1 || {
	echo "OpenSSL is required for the disposable HTTPS uploader fixture" >&2
	exit 1
}
docker build --tag "$image" "$root"

run_image() {
	output=$1
	shift
	mkdir -p "$output"
	chmod 0777 "$output"
	docker_opts=
	while [ "$1" != -- ]; do
		docker_opts="$docker_opts $1"
		shift
	done
	shift
	# The test paths contain no spaces; options are deliberately limited to
	# the fixed Docker flags and temporary fixture mounts below.
	# shellcheck disable=SC2086
	docker run --rm --read-only --cap-drop=ALL --network none \
		--user 65532:65532 --volume "$output:/output" $docker_opts "$image" "$@"
}

run_image_default() {
	output=$1
	shift
	mkdir -p "$output"
	chmod 0777 "$output"
	docker_opts=
	while [ "$1" != -- ]; do
		docker_opts="$docker_opts $1"
		shift
	done
	shift
	# shellcheck disable=SC2086
	docker run --rm --read-only --cap-drop=ALL --network none \
		--volume "$output:/output" $docker_opts "$image" "$@"
}

run_root_collector() {
	output=$1
	shift
	docker_opts=
	while [ "$1" != -- ]; do
		docker_opts="$docker_opts $1"
		shift
	done
	shift
	# Crashdump collection needs root to read root-only host files, but the
	# effective group is the uploader group and every capability is dropped.
	# This is the real hand-off contract: no CAP_CHOWN workaround is allowed.
	# shellcheck disable=SC2086
	docker run --rm --read-only --cap-drop=ALL --network none \
		--user 0:65532 --volume "$output:/output" $docker_opts "$image" "$@"
}

assert_handoff_metadata() {
	output=$1
	file=$2
	want=$3
	# Inspect ownership and mode inside the Linux image, not on the host where
	# Docker Desktop may translate bind-mount ownership to the host account.
	got=$(docker run --rm --read-only --cap-drop=ALL --network none \
		--user 0:65532 --volume "$output:/output" --entrypoint /bin/stat \
		"$image" -c '%u:%g %a' "/output/$file")
	[ "$got" = "$want" ] || {
		echo "unexpected $file hand-off metadata: got $got want $want" >&2
		exit 1
	}
}

copy_output_file() {
	copy_output_dir=$1
	copy_name=$2
	copy_destination=$3
	docker run --rm --read-only --cap-drop=ALL --network none \
		--user 65532:65532 --volume "$copy_output_dir:/output" --entrypoint /bin/cat \
		"$image" "/output/$copy_name" >"$copy_destination"
}

mkdir "$test_dir/smoke-output"
default_uid=$(docker run --rm --read-only --cap-drop=ALL --network none \
	--entrypoint /bin/id "$image" -u)
[ "$default_uid" = 65532 ] || {
	echo "unexpected image default UID: $default_uid" >&2
	exit 1
}
for runbook_identity in 65532:65532 0:65532; do
	docker run --rm --read-only --cap-drop=ALL --network none \
		--user "$runbook_identity" --entrypoint /bin/sh "$image" -ceu '
			test -r /usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection/README.md
			test -r /usr/share/breakglass/runbooks/upstream/diagnostic-artifact-collection/RUNBOOK.md
			test "$(stat -c "%u:%g %a" /usr/share/breakglass/runbooks/internal)" = "0:0 555"
			if touch /usr/share/breakglass/runbooks/internal/untrusted 2>/dev/null; then
				echo "internal runbook mount point is writable" >&2
				exit 1
			fi
		'
done
run_image "$test_dir/smoke-output" -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
[ -f "$test_dir/smoke-output/artifact.tar.gz" ]
[ -f "$test_dir/smoke-output/artifact.manifest.json" ]
[ -f "$test_dir/smoke-output/artifact.ready" ]
mode=$(stat -c '%a' "$test_dir/smoke-output/artifact.tar.gz" 2>/dev/null ||
	stat -f '%Lp' "$test_dir/smoke-output/artifact.tar.gz")
[ "$mode" = 600 ]
mkdir "$test_dir/smoke-extracted"
copy_output_file "$test_dir/smoke-output" artifact.tar.gz "$test_dir/smoke-output/artifact.readable.tar.gz"
tar -xzf "$test_dir/smoke-output/artifact.readable.tar.gz" -C "$test_dir/smoke-extracted"
python3 -c 'import json, sys; value=json.load(open(sys.argv[1], encoding="utf-8")); assert value["recipe"] == "system-summary.v1" and value["inputs"]["maxArchiveBytes"] == 16777216' \
	"$test_dir/smoke-extracted/manifest.json"
python3 -c 'import json, sys; assert json.load(open(sys.argv[1], encoding="utf-8"))["collector_status"] == "complete"' \
	"$test_dir/smoke-extracted/files/system-summary.json"
copy_output_file "$test_dir/smoke-output" artifact.manifest.json "$test_dir/smoke-output/artifact.readable.manifest.json"
cmp "$test_dir/smoke-output/artifact.readable.manifest.json" "$test_dir/smoke-extracted/manifest.json"

run_image_default "$test_dir/default-output-created-by-helper" -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
[ -f "$test_dir/default-output-created-by-helper/artifact.tar.gz" ]

mkdir "$test_dir/extended-output"
run_image "$test_dir/extended-output" --env DIAGNOSTIC_DETAIL_LEVEL=extended -- \
	collect --recipe system-summary.v1 --output /output/artifact.tar.gz
mkdir "$test_dir/extended-extracted"
copy_output_file "$test_dir/extended-output" artifact.tar.gz "$test_dir/extended-output/artifact.readable.tar.gz"
tar -xzf "$test_dir/extended-output/artifact.readable.tar.gz" -C "$test_dir/extended-extracted"
python3 -c 'import json, sys; value=json.load(open(sys.argv[1], encoding="utf-8")); assert value["detail_level"] == "extended" and isinstance(value["cpu_count"], int) and value["cpu_count"] > 0 and isinstance(value["memory_kib"], int) and value["memory_kib"] > 0' \
	"$test_dir/extended-extracted/files/system-summary.json"

mkdir "$test_dir/crash-output" "$test_dir/coredumps" "$test_dir/coredumps/nested"
printf '%s\n' 'kernel panic fixture' >"$test_dir/coredumps/nested/panic.dump"
printf '%s\n' 'raw-core-memory-is-not-redacted' >"$test_dir/coredumps/report.txt"
printf '%s\n' 'secret fixture' >"$test_dir/coredumps/password=super secret value.dump"
printf '%s\n' 'uppercase fixture' >"$test_dir/coredumps/TOKEN=UPPERCASE credential.dump"
printf '%s\n' 'mixed-case fixture' >"$test_dir/coredumps/Api_Key=mixed credential.dump"
printf '%s\n' 'old fixture' >"$test_dir/coredumps/old.dump"
touch -t 200001010000 "$test_dir/coredumps/old.dump"
run_image "$test_dir/crash-output" --env DIAGNOSTIC_NODE=node-a --env DIAGNOSTIC_MAX_AGE_MINUTES=10080 \
	--volume "$test_dir/coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz
mkdir "$test_dir/crash-extracted"
copy_output_file "$test_dir/crash-output" artifact.tar.gz "$test_dir/crash-output/artifact.readable.tar.gz"
tar -xzf "$test_dir/crash-output/artifact.readable.tar.gz" -C "$test_dir/crash-extracted"
python3 -c 'import json, sys; value=json.load(open(sys.argv[1], encoding="utf-8")); assert value["node"] == "node-a" and value["inputs"]["maxAgeMinutes"] == 10080' \
	"$test_dir/crash-extracted/manifest.json"
cmp "$test_dir/coredumps/nested/panic.dump" "$test_dir/crash-extracted/files/coredumps/nested/panic.dump"
cmp "$test_dir/coredumps/report.txt" "$test_dir/crash-extracted/files/coredumps/report.txt"
python3 -c 'import sys; text=open(sys.argv[1], encoding="utf-8").read(); assert all(secret not in text for secret in ("super secret value", "UPPERCASE credential", "mixed credential")) and text.count("[REDACTED]") >= 3' \
	"$test_dir/crash-extracted/stdout.log"
[ ! -e "$test_dir/crash-extracted/files/coredumps/old.dump" ]

mkdir "$test_dir/mount-boundary-coredumps" "$test_dir/mount-boundary-coredumps/nested" \
	"$test_dir/mount-boundary-external" "$test_dir/mount-boundary-output"
chmod 0777 "$test_dir/mount-boundary-output"
printf '%s\n' 'same filesystem fixture' >"$test_dir/mount-boundary-coredumps/local.dump"
printf '%s\n' 'nested mount fixture' >"$test_dir/mount-boundary-external/escape.dump"
if run_root_collector "$test_dir/mount-boundary-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/mount-boundary-coredumps:/host-coredumps:ro" \
	--volume "$test_dir/mount-boundary-external:/host-coredumps/nested:ro" -- \
	collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz; then
	echo 'collector accepted a nested source mount' >&2
	exit 1
fi
[ ! -e "$test_dir/mount-boundary-output/artifact.ready" ] || {
	echo 'collector published a nested-mount artifact' >&2
	exit 1
}

docker volume create "$root_volume" >/dev/null
# The image creates /output as 65532-owned mode 0755. With CAP_DAC_OVERRIDE
# dropped, root cannot write that directory unless its owner first grants the
# shared-volume write bit; this setup mirrors a writable emptyDir mount without
# granting either container a capability.
# The setup container only prepares the disposable volume; the collector and
# uploader below both retain their read-only root filesystems. Keep a marker so
# Docker does not reinitialize an otherwise-empty named volume from the image
# on its next mount, which would restore the image's 0755 directory mode.
docker run --rm --cap-drop=ALL --network none \
	--user 65532:65532 --volume "$root_volume:/output" --entrypoint /bin/sh \
	"$image" -c 'chmod 0777 /output && touch /output/.volume-initialized'
run_root_collector "$root_volume" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz
for handoff in artifact.tar.gz artifact.manifest.json artifact.ready; do
	assert_handoff_metadata "$root_volume" "$handoff" '0:65532 640'
done

# Run the real uploader as its unprivileged identity. An intentionally
# unreachable HTTP endpoint makes the command stop after file validation; a
# permission/private-file error here would prove the root hand-off contract is
# broken before any network operation is attempted.
if uploader_result=$(docker run --rm --read-only --cap-drop=ALL --network none \
	--user 65532:65532 --volume "$root_volume:/output" \
	--env BREAKGLASS_ARTIFACT_UPLOAD_URL=http://upload.example.invalid/object \
	--env BREAKGLASS_ARTIFACT_UPLOAD_TOKEN=behavioral-test-token \
	--entrypoint /usr/local/bin/diagnostic-artifact-upload "$image" \
	--archive /output/artifact.tar.gz 2>&1); then
	echo 'root hand-off uploader unexpectedly succeeded against unreachable endpoint' >&2
	exit 1
fi
printf '%s\n' "$uploader_result" | grep -F 'HTTPS' >/dev/null
if printf '%s\n' "$uploader_result" | grep -Eiq 'private|changed while it was opened'; then
	echo "uploader rejected valid root hand-off: $uploader_result" >&2
	exit 1
fi

# Exercise the packaged uploader binary (rather than only its Go unit-test
# replacement) against a disposable, certificate-verified HTTPS fixture. The
# fixture captures the request bytes so the test proves the uploaded payload
# is exactly the archive produced by the collector.
docker volume create "$upload_volume" >/dev/null
docker run --rm --read-only --cap-drop=ALL --network none \
	--volume "$upload_volume:/output" "$image" \
	collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expected_upload="$test_dir/expected-upload.tar.gz"
docker run --rm --read-only --cap-drop=ALL --network none \
	--volume "$upload_volume:/output" --entrypoint /bin/cat "$image" \
	/output/artifact.tar.gz >"$expected_upload"
https_port_file="$test_dir/https-port"
https_body_file="$test_dir/https-body"
https_path_file="$test_dir/https-path"
https_cert="$test_dir/https-ca.pem"
https_key="$test_dir/https-key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$https_key" -out "$https_cert" \
	-subj '/CN=host.docker.internal' \
	-addext 'subjectAltName=DNS:host.docker.internal' >/dev/null 2>&1
chmod 0644 "$https_cert"
python3 - "$https_port_file" "$https_body_file" "$https_path_file" "$https_cert" "$https_key" <<'PY' &
import http.server
import ssl
import sys

port_file, body_file, path_file, cert_file, key_file = sys.argv[1:]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):  # noqa: N802
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self.send_error(411)
            return
        length = int(length_header)
        with open(body_file, "wb") as body:
            body.write(self.rfile.read(length))
        with open(path_file, "w", encoding="utf-8") as path:
            path.write(self.path)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass

server = http.server.HTTPServer(("0.0.0.0", 0), Handler)
with open(port_file, "w", encoding="utf-8") as port:
    port.write(str(server.server_port))
    port.flush()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_file, keyfile=key_file)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
server.server_close()
PY
https_pid=$!
https_port=
attempt=0
while [ ! -s "$https_port_file" ] && [ "$attempt" -lt 30 ]; do
	sleep 1
	attempt=$((attempt + 1))
done
[ -s "$https_port_file" ] || {
	echo 'HTTPS fixture did not publish a port' >&2
	exit 1
}
https_port=$(cat "$https_port_file")
# Ambient CA variables are pod-controlled input and must not re-trust the
# bearer token. The request must fail before the HTTPS fixture receives a PUT.
if attacker_ca_result=$(docker run --rm --read-only --cap-drop=ALL \
	--add-host=host.docker.internal:host-gateway \
	--volume "$upload_volume:/output" --volume "$https_cert:/tmp/attacker-ca.pem:ro" \
	--env SSL_CERT_FILE=/tmp/attacker-ca.pem --env SSL_CERT_DIR=/tmp \
	--env BREAKGLASS_ARTIFACT_UPLOAD_URL="https://host.docker.internal:$https_port/exact-object" \
	--env BREAKGLASS_ARTIFACT_UPLOAD_TOKEN=packaged-upload-token \
	--entrypoint /usr/local/bin/diagnostic-artifact-upload "$image" \
	--archive /output/artifact.tar.gz 2>&1); then
	echo 'ambient attacker CA unexpectedly authorized a packaged upload' >&2
	exit 1
fi
[ ! -e "$https_body_file" ] || {
	echo 'HTTPS fixture received bytes through the ambient attacker CA' >&2
	exit 1
}
printf '%s\n' "$attacker_ca_result" | grep -Eiq 'certificate|authority|tls' || {
	echo "unexpected ambient CA refusal: $attacker_ca_result" >&2
	exit 1
}

# A hostile proxy must not see the presigned URL or bearer token. The real
# request below still succeeds directly against the certificate-pinned fixture.
proxy_port_file="$test_dir/proxy-port"
proxy_seen_file="$test_dir/proxy-seen"
python3 - "$proxy_port_file" "$proxy_seen_file" <<'PY' &
import http.server
import sys

port_file, seen_file = sys.argv[1:]

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def _record(self):
        with open(seen_file, "w", encoding="utf-8") as seen:
            seen.write(self.command + " " + self.path)
        self.send_error(502)

    def do_CONNECT(self):  # noqa: N802
        self._record()

    def do_PUT(self):  # noqa: N802
        self._record()

    def log_message(self, *_args):
        pass

server = http.server.HTTPServer(("0.0.0.0", 0), ProxyHandler)
with open(port_file, "w", encoding="utf-8") as port:
    port.write(str(server.server_port))
    port.flush()
server.serve_forever()
server.server_close()
PY
proxy_pid=$!
attempt=0
while [ ! -s "$proxy_port_file" ] && [ "$attempt" -lt 30 ]; do
	sleep 1
	attempt=$((attempt + 1))
done
[ -s "$proxy_port_file" ] || {
	echo 'hostile proxy fixture did not publish a port' >&2
	exit 1
}
proxy_port=$(cat "$proxy_port_file")

# Mount the disposable CA only over the immutable image CA path to exercise a
# real certificate-verified packaged upload without creating an environment
# override path in the production contract.
docker run --rm --read-only --cap-drop=ALL \
	--add-host=host.docker.internal:host-gateway \
	--volume "$upload_volume:/output" \
	--volume "$https_cert:/etc/ssl/certs/ca-certificates.crt:ro" \
	--env HTTP_PROXY="http://host.docker.internal:$proxy_port" \
	--env HTTPS_PROXY="http://host.docker.internal:$proxy_port" \
	--env BREAKGLASS_ARTIFACT_UPLOAD_URL="https://host.docker.internal:$https_port/exact-object" \
	--env BREAKGLASS_ARTIFACT_UPLOAD_TOKEN=packaged-upload-token \
	--entrypoint /usr/local/bin/diagnostic-artifact-upload "$image" \
	--archive /output/artifact.tar.gz
cmp "$expected_upload" "$https_body_file"
[ "$(cat "$https_path_file")" = /exact-object ]
[ ! -e "$proxy_seen_file" ] || {
	echo 'hostile proxy received the packaged upload request' >&2
	exit 1
}
kill "$proxy_pid"
wait "$proxy_pid" 2>/dev/null || true
proxy_pid=
kill "$https_pid"
wait "$https_pid" 2>/dev/null || true
https_pid=

# The standalone uploader independently enforces the immutable recipe ceiling
# recorded by a private manifest. A deployment-wide 512 MiB cap must not let a
# forged or stale summary hand-off upload a crashdump-sized payload.
docker run --rm --read-only --cap-drop=ALL --network none \
	--user 65532:65532 --volume "$upload_volume:/output" --entrypoint /bin/sh "$image" -ceu '
		rm -f /output/artifact.tar.gz /output/artifact.manifest.json /output/artifact.ready
		truncate -s 16777217 /output/artifact.tar.gz
		printf "%s\n" '\''{"recipe":"system-summary.v1","inputs":{"maxArchiveBytes":16777216}}'\'' > /output/artifact.manifest.json
		printf "ready\n" > /output/artifact.ready
		chmod 0600 /output/artifact.tar.gz /output/artifact.manifest.json /output/artifact.ready
	'
if summary_limit_result=$(docker run --rm --read-only --cap-drop=ALL --network none \
	--user 65532:65532 --volume "$upload_volume:/output" \
	--env BREAKGLASS_ARTIFACT_UPLOAD_URL=https://upload.example.invalid/object \
	--env BREAKGLASS_ARTIFACT_UPLOAD_TOKEN=packaged-upload-token \
	--entrypoint /usr/local/bin/diagnostic-artifact-upload "$image" \
	--archive /output/artifact.tar.gz 2>&1); then
	echo 'summary archive above 16 MiB unexpectedly passed the packaged uploader' >&2
	exit 1
fi
printf '%s\n' "$summary_limit_result" | grep -F 'bounded upload limit' >/dev/null || {
	echo "unexpected summary ceiling error: $summary_limit_result" >&2
	exit 1
}

expect_failure() {
	output=$1
	shift
	mkdir -p "$output"
	chmod 0777 "$output"
	docker_opts=
	while [ "$1" != -- ]; do
		docker_opts="$docker_opts $1"
		shift
	done
	shift
	# shellcheck disable=SC2086
	if docker run --rm --read-only --cap-drop=ALL --network none \
		--user 65532:65532 --volume "$output:/output" $docker_opts "$image" "$@"; then
		echo "unsafe invocation unexpectedly succeeded: $*" >&2
		exit 1
	fi
	[ ! -e "$output/artifact.tar.gz" ]
	[ ! -e "$output/artifact.ready" ]
}

# Create high-cardinality fixtures in bounded batches. Calling mkdir/touch once
# per entry makes the behavioral limit tests unnecessarily slow on Docker
# Desktop/OrbStack bind mounts while proving no additional collector behavior.
create_fixture_entries() {
	directory=$1
	count=$2
	type=$3
	shift 3
	set --
	i=1
	while [ "$i" -le "$count" ]; do
		case "$type" in
		file)
			set -- "$@" "$directory/candidate-$i.dump"
			;;
		directory)
			set -- "$@" "$directory/dir-$i"
			;;
		esac
		if [ "$#" -eq 128 ]; then
			if [ "$type" = file ]; then
				touch "$@"
			else
				mkdir "$@"
			fi
			set --
		fi
		i=$((i + 1))
	done
	if [ "$#" -gt 0 ]; then
		if [ "$type" = file ]; then
			touch "$@"
		else
			mkdir "$@"
		fi
	fi
}

expect_preserved_collision() {
	publication=$1
	output="$test_dir/preexisting-$publication"
	mkdir "$output"
	chmod 0777 "$output"
	printf '%s\n' "pre-existing-$publication" >"$output/$publication"
	chmod 0600 "$output/$publication"
	if run_image "$output" -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz; then
		echo "collector overwrote pre-existing $publication" >&2
		exit 1
	fi
	[ "$(cat "$output/$publication")" = "pre-existing-$publication" ] || {
		echo "collector deleted or changed pre-existing $publication" >&2
		exit 1
	}
	for candidate in artifact.tar.gz artifact.manifest.json artifact.ready; do
		[ "$candidate" = "$publication" ] || [ ! -e "$output/$candidate" ] || {
			echo "collector left partial output beside pre-existing $publication" >&2
			exit 1
		}
	done
}

expect_failure "$test_dir/unknown" -- collect --recipe unknown.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/injected" -- collect --recipe 'system-summary.v1;id' --output /output/artifact.tar.gz
expect_failure "$test_dir/extra" -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz extra
expect_failure "$test_dir/env-command" --env ARTIFACT_COMMAND=id -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/bad-detail" --env DIAGNOSTIC_DETAIL_LEVEL=all -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/narrow-cap" --env BREAKGLASS_ARTIFACT_MAX_BYTES=1 -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/invalid-cap" --env BREAKGLASS_ARTIFACT_MAX_BYTES=not-a-number -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/zero-cap" --env BREAKGLASS_ARTIFACT_MAX_BYTES=0 -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/oversized-cap" --env BREAKGLASS_ARTIFACT_MAX_BYTES=536870913 -- collect --recipe system-summary.v1 --output /output/artifact.tar.gz
expect_preserved_collision artifact.tar.gz
expect_preserved_collision artifact.manifest.json
expect_preserved_collision artifact.ready
expect_failure "$test_dir/missing-node" --volume "$test_dir/coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz
expect_failure "$test_dir/bad-node" --env DIAGNOSTIC_NODE='../escape' \
	--volume "$test_dir/coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/symlink-coredumps" "$test_dir/symlink-output"
ln -s "$test_dir/coredumps/nested/panic.dump" "$test_dir/symlink-coredumps/link.dump"
expect_failure "$test_dir/symlink-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/symlink-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/hardlink-coredumps" "$test_dir/hardlink-output"
printf '%s\n' 'hardlink fixture' >"$test_dir/hardlink-coredumps/one.dump"
ln "$test_dir/hardlink-coredumps/one.dump" "$test_dir/hardlink-coredumps/two.dump"
expect_failure "$test_dir/hardlink-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/hardlink-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/external-hardlink-coredumps" "$test_dir/external-hardlink-output" "$test_dir/external-hardlink-target"
printf '%s\n' 'externally linked fixture' >"$test_dir/external-hardlink-coredumps/visible.dump"
ln "$test_dir/external-hardlink-coredumps/visible.dump" "$test_dir/external-hardlink-target/outside.dump"
expect_failure "$test_dir/external-hardlink-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/external-hardlink-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/oversize-coredumps" "$test_dir/oversize-output"
truncate -s 536870913 "$test_dir/oversize-coredumps/oversize.dump"
expect_failure "$test_dir/oversize-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/oversize-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/special-coredumps" "$test_dir/special-output"
mkfifo "$test_dir/special-coredumps/pipe"
expect_failure "$test_dir/special-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/special-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/control-coredumps" "$test_dir/control-output"
control_name=$(printf 'line1\nline2.dump')
printf '%s\n' 'control-name fixture' >"$test_dir/control-coredumps/$control_name"
expect_failure "$test_dir/control-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/control-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/candidate-coredumps" "$test_dir/candidate-output"
create_fixture_entries "$test_dir/candidate-coredumps" 4097 file
touch -t 200001010000 "$test_dir/candidate-coredumps/"*.dump
expect_failure "$test_dir/candidate-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/candidate-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/long-path-coredumps" "$test_dir/long-path-output"
long_component=$(printf '%180s' '' | tr ' ' x)
long_parent="$test_dir/long-path-coredumps"
i=1
while [ "$i" -le 3 ]; do
	long_parent="$long_parent/$long_component"
	mkdir "$long_parent"
	i=$((i + 1))
done
long_name=$(printf '%80s' '' | tr ' ' y)
printf '%s\n' 'long path fixture' >"$long_parent/$long_name.dump"
expect_failure "$test_dir/long-path-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/long-path-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

mkdir "$test_dir/entry-limit-coredumps" "$test_dir/entry-limit-output"
create_fixture_entries "$test_dir/entry-limit-coredumps" 8192 directory
expect_failure "$test_dir/entry-limit-output" --env DIAGNOSTIC_NODE=node-a \
	--volume "$test_dir/entry-limit-coredumps:/host-coredumps:ro" -- collect --recipe crashdump-collection.v1 --output /output/artifact.tar.gz

expect_failure "$test_dir/not-ready" --env BREAKGLASS_ARTIFACT_UPLOAD_URL=https://upload.example.invalid/object \
	-- upload --archive /output/artifact.tar.gz

echo "diagnostic-artifact-collector behavioral tests passed"

#!/usr/bin/env bash
# Run native CI tests against an owned, deterministic public-address HTTP/TLS fixture.
set -euo pipefail

if [[ "${CI:-}" != true || $# -eq 0 ]]; then
    echo "usage: CI=true $0 COMMAND [ARG...] (disposable Linux CI runners only)" >&2
    exit 2
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
fixture_root=$(mktemp -d)
fixture_ip=93.184.215.14
certificate=/usr/local/share/ca-certificates/zerobox-native-example.crt
route_owned=0
hosts_owned=0
certificate_owned=0
fixture_pid=

cleanup() {
    if [[ -n "$fixture_pid" ]]; then
        sudo kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    if (( certificate_owned )); then
        sudo rm -f "$certificate"
        sudo update-ca-certificates >/dev/null
    fi
    if (( hosts_owned )); then
        sudo sed -i '/# zerobox-native-fixture$/d' /etc/hosts
    fi
    if (( route_owned )); then
        sudo ip route del local "$fixture_ip/32" dev lo table local
    fi
    rm -rf "$fixture_root"
}
trap cleanup EXIT

if [[ -e "$certificate" ]] || grep -q '# zerobox-native-fixture$' /etc/hosts; then
    echo "Native network fixture is already installed; refusing to replace it" >&2
    exit 1
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$fixture_root/key.pem" -out "$fixture_root/cert.pem" \
    -subj /CN=example.com -addext subjectAltName=DNS:example.com >/dev/null 2>&1
sudo ip route add local "$fixture_ip/32" dev lo table local
route_owned=1
printf '%s example.com # zerobox-native-fixture\n' "$fixture_ip" | sudo tee -a /etc/hosts >/dev/null
hosts_owned=1
sudo install -m 0644 "$fixture_root/cert.pem" "$certificate"
certificate_owned=1
sudo update-ca-certificates >/dev/null
sudo python3 "$script_dir/ci-native-direct-fixture.py" \
    --address "$fixture_ip" --cert "$fixture_root/cert.pem" --key "$fixture_root/key.pem" \
    >"$fixture_root/server.log" 2>&1 &
fixture_pid=$!

ready=0
for _ in $(seq 1 30); do
    if curl --proxy '' -fsS --max-time 2 http://example.com | grep -q 'Example Domain' && \
       curl --proxy '' -fsS --max-time 2 https://example.com | grep -q 'Example Domain'; then
        ready=1
        break
    fi
    sleep 0.2
done
if (( ! ready )); then
    cat "$fixture_root/server.log" >&2
    exit 1
fi

"$@"

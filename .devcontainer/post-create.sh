#!/usr/bin/env bash
# Runs once when the dev container is created. Installs uv, the project with
# every extra, and the Open Policy Agent binary. The OPA download is verified
# against the checksum published on the v1.20.2 release page.
set -euo pipefail

UV_VERSION="0.12.9"
OPA_VERSION="v1.20.2"
# sha256 of opa_linux_amd64_static from
# https://github.com/open-policy-agent/opa/releases/tag/v1.20.2
OPA_SHA256="69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f"
OPA_URL="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_amd64_static"

echo "==> Installing uv ${UV_VERSION}"
python -m pip install --quiet --disable-pip-version-check "uv==${UV_VERSION}"

echo "==> Syncing project with all extras"
uv sync --all-extras

echo "==> Installing OPA ${OPA_VERSION}"
tmp="$(mktemp)"
curl -fsSL -o "${tmp}" "${OPA_URL}"
echo "${OPA_SHA256}  ${tmp}" | sha256sum -c -
install -m 0755 "${tmp}" /usr/local/bin/opa
rm -f "${tmp}"
opa version

echo "==> Ready. Try: uv run soclab compare --out runs/demo"

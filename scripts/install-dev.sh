#!/usr/bin/env bash
# Buduje provider z lokalnego source'u i podmienia binarkę w "implied local
# mirror directory" Terraform/OpenTofu (~/.terraform.d/plugins/...), żeby
# konsumujące repo (np. password-manager-terraform) od razu widziały nowy
# build przy kolejnym `tofu init`. Patrz README.md, sekcja "Build i
# instalacja lokalna (dev)".
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

version="${PROVIDER_VERSION:-0.1.0}"
os="$(go env GOOS)"
arch="$(go env GOARCH)"
os_arch="${os}_${arch}"

binary="terraform-provider-sharqey_v${version}"
dest="$HOME/.terraform.d/plugins/registry.terraform.io/moscich/sharqey/${version}/${os_arch}"

echo "==> go build -> ${binary}"
go build -o "${binary}" .

mkdir -p "${dest}"
mv "${binary}" "${dest}/"

echo "==> zainstalowano: ${dest}/${binary}"

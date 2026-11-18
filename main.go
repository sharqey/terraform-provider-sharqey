// Command terraform-provider-sharqey — Terraform provider dla Sharqey,
// wydzielony 2026-09-06 z password-manager/cmd/terraform-provider-sharqey
// (geneza: tasks/todo/026, część 4; kontynuacja: tasks/todo/062). Resource +
// data source dla sekretów Sharqey; auth lokalna, czytana z tego samego
// stanu co `sharqey` CLI zostawia (internal/localstate) — provider sam nie
// ma mechanizmu login, wzorem providera AWS czytającego ~/.aws/credentials.
// Provider odszyfrowuje/szyfruje LOKALNIE (internal/secretcrypto) — serwer
// nigdy nie widzi plaintextu ani surowych kluczy. Zobacz README.md po co
// internal/client|localstate|secretcrypto są tu skopiowane, nie importowane
// ze wspólnego modułu.
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	err := providerserver.Serve(context.Background(), New, providerserver.ServeOpts{
		Address: "registry.terraform.io/moscich/sharqey",
	})
	if err != nil {
		log.Fatal(err)
	}
}

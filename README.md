# Terraform provider for Sharqey

Manage [Sharqey](https://sharqey.com) groups, secrets and service accounts as code, and read
secrets into your infrastructure without writing them to Terraform state.

Sharqey is an end-to-end encrypted secrets manager. This provider does all encryption locally,
so the server only ever sees ciphertext.

## Requirements

- Terraform or OpenTofu **1.11 or newer**. The provider uses write-only attributes and
  ephemeral resources, which older versions cannot load.
- A Sharqey account on [app.sharqey.com](https://app.sharqey.com) or your own server, with the
  [`sharqey` CLI](https://github.com/sharqey/cli) signed in (`sharqey login`), or a local
  `.sharqey` database file.

## Usage

```hcl
terraform {
  required_providers {
    sharqey = {
      source = "sharqey/sharqey"
    }
  }
}

provider "sharqey" {}

# Read a secret without storing it in state.
ephemeral "sharqey_secret" "db" {
  group = "acme/prod"
  slug  = "db-password"
}

# Write one. `value` is write-only and never lands in state.
resource "sharqey_secret" "copy" {
  group = "acme/ci"
  type  = "env"
  title = "DB_PASSWORD"
  value = ephemeral.sharqey_secret.db.value
}
```

## Resources and data sources

| Name | Purpose |
|---|---|
| `sharqey_group` | A subgroup under an existing organization or group. |
| `sharqey_secret` | An `env` or `account` secret. `value` and `notes` are write-only. |
| `sharqey_file_secret` | A file secret (certificates, key files). `content_base64` is write-only. |
| `sharqey_service_account` | A machine identity scoped to a subgroup, for CI. |
| `sharqey_sso` | Single sign-on (OIDC or SAML) for an organization. |
| `ephemeral sharqey_secret` | Read a secret without writing it to state. |
| `data sharqey_secret` | Read a secret into state, only for attributes that cannot take an ephemeral value. |

Organizations are created in the web app, not by this provider.

## What stays in state

Secret values never do. `sharqey_service_account` returns its `token` and `private_key` once, at
creation, so they are in state as sensitive values: encrypt your state (OpenTofu state encryption
or an encrypted backend).

## Local database mode

The provider can work fully offline against a `.sharqey` file:

```hcl
provider "sharqey" {
  local_vault_path     = "./secrets/prod.sharqey"
  local_vault_password = var.vault_password
}
```

In this mode groups are not used, and secrets are identified by `title`.

## Authentication

The provider uses the session of the `sharqey` CLI (`sharqey login`), the same way the AWS
provider reads `~/.aws/credentials`. The server is the one you signed in to: for a self-hosted
instance run `sharqey login --server https://sharqey.example.com`.

## Development

```sh
go build ./...
go test ./...
```

## License

Apache License 2.0, see [LICENSE](LICENSE).

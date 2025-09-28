path "secret/data/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
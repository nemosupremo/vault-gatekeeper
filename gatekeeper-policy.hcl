/*
	Add the ability to create orphan tokens with any policy.
*/
path "auth/token/create" {
	capabilities = ["create", "read", "sudo", "update"]
}

path "auth/token/create/*" {
	capabilities = ["create", "read", "sudo", "update"]
}

path "auth/token/create-orphan" {
	capabilities = ["create", "read", "sudo", "update"]
}

// Cubbyhole Unsealing
path "secret/gatekeeper" {
	capabilities = ["read"]
}
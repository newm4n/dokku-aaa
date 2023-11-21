package internal

type User struct {
	Email      string
	Passphrase string
}

type TenantRoles struct {
	Tenant string
	Roles  []string
}

type LoginRequest struct {
	Email      string
	Passphrase string
	Tenant     string
}

type LoginResponse struct {
	Access  string
	Refresh string
}

type RefreshRequest struct {
	Refresh string
}

type RefreshResponse struct {
	Access string
}

type RegisterRequest struct {
	FullName   string
	Email      string
	Passphrase string
	TenantRole []string // role1,role2@tenant1,tenant2
}

type UnRegisterRequest struct {
	Email string
}

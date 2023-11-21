package tenantrole

import (
	"fmt"
	"strings"
)

func NewTenantRole(tenantRole string) (*TenantRole, error) {
	if strings.Contains(tenantRole, "@") {
		splt := strings.Split(tenantRole, "@")
		if len(splt) != 2 {
			return nil, fmt.Errorf("invalid tenant-role string \"%s\" need @ separator", tenantRole)
		}
		roleArr := make([]string, 0)
		tenantArr := make([]string, 0)
		for _, ro := range strings.Split(splt[0], ",") {
			roleArr = append(roleArr, strings.TrimSpace(ro))
		}
		for _, tn := range strings.Split(splt[1], ",") {
			tenantArr = append(tenantArr, strings.TrimSpace(tn))
		}
		strRoleArr := make([]string, 0)
		for _, str := range roleArr {
			strRoleArr = append(strRoleArr, strings.TrimSpace(str))
		}
		strTenantArr := make([]string, 0)
		for _, str := range strTenantArr {
			strTenantArr = append(strTenantArr, strings.TrimSpace(str))
		}

		return &TenantRole{
			roleIDs:   strRoleArr,
			tenantIDs: strTenantArr,
		}, nil
	} else {
		return nil, fmt.Errorf("invalid tenant-role string \"%s\" missing @ character", tenantRole)
	}
}

type TenantRole struct {
	tenantIDs []string
	roleIDs   []string
}

func (tr *TenantRole) Validates(tenant, role string) bool {
	return tr.tenantValid(tenant) && tr.roleValid(role)
}

func (tr *TenantRole) tenantValid(tenant string) bool {
	for _, ten := range tr.tenantIDs {
		if ten == "*" {
			return true
		}
		if ten == tenant {
			return true
		}
	}
	return false
}

func (tr *TenantRole) roleValid(role string) bool {
	for _, rol := range tr.roleIDs {
		if rol == "*" {
			return true
		}
		if rol == role {
			return true
		}
	}
	return false
}

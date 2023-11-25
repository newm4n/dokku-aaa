package internal

import (
	"context"
	"dokku-aaa/internal/tools"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/hyperjumptech/jiffy"
	"github.com/newm4n/dokku-aaa/configuration"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

var (
	ErrNotFound        = fmt.Errorf("data not found")
	ErrFound           = fmt.Errorf("data alreadt exist")
	ErrArgumentEmpty   = fmt.Errorf("argument is empty")
	ErrInvalidPassword = fmt.Errorf("wrong passphrase")
	ErrWrongIssuer     = fmt.Errorf("wrong issuer")
	ErrWrongToken      = fmt.Errorf("wrong token type")
)

type UserAccount struct {
	email      string
	passphrase string
}

type UserTenantRoles struct {
	email  string
	tenant string
	roles  []string
}

type DataAccess interface {
	CreateUserAccount(ctx context.Context, email, passphrase string) (success bool, err error)
	UpdateUserPassphrase(ctx context.Context, email, oldPassphrase, newPassphrase string) (success bool, err error)
	DeleteUserAccount(ctx context.Context, email string) (success bool, err error)
	UserExist(ctx context.Context, email string) (exist bool, err error)
	SearchUser(ctx context.Context, search string) (emails []string, err error)

	CreateUserTenant(ctx context.Context, email, tenant string) (success bool, err error)
	UpdateUserTenant(ctx context.Context, email, oldTenant, newTenant string) (success bool, err error)
	DeleteUserTenant(ctx context.Context, email, tenant string) (success bool, err error)
	DeleteUserAllTenant(ctx context.Context, email string) (success bool, err error)
	UserTenantExist(ctx context.Context, email, tenant string) (exist bool, err error)
	SearchUserTenant(ctx context.Context, email, search string) (tenants []string, err error)

	CreateUserTenantRole(ctx context.Context, email, tenant, role string) (success bool, err error)
	DeleteUserTenantRole(ctx context.Context, email, tenant, role string) (success bool, err error)
	DeleteUserTenantAllRoles(ctx context.Context, email, tenant string) (success bool, err error)
	UserTenantRoleExist(ctx context.Context, email, tenant, role string) (exist bool, err error)
	SearchUserRoleTenant(ctx context.Context, email, tenant, search string) (roles []string, err error)

	Authenticate(ctx context.Context, email, passphrase string) (accessToken, refreshToken string, err error)
	Refresh(ctx context.Context, refreshToken string) (accessToken string, err error)
}

type MemoryDAO struct {
	UserAccountList    []*UserAccount
	UserTenantRoleList []*UserTenantRoles
}

func (mdao *MemoryDAO) CreateUserAccount(ctx context.Context, email, passphrase string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(passphrase) == 0 {
		return false, ErrArgumentEmpty
	}
	exist, err := mdao.UserExist(ctx, email)
	if err != nil && err != ErrNotFound {
		return false, err
	}
	if exist {
		log.Errorf("can not create user. user with %s email aready exist in UserAccountList", email)
		return false, ErrFound
	}

	passHash, err := tools.CreateHash(passphrase, tools.DefaultParams)
	if err != nil {
		return false, ErrInvalidPassword
	}

	usrAcc := &UserAccount{
		email:      email,
		passphrase: passHash,
	}
	mdao.UserAccountList = append(mdao.UserAccountList, usrAcc)
	return true, nil
}
func (mdao *MemoryDAO) UpdateUserPassphrase(ctx context.Context, email, oldPassphrase, newPassphrase string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(oldPassphrase) == 0 || len(newPassphrase) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, acc := range mdao.UserAccountList {
		if strings.EqualFold(email, acc.email) {
			compare, err := tools.ComparePasswordAndHash(oldPassphrase, acc.passphrase)
			if err != nil {
				return false, err
			}
			if compare {
				acc.passphrase, err = tools.CreateHash(newPassphrase, tools.DefaultParams)
				if err != nil {
					return false, err
				}
				return true, nil
			} else {
				return false, nil
			}
		}
	}
	return false, nil
}
func (mdao *MemoryDAO) DeleteUserAccount(ctx context.Context, email string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 {
		return false, ErrArgumentEmpty
	}
	if len(mdao.UserAccountList) == 0 {
		return false, nil
	}
	exist, err := mdao.UserExist(ctx, email)
	if err != nil {
		return false, err
	}
	if !exist {
		return false, nil
	}
	for idx, uacc := range mdao.UserAccountList {
		if strings.EqualFold(email, uacc.email) {
			mdao.UserAccountList = append(mdao.UserAccountList[:idx], mdao.UserAccountList[idx+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (mdao *MemoryDAO) UserExist(ctx context.Context, email string) (exist bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, ual := range mdao.UserAccountList {
		if strings.EqualFold(email, ual.email) {
			return true, nil
		}
	}
	return false, nil
}
func (mdao *MemoryDAO) SearchUser(ctx context.Context, search string) (emails []string, err error) {
	if ctx == nil {
		return nil, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(search) == 0 {
		return make([]string, 0), ErrArgumentEmpty
	}
	dup := make(map[string]bool)
	for _, acc := range mdao.UserAccountList {
		l := len(search)
		if l > len(acc.email) {
			continue
		}
		if strings.EqualFold(search, acc.email[:l]) {
			dup[acc.email] = true
		}
	}
	ret := make([]string, 0)
	for k, _ := range dup {
		ret = append(ret, k)
	}
	return ret, nil
}

func (mdao *MemoryDAO) CreateUserTenant(ctx context.Context, email, tenant string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	exist, err := mdao.UserTenantExist(ctx, email, tenant)
	if err != nil {
		return false, err
	}
	if exist {
		return false, ErrFound
	}
	data := &UserTenantRoles{
		email:  email,
		tenant: tenant,
		roles:  make([]string, 0),
	}
	mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, data)
	return true, nil
}

func (mdao *MemoryDAO) UpdateUserTenant(ctx context.Context, email, oldTenant, newTenant string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(oldTenant) == 0 || len(newTenant) == 0 {
		return false, ErrArgumentEmpty
	}

	source := &UserTenantRoles{}
	target := &UserTenantRoles{}

	source = nil
	for _, em := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, em.email) && oldTenant == em.tenant {
			source = em
			break
		}
	}

	target = nil
	for _, em := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, em.email) && newTenant == em.tenant {
			target = em
			break
		}
	}

	if target == nil {
		fmt.Println("Target == nil")
	} else {
		fmt.Println("Target not Nil")
	}

	if source == nil {
		return false, ErrNotFound
	}

	if target == nil {
		nt := &UserTenantRoles{
			email:  email,
			tenant: newTenant,
			roles:  source.roles,
		}
		mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, nt)
	} else {
		target.roles = Merge(target.roles, source.roles)
	}

	return mdao.DeleteUserTenant(ctx, email, oldTenant)
}

func (mdao *MemoryDAO) DeleteUserTenant(ctx context.Context, email, tenant string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 {
		return false, ErrArgumentEmpty
	}
	for idx, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			mdao.UserTenantRoleList = append(mdao.UserTenantRoleList[:idx], mdao.UserTenantRoleList[idx+1:]...)
			break
		}
	}
	return true, nil
}

func (mdao *MemoryDAO) DeleteUserAllTenant(ctx context.Context, email string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 {
		return false, ErrArgumentEmpty
	}

	tenantsToDel := make([]string, 0)
	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) {
			tenantsToDel = append(tenantsToDel, data.tenant)
		}
	}

	for _, del := range tenantsToDel {
		success, err := mdao.DeleteUserTenant(ctx, email, del)
		if err != nil {
			return false, err
		}
		if !success {
			return false, fmt.Errorf("not success")
		}
	}

	return true, nil
}
func (mdao *MemoryDAO) UserTenantExist(ctx context.Context, email, tenant string) (exist bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, ele := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, ele.email) && tenant == ele.tenant {
			return true, nil
		}
	}
	return false, nil
}
func (mdao *MemoryDAO) SearchUserTenant(ctx context.Context, email, search string) (tenants []string, err error) {
	if ctx == nil {
		return nil, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(search) == 0 {
		return make([]string, 0), ErrArgumentEmpty
	}
	dup := make(map[string]bool)
	for _, acc := range mdao.UserTenantRoleList {
		l := len(search)
		if l > len(acc.email) {
			continue
		}
		if strings.EqualFold(email, acc.email) && strings.EqualFold(search, acc.tenant[:l]) {
			dup[acc.tenant] = true
		}
	}
	ret := make([]string, 0)
	for k, _ := range dup {
		ret = append(ret, k)
	}
	return ret, nil
}

func (mdao *MemoryDAO) CreateUserTenantRole(ctx context.Context, email, tenant, role string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 || len(role) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			for _, rs := range data.roles {
				if rs == role {
					return false, ErrFound
				}
			}
			if data.roles == nil {
				data.roles = make([]string, 0)
			}
			data.roles = append(data.roles, role)
			return true, nil
		}
	}

	utr := &UserTenantRoles{
		email:  email,
		tenant: tenant,
		roles:  []string{role},
	}
	mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, utr)
	return true, nil
}

func (mdao *MemoryDAO) DeleteUserTenantRole(ctx context.Context, email, tenant, role string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 || len(role) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			toDel := -1
			for idx, r := range data.roles {
				if r == role {
					toDel = idx
				}
			}
			if toDel == -1 {
				return false, ErrNotFound
			}
			data.roles = append(data.roles[:toDel], data.roles[toDel+1:]...)
			return true, nil
		}
	}
	return false, ErrNotFound
}
func (mdao *MemoryDAO) DeleteUserTenantAllRoles(ctx context.Context, email, tenant string) (success bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			data.roles = make([]string, 0)
			return true, nil
		}
	}
	return false, ErrNotFound
}
func (mdao *MemoryDAO) UserTenantRoleExist(ctx context.Context, email, tenant, role string) (exist bool, err error) {
	if ctx == nil {
		return false, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if len(email) == 0 || len(tenant) == 0 || len(role) == 0 {
		return false, ErrArgumentEmpty
	}
	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			ex := Contains(data.roles, role)
			return ex, nil
		}
	}
	return false, ErrNotFound
}
func (mdao *MemoryDAO) SearchUserRoleTenant(ctx context.Context, email, tenant, search string) (roles []string, err error) {
	if ctx == nil {
		return nil, ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(email) == 0 || len(tenant) == 0 || len(search) == 0 {
		return nil, ErrArgumentEmpty
	}

	for _, data := range mdao.UserTenantRoleList {
		if strings.EqualFold(email, data.email) && tenant == data.tenant {
			dup := make(map[string]bool)
			for _, rol := range data.roles {
				l := len(search)
				if l > len(rol) {
					continue
				}
				if strings.EqualFold(search, rol[:l]) {
					dup[rol] = true
				}
			}
			ret := make([]string, 0)
			for k, _ := range dup {
				ret = append(ret, k)
			}
			return ret, nil
		}
	}
	return nil, ErrNotFound
}

func (mdao *MemoryDAO) Authenticate(ctx context.Context, email, passphrase string) (accessToken, refreshToken string, err error) {
	if ctx == nil {
		return "", "", ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	//return "", "", nil
	//	for usr, mp := range mdao.UserTenantMap {
	for _, usr := range mdao.UserAccountList {
		if strings.EqualFold(email, usr.email) {
			match, err := tools.ComparePasswordAndHash(passphrase, usr.passphrase)
			if err != nil || match == false {
				return "", "", ErrInvalidPassword
			}

			auds := make([]string, 0)
			for _, data := range mdao.UserTenantRoleList {
				if strings.EqualFold(email, data.email) {
					str := fmt.Sprintf("%s@%s", strings.Join(data.roles, ","), data.tenant)
					auds = append(auds, str)
				}
			}

			now := time.Now()

			durAccess, err := jiffy.DurationOf(configuration.Get("token.age.access"))
			if err != nil {
				return "", "", err
			}

			durRefresh, err := jiffy.DurationOf(configuration.Get("token.age.refresh"))
			if err != nil {
				return "", "", err
			}

			expAccess := now.Add(durAccess)
			expRefresh := now.Add(durRefresh)

			// TODO set proper audience for claims
			accessClaim := &tools.GoClaim{
				Issuer:     configuration.Get("token.issuer"),
				Subscriber: email,
				TokenType:  tools.AccessToken,
				Audience:   auds,
				NotBefore:  now,
				IssuedAt:   now,
				ExpireAt:   expAccess,
				Tokenid:    "",
			}
			refeshClaim := &tools.GoClaim{
				Issuer:     configuration.Get("token.issuer"),
				Subscriber: email,
				TokenType:  tools.RefreshToken,
				Audience:   auds,
				NotBefore:  now,
				IssuedAt:   now,
				ExpireAt:   expRefresh,
				Tokenid:    "",
			}

			key, err := tools.LoadPrivateKey()
			if err != nil {
				return "", "", err
			}

			accessToken, err := accessClaim.ToToken(key, crypto.SigningMethodRS512)
			if err != nil {
				return "", "", err
			}

			refeshToken, err := refeshClaim.ToToken(key, crypto.SigningMethodRS512)
			if err != nil {
				return "", "", err
			}

			return accessToken, refeshToken, nil
		}
	}
	return "", "", fmt.Errorf("no such user for user %s", email)
}
func (mdao *MemoryDAO) Refresh(ctx context.Context, refreshToken string) (accessToken string, err error) {
	if ctx == nil {
		return "", ErrArgumentEmpty
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if len(refreshToken) == 0 {
		return "", ErrArgumentEmpty
	}

	pubKey, err := tools.LoadPublicKey()
	if err != nil {
		return "", err
	}
	oClaim, err := tools.NewGoClaimFromToken(refreshToken, pubKey, crypto.SigningMethodRS512)
	if err != nil {
		return "", err
	}
	if oClaim.Issuer != configuration.Get("token.issuer") {
		return "", ErrWrongIssuer
	}
	if oClaim.TokenType != tools.RefreshToken {
		return "", ErrWrongToken
	}

	now := time.Now()

	durAccess, err := jiffy.DurationOf(configuration.Get("token.age.access"))
	if err != nil {
		return "", err
	}

	expAccess := now.Add(durAccess)

	nClaim := &tools.GoClaim{
		Issuer:     oClaim.Issuer,
		Subscriber: oClaim.Subscriber,
		TokenType:  tools.AccessToken,
		Audience:   oClaim.Audience,
		NotBefore:  now,
		IssuedAt:   now,
		ExpireAt:   expAccess,
		Tokenid:    "",
	}
	privKey, err := tools.LoadPrivateKey()
	if err != nil {
		return "", err
	}
	return nClaim.ToToken(privKey, crypto.SigningMethodRS512)
}

func Contains(arr []string, str string) bool {
	if arr == nil || len(arr) == 0 {
		return false
	}
	for _, stri := range arr {
		if stri == str {
			return true
		}
	}
	return false
}

func Merge(one, two []string) []string {
	if one != nil && two == nil {
		return one
	}
	if one == nil && two != nil {
		return two
	}
	if one == nil && two == nil {
		return make([]string, 0)
	}
	dup := make(map[string]bool)
	for _, s := range one {
		dup[s] = true
	}
	for _, s := range two {
		dup[s] = true
	}
	ret := make([]string, 0)
	for k := range dup {
		ret = append(ret, k)
	}
	return ret
}

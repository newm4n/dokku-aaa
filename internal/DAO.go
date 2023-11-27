package internal

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/hyperjumptech/jiffy"
	"github.com/newm4n/dokku-aaa/configuration"
	security "github.com/newm4n/dokku-common/security"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
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

	priateKey *rsa.PrivateKey
	publicKey *rsa.PublicKey
)

const (
	DefaultPublicPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAsZ6vq7T+E6UnFHf1i5wljs4c+dpXTsIa1fk6S6Z74v/V7AjW
qXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJH9W5F4Ppz1dNIJBU5qYsJOEwIl1/
uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1l+axo5ULaBnWW0IJqYipMU58IlVR
c+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8U+cnv7wav+N/2G4hSgakYJofhkx+
watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/Gr1F29l4A1wGjQt0oA3eTATFng+j
D0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M9wIDAQABAoIBAAnuJUQkSlAu25B5
ZHD5ud/SBiyx2E++6mEsHeY82JBIXV1k4Rt4rpERWncPavqgHw9u5DUfjVb4THq9
D1LG00vEVyTJazj8WIOJjjWW9MDbFiXVtF5U14z7mKcNMBApms1NqIsSTJfqsDHs
fAeziH+Flkje/FRFnYZcms2vpkXrVUd191Rr2Zwc0m8vLroAq5LGE9uFbNM5z1mL
FTUaESnQdNf+Pg6It9p/eJ+jXbN98dbNCd2xObD+LrPLeSMpy2o41Bqk6vLN7pwN
zI5jGMgaIC7SHZHiU5O+mnsbQ2kBknubXgKxm6SuaVp13TCd9tNW7Wu74MznUJ3T
AQsZeoECgYEA+Ay0grNBnNWTejg20zVexO4t3etvd+NpHu268kIf87L9NX16hYAd
IZvAXzlu0Y0hzA9SA/xygtTXdm6HZhl+4VFjLfLwudVVLFPf2RqinJdyrI6lbgE9
ksUBpFL2dtzCmPQ70Rj791u9Ai1k6/zh6XqDL0ITAg70KrL5iDHmWVUCgYEAt1AX
Y9Nxqkeiq2WqN1VmFqqW/FwwsqybuggaTKCQ3Zj5sNR8aMIYpY7kUTf/+Xk5Wdcy
VAMMr824SVqgeNyd8YnTIn9htRs5g/moO5+GQrVk2YPR6m1x6drj7c5d74VEubdk
ech4Yg25Vra1roC+cvgZdgSPa7mxmZ5TVMRhHRsCgYEAy2wP9UfwvR/iLE9BlwCj
0bjK4L4d0iIrqXOo5tgXwBG/2kgnXKhuO4uxveYp3axyVRkTV7WGa4kFklierbqm
9T17qskbZitwCERYxYE0bls9bgol3QsjZeQuroZjHaN561oQXDCzIm6XmNuFcosW
8hTI1M7JK9z7nLDeNzVFBWkCgYAls7RL1MYw9nDPfaZnoQnRKZ7KIo/lf7i7p0T5
c6C34umf4+P+i8UT7/KnfbQI9FTGVItGWiY21kHL3HbaxM07S1SAaOCIpiPLMALY
2HN9rt8iGYmIBKCEL3/nfiU1yRwcckqY/ZE84YO4APYXAOWqsbpS2pdA2b1cUgLj
kUxD9wJ/BrLnevv6y7BA/oOsf5yl9WvgCaYgFKiUxTwgZmjDP/W36HYDV9is8MwQ
9VRjLLMXN1p/UYxNjFJlUJwjLMmGcKR9rVtJxFI+I65I1wrCGl9A8vsyS/oKZVKy
hMmtM9D7v/lK/yBAJzHLA7QD+EiDuEk26Xob30B7mk5PuNLRDQ==
-----END RSA PRIVATE KEY-----`
	DefaultPrivatePEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZ6vq7T+E6UnFHf1i5wl
js4c+dpXTsIa1fk6S6Z74v/V7AjWqXzJ52aI+N18yf+PD4HuZN/AvDOqIjQgaGUJ
H9W5F4Ppz1dNIJBU5qYsJOEwIl1/uRkBPtKPRtYESVbYPPU6va7ttZv0lZEvPpJ1
l+axo5ULaBnWW0IJqYipMU58IlVRc+sJEV0sC4vvPHk62/VixpjskHuGeD0fmNu8
U+cnv7wav+N/2G4hSgakYJofhkx+watP2wHBCrSDMq8rc4socdWebmISQhoCkwI/
Gr1F29l4A1wGjQt0oA3eTATFng+jD0MLmR3lP7elATNTmHawpBH6IqWX9eKVSJ8M
9wIDAQAB
-----END PUBLIC KEY-----`
)

func GetPrivateKey() *rsa.PrivateKey {
	if priateKey != nil {
		return priateKey
	}
	filePath := configuration.Get("token.key.private.pem.path")
	if fl, err := os.Open(filePath); err == nil {
		if fileBytes, err := io.ReadAll(fl); err == nil {
			if priKey, err := security.BytesToPrivateKey(fileBytes); err == nil {
				priateKey = priKey
				return priateKey
			}
		}
	}
	log.Errorf("Can not load private key from file, using default private key. THIS IS NOT SAVE")
	priKey, err := security.BytesToPrivateKey([]byte(DefaultPrivatePEM))
	if err != nil {
		panic(err)
	}
	priateKey = priKey
	return priateKey
}

func GetPublicKey() *rsa.PublicKey {
	if publicKey != nil {
		return publicKey
	}
	filePath := configuration.Get("token.key.public.pem.path")
	if fl, err := os.Open(filePath); err == nil {
		if fileBytes, err := io.ReadAll(fl); err == nil {
			if pubKey, err := security.BytesToPublicKey(fileBytes); err == nil {
				publicKey = pubKey
				return publicKey
			}
		}
	}
	log.Errorf("Can not load public key from file, using default public key. THIS IS NOT SAVE")
	pubKey, err := security.BytesToPublicKey([]byte(DefaultPublicPEM))
	if err != nil {
		panic(err)
	}
	publicKey = pubKey
	return publicKey
}

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

	passHash, err := security.CreateHash(passphrase, security.DefaultParams)
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
			compare, err := security.ComparePasswordAndHash(oldPassphrase, acc.passphrase)
			if err != nil {
				return false, err
			}
			if compare {
				acc.passphrase, err = security.CreateHash(newPassphrase, security.DefaultParams)
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
			match, err := security.ComparePasswordAndHash(passphrase, usr.passphrase)
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
			accessClaim := &security.GoClaim{
				Issuer:     configuration.Get("token.issuer"),
				Subscriber: email,
				TokenType:  security.AccessToken,
				Audience:   auds,
				NotBefore:  now,
				IssuedAt:   now,
				ExpireAt:   expAccess,
				Tokenid:    "",
			}
			refeshClaim := &security.GoClaim{
				Issuer:     configuration.Get("token.issuer"),
				Subscriber: email,
				TokenType:  security.RefreshToken,
				Audience:   auds,
				NotBefore:  now,
				IssuedAt:   now,
				ExpireAt:   expRefresh,
				Tokenid:    "",
			}

			private := GetPrivateKey()

			accessToken, err := accessClaim.ToToken(private, crypto.SigningMethodRS512)
			if err != nil {
				return "", "", err
			}

			refeshToken, err := refeshClaim.ToToken(private, crypto.SigningMethodRS512)
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

	pubKey := GetPublicKey()
	oClaim, err := security.NewGoClaimFromToken(refreshToken, pubKey, crypto.SigningMethodRS512)
	if err != nil {
		return "", err
	}
	if oClaim.Issuer != configuration.Get("token.issuer") {
		return "", ErrWrongIssuer
	}
	if oClaim.TokenType != security.RefreshToken {
		return "", ErrWrongToken
	}

	now := time.Now()

	durAccess, err := jiffy.DurationOf(configuration.Get("token.age.access"))
	if err != nil {
		return "", err
	}

	expAccess := now.Add(durAccess)

	nClaim := &security.GoClaim{
		Issuer:     oClaim.Issuer,
		Subscriber: oClaim.Subscriber,
		TokenType:  security.AccessToken,
		Audience:   oClaim.Audience,
		NotBefore:  now,
		IssuedAt:   now,
		ExpireAt:   expAccess,
		Tokenid:    "",
	}
	privKey := GetPrivateKey()
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

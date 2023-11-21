package internal

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMemoryDAO_CreateUserAccount(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}

	exist, err := mdao.UserExist(context.Background(), "user@email.com")
	assert.NoError(t, err)
	assert.False(t, exist)

	success, err := mdao.CreateUserAccount(context.Background(), "user@email.com", "this is a password")
	assert.NoError(t, err)
	assert.True(t, success)

	exist, err = mdao.UserExist(context.Background(), "user@email.com")
	assert.NoError(t, err)
	assert.True(t, exist)
}

func TestMemoryDAO_UpdateUserPassphrase(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}

	exist, err := mdao.UserExist(context.Background(), "user@email.com")
	assert.NoError(t, err)
	assert.False(t, exist)

	success, err := mdao.CreateUserAccount(context.Background(), "user@email.com", "this is a password")
	assert.NoError(t, err)
	assert.True(t, success)

	// todo Use the old password to login
	// todo Use the new password to login

	success, err = mdao.UpdateUserPassphrase(context.Background(), "user@email.com", "this is a password", "this is a new password")
	assert.NoError(t, err)
	assert.True(t, success)

	// todo Use the new password to login
}

func TestMemoryDAO_DeleteUserAccount(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}

	exist, err := mdao.UserExist(context.Background(), "user1@email.com")
	assert.NoError(t, err)
	assert.False(t, exist)

	success, err := mdao.CreateUserAccount(context.Background(), "user1@email.com", "this is a password")
	assert.NoError(t, err)
	assert.True(t, success)

	exist, err = mdao.UserExist(context.Background(), "user1@email.com")
	assert.NoError(t, err)
	assert.True(t, exist)

	exist, err = mdao.UserExist(context.Background(), "user2@email.com")
	assert.NoError(t, err)
	assert.False(t, exist)

	success, err = mdao.CreateUserAccount(context.Background(), "user2@email.com", "this is anpther password")
	assert.NoError(t, err)
	assert.True(t, success)

	exist, err = mdao.UserExist(context.Background(), "user2@email.com")
	assert.NoError(t, err)
	assert.True(t, exist)

	success, err = mdao.DeleteUserAccount(context.Background(), "user2@email.com")
	assert.NoError(t, err)
	assert.True(t, success)

	exist, err = mdao.UserExist(context.Background(), "user2@email.com")
	assert.NoError(t, err)
	assert.False(t, exist)

	exist, err = mdao.UserExist(context.Background(), "user1@email.com")
	assert.NoError(t, err)
	assert.True(t, exist)
}

func TestMemoryDAO_SearchUser(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}
	mdao.UserAccountList = append(mdao.UserAccountList, &UserAccount{
		email: "abc123@123.com",
	})
	mdao.UserAccountList = append(mdao.UserAccountList, &UserAccount{
		email: "abc234@123.com",
	})
	mdao.UserAccountList = append(mdao.UserAccountList, &UserAccount{
		email: "def123@123.com",
	})
	mdao.UserAccountList = append(mdao.UserAccountList, &UserAccount{
		email: "def234@123.com",
	})

	ret, err := mdao.SearchUser(context.Background(), "def")
	assert.NoError(t, err)
	assert.NotNil(t, ret)
	assert.Equal(t, 2, len(ret))
	for i, em := range ret {
		t.Log(i, " ", em)
	}
}

func TestMemoryDAO_CreateUserTenant(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}

	mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, &UserTenantRoles{
		email:  "abc123@123.com",
		tenant: "ABC",
		roles:  make([]string, 0),
	})

	success, err := mdao.CreateUserTenant(context.Background(), "abc234@123.com", "ABC")
	assert.NoError(t, err)
	assert.True(t, success)

	success, err = mdao.CreateUserTenant(context.Background(), "abc123@123.com", "ABC")
	assert.Error(t, err)
	assert.False(t, success)
}

func TestMemoryDAO_UpdateUserTenant(t *testing.T) {
	mdao := &MemoryDAO{
		UserAccountList:    make([]*UserAccount, 0),
		UserTenantRoleList: make([]*UserTenantRoles, 0),
	}

	t.Run("Run copy new", func(t *testing.T) {
		mdao.UserTenantRoleList = make([]*UserTenantRoles, 0)
		mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, &UserTenantRoles{
			email:  "abc123@123.com",
			tenant: "ABC",
			roles:  make([]string, 0),
		})

		assert.Equal(t, 1, len(mdao.UserTenantRoleList))

		success, err := mdao.UpdateUserTenant(context.Background(), "abc123@123.com", "ABC", "AAA")
		assert.NoError(t, err)
		assert.True(t, success)

		assert.Equal(t, 1, len(mdao.UserTenantRoleList))

		for _, el := range mdao.UserTenantRoleList {
			assert.Equal(t, "abc123@123.com", el.email)
			assert.Equal(t, "AAA", el.tenant)
		}
	})

	t.Run("Run copy exist", func(t *testing.T) {
		mdao.UserTenantRoleList = make([]*UserTenantRoles, 0)
		mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, &UserTenantRoles{
			email:  "abc123@123.com",
			tenant: "ABC",
			roles:  []string{"R2"},
		})
		mdao.UserTenantRoleList = append(mdao.UserTenantRoleList, &UserTenantRoles{
			email:  "abc123@123.com",
			tenant: "AAA",
			roles:  []string{"R1"},
		})

		assert.Equal(t, 2, len(mdao.UserTenantRoleList))

		success, err := mdao.UpdateUserTenant(context.Background(), "abc123@123.com", "ABC", "AAA")
		assert.NoError(t, err)
		assert.True(t, success)

		assert.Equal(t, 1, len(mdao.UserTenantRoleList))

		for _, el := range mdao.UserTenantRoleList {
			assert.Equal(t, "abc123@123.com", el.email)
			assert.Equal(t, "AAA", el.tenant)
		}
	})
}

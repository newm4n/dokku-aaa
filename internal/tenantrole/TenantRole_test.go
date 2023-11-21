package tenantrole

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTenantRole_Validates(t *testing.T) {
	tr, err := NewTenantRole("admin,user,janitor@surabaya,padang,makasar")
	assert.NoError(t, err)
	assert.True(t, tr.Validates("surabaya", "admin"))
	assert.True(t, tr.Validates("surabaya", "user"))
	assert.True(t, tr.Validates("surabaya", "janitor"))
	assert.False(t, tr.Validates("surabaya", "notenant"))
	assert.False(t, tr.Validates("surabaya", ""))
	assert.True(t, tr.Validates("padang", "admin"))
	assert.True(t, tr.Validates("padang", "user"))
	assert.True(t, tr.Validates("padang", "janitor"))
	assert.False(t, tr.Validates("padang", "notenant"))
	assert.False(t, tr.Validates("padang", ""))
	assert.True(t, tr.Validates("makasar", "admin"))
	assert.True(t, tr.Validates("makasar", "user"))
	assert.True(t, tr.Validates("makasar", "janitor"))
	assert.False(t, tr.Validates("makasar", "notenant"))
	assert.False(t, tr.Validates("makasar", ""))
}

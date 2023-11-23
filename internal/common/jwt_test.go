package common

import (
	"embed"
	"github.com/SermoDigital/jose/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var (
	//go:embed ../testkey
	keyFs embed.FS
)

func TestGoClaim_MarshalUnmarshal(t *testing.T) {
	//privKey, pubKey, err := GenerateKeyPair(2048)
	//assert.NoError(t, err)

	claim := &GoClaim{
		Issuer:     "Issuer.com",
		Subscriber: "subs@Issuer.com",
		TokenType:  AccessToken,
		Audience:   []string{},
		NotBefore:  time.Time{},
		IssuedAt:   time.Time{},
		ExpireAt:   time.Time{},
		Tokenid:    "",
	}

	//privateBytes, err := keyFs.ReadFile("testkey/ori_pri.pem")
	privateBytes, err := keyFs.ReadFile("testkey/private.pem")
	assert.NoError(t, err)
	assert.NotNil(t, privateBytes)

	privk, err := BytesToPrivateKey(privateBytes)
	assert.NoError(t, err)

	token, err := claim.ToToken(privk, crypto.SigningMethodRS512)
	assert.NoError(t, err)

	//publicBytes, err := keyFs.ReadFile("testkey/ori_pub.pem")
	publicBytes, err := keyFs.ReadFile("testkey/public.pem")
	assert.NoError(t, err)
	assert.NotNil(t, publicBytes)

	pubk, err := BytesToPublicKey(publicBytes)
	assert.NoError(t, err)

	klaim, err := NewGoClaimFromToken(token, pubk, crypto.SigningMethodRS512)
	assert.NoError(t, err)

	assert.Equal(t, claim.Issuer, klaim.Issuer)
	assert.Equal(t, claim.Subscriber, klaim.Subscriber)

	assert.Equal(t, string(claim.TokenType), string(klaim.TokenType))

	assert.Equal(t, claim.Audience, klaim.Audience)
	assert.Equal(t, claim.NotBefore, klaim.NotBefore)
	assert.Equal(t, claim.IssuedAt, klaim.IssuedAt)
	assert.Equal(t, claim.ExpireAt, klaim.ExpireAt)
	assert.Equal(t, claim.Tokenid, klaim.Tokenid)
}

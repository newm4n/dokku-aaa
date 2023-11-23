package common

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/newm4n/dokku-aaa/configuration"
	"io"
	"os"
	"strings"
	"time"
)

type TokenType string

const (
	AccessToken  TokenType = "application/at+jwt"
	RefreshToken TokenType = "application/rt+jwt"
)

func NewGoClaimFromToken(tokenString string, verifyKey *rsa.PublicKey, signM *crypto.SigningMethodRSA) (*GoClaim, error) {
	jwt, err := jws.ParseJWT([]byte(tokenString))
	if err != nil {
		return nil, fmt.Errorf("malformed jwt token")
	}

	if verifyKey != nil {
		if err := jwt.Validate(verifyKey, signM); err != nil {
			return nil, err
		}
	}
	claims := jwt.Claims()
	gc := &GoClaim{}
	for k, v := range claims {
		if strings.EqualFold(k, "iss") {
			gc.Issuer = v.(string)
		} else if strings.EqualFold(k, "sub") {
			gc.Subscriber = v.(string)
		} else if strings.EqualFold(k, "aud") {
			arrs := v.([]interface{})
			gc.Audience = make([]string, 0)
			for _, str := range arrs {
				gc.Audience = append(gc.Audience, str.(string))
			}
		} else if strings.EqualFold(k, "typ") {
			gc.TokenType = TokenType(v.(string))
		} else if strings.EqualFold(k, "nbf") {
			gc.NotBefore = time.Unix(v.(int64), 0)
		} else if strings.EqualFold(k, "iat") {
			gc.IssuedAt = time.Unix(v.(int64), 0)
		} else if strings.EqualFold(k, "exp") {
			gc.ExpireAt = time.Unix(v.(int64), 0)
		} else if strings.EqualFold(k, "jti") {
			gc.Tokenid = v.(string)
		}
	}
	return gc, nil
}

type GoClaim struct {
	Issuer     string
	Subscriber string
	TokenType  TokenType
	Audience   []string
	NotBefore  time.Time
	IssuedAt   time.Time
	ExpireAt   time.Time
	Tokenid    string
}

func (gc *GoClaim) String() string {
	needComma := false
	adayAgo := time.Now().Add(time.Duration(-24 * time.Hour))

	buff := bytes.Buffer{}
	buff.WriteString("{")
	if gc.Issuer != "" {
		buff.WriteString(fmt.Sprintf("uss:%s", gc.Issuer))
		needComma = true
	}
	if gc.Subscriber != "" {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("sub:%s", gc.Subscriber))
		needComma = true
	}
	if gc.TokenType != "" {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("typ:%s", gc.TokenType))
		needComma = true
	}

	if gc.Audience != nil && len(gc.Audience) > 0 {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("aud:[\"%s\"]", strings.Join(gc.Audience, "\",\"")))
		needComma = true
	}

	if gc.NotBefore.After(adayAgo) {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("nbf:%d", gc.NotBefore.Unix()))
		needComma = true
	}

	if gc.IssuedAt.After(adayAgo) {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("iat:%d", gc.IssuedAt.Unix()))
		needComma = true
	}

	if gc.ExpireAt.After(adayAgo) {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("exp:%d", gc.ExpireAt.Unix()))
		needComma = true
	}

	if gc.Tokenid != "" {
		if needComma {
			buff.WriteString(",")
		}
		buff.WriteString(fmt.Sprintf("jit:%s", gc.Tokenid))
	}

	buff.WriteString("}")
	return buff.String()
}

func (gc *GoClaim) ToToken(signing *rsa.PrivateKey, signM *crypto.SigningMethodRSA) (string, error) {

	claims := jws.Claims{}
	if len(gc.Issuer) > 0 {
		claims.SetIssuer(gc.Issuer)
	}
	if len(gc.Subscriber) > 0 {
		claims.SetSubject(gc.Subscriber)
	}
	if gc.Subscriber != "" && len(gc.Subscriber) > 0 {
		claims.SetAudience(gc.Audience...)
	}
	adayAgo := time.Now().Add((24 * time.Hour) * (-1))
	if gc.IssuedAt.After(adayAgo) {
		claims.SetIssuedAt(gc.IssuedAt)
	}
	if gc.NotBefore.After(adayAgo) {
		claims.SetNotBefore(gc.NotBefore)
	}
	if gc.ExpireAt.After(adayAgo) {
		claims.SetExpiration(gc.ExpireAt)
	}
	if gc.TokenType != "" && len(gc.TokenType) > 0 {
		claims.Set("typ", gc.TokenType)
	}

	jwtBytes := jws.NewJWT(claims, signM)
	tokenByte, err := jwtBytes.Serialize(signing)
	if err != nil {
		return "", err
	}
	return string(tokenByte), nil
}

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func LoadPublicKey() (*rsa.PublicKey, error) {
	if publicKey == nil {
		keyPath := configuration.Get("token.key.public.pem.path")
		file, err := os.Open(keyPath)
		if err != nil {
			return nil, err
		}
		fstat, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if fstat.IsDir() {
			return nil, fmt.Errorf("%s is directory", keyPath)
		}
		content, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		pubKey, err := BytesToPublicKey(content)
		if err != nil {
			return nil, err
		}
		publicKey = pubKey
		return pubKey, nil
	}
	return publicKey, nil
}

func LoadPrivateKey() (*rsa.PrivateKey, error) {
	if privateKey == nil {
		keyPath := configuration.Get("token.key.private.pem.path")
		file, err := os.Open(keyPath)
		if err != nil {
			return nil, err
		}
		fstat, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if fstat.IsDir() {
			return nil, fmt.Errorf("%s is directory", keyPath)
		}
		content, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		privk, err := BytesToPrivateKey(content)
		if err != nil {
			return nil, err
		}
		privateKey = privk
		return privk, nil
	}
	return privateKey, nil
}

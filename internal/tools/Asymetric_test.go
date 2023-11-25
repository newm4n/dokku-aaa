package tools

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"math/rand"
	"testing"
)

const (
	CharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func MakeRandomText(length int) string {
	var buff bytes.Buffer
	for buff.Len() < length {
		off := rand.Intn(len(CharSet))
		buff.WriteString(CharSet[off : off+1])
	}
	return buff.String()
}

//func TestKeyFileLoadUnload(t *testing.T) {
//
//	//rand.Seed(time.Now().UnixMicro())
//
//	privBytes, err := os.ReadFile("C:\\Users\\Ferdinand Neman\\WSL\\Laboratory\\Go\\src\\github.com\\hyperjumptech\\peduli-lindungi-qr-cert\\report\\ID_RSA")
//	if err != nil {
//		t.Errorf(err.Error())
//		t.FailNow()
//	}
//	genPriv, err := BytesToPrivateKey(privBytes)
//	if err != nil {
//		t.Errorf(err.Error())
//		t.Fail()
//	}
//	pubBytes, err := os.ReadFile("C:\\Users\\Ferdinand Neman\\WSL\\Laboratory\\Go\\src\\github.com\\hyperjumptech\\peduli-lindungi-qr-cert\\report\\ID_RSA.pub")
//	if err != nil {
//		t.Errorf(err.Error())
//		t.FailNow()
//	}
//	genPub, err := BytesToPublicKey(pubBytes)
//	if err != nil {
//		t.Errorf(err.Error())
//		t.Fail()
//	}
//	data := MakeRandomText(100)
//	encode, err := EncryptWithPublicKey([]byte(data), genPub)
//	if err != nil {
//		t.Errorf(err.Error())
//		t.FailNow()
//	}
//	decoded, err := DecryptWithPrivateKey(encode, genPriv)
//	if err != nil {
//		t.Errorf(err.Error())
//		t.FailNow()
//	}
//
//	if len(data) != len(decoded) {
//		t.Error("content not equal")
//		t.FailNow()
//	}
//	for i := 0; i < len(data); i++ {
//		if data[i] != decoded[i] {
//			t.Error("content different")
//			t.Fail()
//			break
//		}
//	}
//}

func TestDecryptSA(t *testing.T) {
	origin := `abc`
	source := `HhMaPaWvExZLmINy+DHj4Q1BDLzQHtRDl/Yfq1bcrE5aJUaOX2QX+x/ZBLo8hLHyqgLeVGkbSJ+DbZHLqYbJ29UOF8zRD3RzNW15b/w4060Zc5a2LgofQoL1UAskKRg+z4Xg4DQOXKnS03IM7p7p2MCrzsSDISjstH9G8n39ekhlKn1IsJqvfV6DzsAJzHWsp2lU07mD1AlcLFrviiud89DQM+RbQax38f+4deSwUD2EfQfYrPbBrlayQtaxnghRQfUhj8wFH8UCEDfc0BMpFQI5JJZKVX985GmEsvEDesRCmLwCY93NVJnv+wDxFwIPu5WVkxSlQfTXWnJeEkOQgg==`

	publicKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhwCT/t6T4/mbC2l9jXV
N+K4rFfmPSLU++qmPDlqL5Ou8dsCTKRQGq6RD9nUT1UsI1khKqpzUlFR9zfDgV+H
6ODU9jPTPH8MuGZW1HB1UIgdaLuWv7jdVtBhR2gV2gZF6h+FSV71zqNIUias5wxK
dxIrjflj8jadmW+hYy7eozVPWe9DPBe8CR4/Rabzto9nYN+loWvfkTIhFEHJ81Vp
fKCvvtU02ve0qpCQi93zFkzlHNTkIk8vMxJGd9y9q4v4BneiWg98K5uIgi6Hch3h
nBMQLD2+I9AHh/y6PQxVdQic95biGHYv2fodbMrO1PVGaWwwWsBKH76laofLtt6o
awIDAQAB
-----END RSA PUBLIC KEY-----`

	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyhwCT/t6T4/mbC2l9jXVN+K4rFfmPSLU++qmPDlqL5Ou8dsC
TKRQGq6RD9nUT1UsI1khKqpzUlFR9zfDgV+H6ODU9jPTPH8MuGZW1HB1UIgdaLuW
v7jdVtBhR2gV2gZF6h+FSV71zqNIUias5wxKdxIrjflj8jadmW+hYy7eozVPWe9D
PBe8CR4/Rabzto9nYN+loWvfkTIhFEHJ81VpfKCvvtU02ve0qpCQi93zFkzlHNTk
Ik8vMxJGd9y9q4v4BneiWg98K5uIgi6Hch3hnBMQLD2+I9AHh/y6PQxVdQic95bi
GHYv2fodbMrO1PVGaWwwWsBKH76laofLtt6oawIDAQABAoIBAEurau45MFUDgnj0
KlPhWeAfoZbdHhW7qdRbyTt5H5mKiJCCt/yr9FXZD/TIUKYXNHxTjYhk4uJqEe8m
UKtqcf8t1m4Lf0YCJ2gO4OmO5U1ueNxSh6FmfHBZemJ6xNupR5ndjVCoHg3sslIX
qtqijmrAQdBZFCOGcUEWO21gCfk+fHJ2/qvp41nDpGoHYP6YBp7cb5wCCoERzqFR
jjAHSIYmgs5PCycK7/t6nlWRbt90hRra9Ulpz7VhEL/wvnb/8+Wpfk8xxqOb2cnl
mSoozpY2klkXlpovIwmx32w0w7Q30oT79DMyl5gYr0bxp56/lclnJ6ijYpObh0qv
jm8AWjECgYEA96jjCYYcHCJXC2lpLexrqVujaJq2r2O9PcrNq2qt77o/nc9whVgx
m9YlYouPnhPwmYgtRuv408pHjqu0tEXNRM98fQvWWEAAszGSbT/ROs+JmBlxiZR8
7JsWqtVZjkHwyGcfDyBb2wNN5Gmliz0zAOpgXpH/mYVWx1WaQKRubGMCgYEA0Opt
BgE4sqyqR6J8McC9M8q2+vgFfMRGqU7l1gxRCoFb5UhmlGIwnrRcjeQY024EUQMx
r5d65JgD1qito+00ng9qB8MNtWMCCNjibpqRwOG+/v0rlsqBLQy144WpHi554m6e
JLY9dlUcLX91R+3HViCAO5RIlz10fiVh92JJPlkCgYEAi4eIGiaHkcY7Gj/SNUBc
y7bIUrfPsvLTfIvU4f2hb02UZ9mmQEoW8QBuYZ3VVS9Qv388Wxe5QcFWHWhZz7L/
2gO31E+l/GRawJpuL8TjoWmp0JqNIAEbfMZHuAmpgf9eo9mNYx1NAxBSgxyOWuso
4BwsHTvOMHUyFe4BkOfTGpcCgYAFlo+t/nBezyGK4vzBc+9bqEt2sRWsfa+KLdMW
A6RTTJyBqIsd4vZ7+EUVgolrdmDlLdmxYbLm1G4d2ssyPFEQ/UaPyJbgSDKwu+Rq
ovXNG/y441q8INSNuO5QlK2uYf3eoajXQIyqUqJ7URJ5BxIy6pGjhlbevMUV7rgN
HvLomQKBgQD3auNdOCVOy5Xt5Fw8orKqky6M+pb0e5A3J7+w5Dq3fsPkSbO4O3Vj
oxRQhYigtJqHxkyS35dar8FQDNbfvj26jsf8ojs3CWarA6O+JpBVhH27Ak8RtfiA
cEWjDJMDiVK70goefMpJ19cwY7zOi4/s2DO9l24hYoAI/vJNoqttAw==
-----END RSA PRIVATE KEY-----`

	genPub, err := BytesToPublicKey([]byte(publicKey))
	if err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}

	enc, err := EncryptWithPublicKey([]byte(origin), genPub)
	if err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}
	result := base64.StdEncoding.EncodeToString(enc)

	t.Logf("RESULT : %s", result)

	genPriv, err := BytesToPrivateKey([]byte(privateKey))
	if err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}

	decB64, err := base64.StdEncoding.DecodeString(source)
	if err != nil {
		t.Errorf(err.Error())
	}
	dec, err := DecryptWithPrivateKey(decB64, genPriv)
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log(string(dec))

}

func TestEncrypt(t *testing.T) {

	key := `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhwCT/t6T4/mbC2l9jXV
N+K4rFfmPSLU++qmPDlqL5Ou8dsCTKRQGq6RD9nUT1UsI1khKqpzUlFR9zfDgV+H
6ODU9jPTPH8MuGZW1HB1UIgdaLuWv7jdVtBhR2gV2gZF6h+FSV71zqNIUias5wxK
dxIrjflj8jadmW+hYy7eozVPWe9DPBe8CR4/Rabzto9nYN+loWvfkTIhFEHJ81Vp
fKCvvtU02ve0qpCQi93zFkzlHNTkIk8vMxJGd9y9q4v4BneiWg98K5uIgi6Hch3h
nBMQLD2+I9AHh/y6PQxVdQic95biGHYv2fodbMrO1PVGaWwwWsBKH76laofLtt6o
awIDAQAB
-----END RSA PUBLIC KEY-----`

	genPub, err := BytesToPublicKey([]byte(key))
	if err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}
	data := `abcdefghijklmnopqrstuvwxyz`
	// data := `{"dct":1,"dcn":"SA1234568","nat":"ID","dob":"1981-08-23","fn":"Bruce","ln":"Wayne","vac":[{"do":1,"dt":36,"dd":"2021-03-17","co":"ID"},{"do":2,"dt":36,"dd":"2021-04-27","co":"ID"}]}`
	encode, err := EncryptWithPublicKey([]byte(data), genPub)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}
	t.Log(base64.StdEncoding.EncodeToString(encode))
}

func TestKeyLoadUnload(t *testing.T) {
	priv, pub, err := GenerateKeyPair(2048)
	if err != nil {
		t.Errorf(err.Error())
		t.Fail()
	}

	var genPriv *rsa.PrivateKey
	var genPub *rsa.PublicKey

	t.Run("PrivateKeySaveLoad", func(t *testing.T) {
		privBytes := PrivateKeyToBytes(priv)
		t.Log(string(privBytes))
		genPriv, err = BytesToPrivateKey(privBytes)
		if err != nil {
			t.Errorf(err.Error())
			t.Fail()
		}
	})

	t.Run("PublicKeySaveLoad", func(t *testing.T) {
		pubBytes, err := PublicKeyToBytes(pub)
		if err != nil {
			t.Errorf(err.Error())
			t.Fail()
		}

		t.Log(string(pubBytes))
		genPub, err = BytesToPublicKey(pubBytes)
		if err != nil {
			t.Errorf(err.Error())
			t.Fail()
		}
	})

	t.Run("TestEncryptDecryptOne", func(t *testing.T) {
		data := MakeRandomText(100)
		encode, err := EncryptWithPublicKey([]byte(data), pub)
		if err != nil {
			t.Errorf(err.Error())
			t.FailNow()
		}
		decoded, err := DecryptWithPrivateKey(encode, priv)
		if err != nil {
			t.Errorf(err.Error())
			t.FailNow()
		}

		if len(data) != len(decoded) {
			t.Error("content not equal")
			t.FailNow()
		}
		for i := 0; i < len(data); i++ {
			if data[i] != decoded[i] {
				t.Error("content different")
				t.Fail()
				break
			}
		}
	})

	t.Run("TestEncryptDecryptTwo", func(t *testing.T) {
		data := MakeRandomText(100)
		encode, err := EncryptWithPublicKey([]byte(data), genPub)
		if err != nil {
			t.Errorf(err.Error())
			t.FailNow()
		}
		decoded, err := DecryptWithPrivateKey(encode, genPriv)
		if err != nil {
			t.Errorf(err.Error())
			t.FailNow()
		}

		if len(data) != len(decoded) {
			t.Error("content not equal")
			t.FailNow()
		}
		for i := 0; i < len(data); i++ {
			if data[i] != decoded[i] {
				t.Error("content different")
				t.Fail()
				break
			}
		}
	})
}

func TestSignWithPrivateKeyPSS(t *testing.T) {

}

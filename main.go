package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIGqzCCBZOgAwIBAgIQCxe4C5hTBxSp8iq4fvd4QjANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE
aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMjA4MDkwMDAwMDBa
Fw0yMzA5MDkyMzU5NTlaMFwxCzAJBgNVBAYTAkNPMQ8wDQYDVQQHEwZCT0dPVEEx
HzAdBgNVBAoTFlJFREVCQU4gTVVMVElDT0xPUiBTLkExGzAZBgNVBAMTEnd3dy50
eHN0ZXN0cmJtLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+T
0DEzBlSdSXtjbHzMjoZKUEWXyKkEU4QMKCI7Zm4ejAqFOK9lBYooUeWm66s+/wsE
lBkLSURmA9pisjp+wWBagZLHJOyyorWPBy+pkvYZRGVnizsph0DXXBy6y5yNZ7u/
gdh6FB53gs0JI1P0cvzRApUOkukg+E1oPRx4z/ubNy58B5oIRXRZ5obC3codQb0N
EApDi3VaBOS6eVh4symBA6vFSGAvZB1uw55dp+UksvJ1Fidao0JCZ5yefi5g9KjT
WctWSHVGvOjaXdzz7iUM3xOr9UcIJvny30HyayG3DemcBYeQgIxZrQ+lyO4aPqex
jvcfYC6B2EoOpvL8raECAwEAAaOCA3QwggNwMB8GA1UdIwQYMBaAFLdrouqoqoSM
eeq02g+YssWVdrn0MB0GA1UdDgQWBBSzfYSAIb93PuKTP6WB4o9OC86zWDAdBgNV
HREEFjAUghJ3d3cudHhzdGVzdHJibS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBjwYDVR0fBIGHMIGEMECgPqA8hjpo
dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIw
Q0ExLTQuY3JsMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
cnRUTFNSU0FTSEEyNTYyMDIwQ0ExLTQuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQIC
MCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzB/Bggr
BgEFBQcBAQRzMHEwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
bTBJBggrBgEFBQcwAoY9aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
ZXJ0VExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAJBgNVHRMEAjAAMIIBgAYKKwYB
BAHWeQIEAgSCAXAEggFsAWoAdgDoPtDaPvUGNTLnVyi8iWvJA9PL0RFr7Otp4Xd9
bQa9bgAAAYKBEDTXAAAEAwBHMEUCIFcrvpZc7E3/0JSo/kYN0mpYjwwwRcyzJfC4
E2XwkL0FAiEAji+RiZ4T8ceSV7Zs6yC4FdFcigyuRD2nkm7qhPAlRiUAdwA1zxkb
v7FsV78PrUxtQsu7ticgJlHqP+Eq76gDwzvWTAAAAYKBEDUYAAAEAwBIMEYCIQCI
yZww+gxXHgj00nwbN7RqGQPnWYAv0IgSs7lQgmx+rAIhAMRyOZjTqEM5V1RjlTHz
JkVNITA/BNq6w+pPBkH3WRnfAHcAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0J
gSXttJkAAAGCgRA1LgAABAMASDBGAiEAlHOf65l9t/heqo+RuG91AlQD/W7sKTV4
XEH9oj3PNeECIQC116WfNhA1xPdtpb5HHdiuKJdJqY0ydanxJhXjmxIQnDANBgkq
hkiG9w0BAQsFAAOCAQEAbqDCmJxGB0GRfBKe23Wb8i3pJLZhPAjC5mnANTlcnHoz
sdK5Zc6/XS8zb6r8K49TvfGrI6f8nCkM2k9GXuxz2H7UXEGcpoyE008bASTfRYkc
UmZMB/PM8UFxg21KuQ4/MZlKN9XK1XFWblBQe2Zf6/hAXtR8bnAd6NpdHgF2rmWN
OB6RVHVJykBt84I5Ml9DWFcIwQXSX5XcmRCq9MeTgR3xlFoAyK4QIp14IKwXMScS
jaDNwr8sQcPBzjv6Odw8s2MCxGaR/MQpxAiGXJhSPorY3CjLLtCx2RX3g9EIePlN
A2BUJt1pQu+ZlGi1tsE/ps2s9jgebnNpoxGumXaRNg==
-----END CERTIFICATE-----`

const pubPEM = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`

const privateKEY = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3zZ6ifKVxnzYK
+FBDaz/TKGippOE5767kKssKmPp70X0dYIhfLdzbrgr1LYgEblN4/aDzWip73ap4
Upm+Z9QoDgD5GUJteqkxZhcSi75aJaORn6EqA3+XvhLQl1JvPYxuwnkXbHakrz+r
joQIm05rxwfaCu5QFPZslXQv97lsXdgvKkLavIiNLB7l+sZGxT8xRlvj1/QudPst
RhF8YfLRLwe+40Fyv1HaHLhDhyv2nlmJ3rvx5JDcpQSirNknK94P2uxIy6UN4NXv
3KdPJFWus0zDFCUrScF4rxiq22QIH5znwij8ODcpfun/1TPNNA6+rXgClCuac8ty
kwGLHqFBAgMBAAECggEAAZFYbAxiIOD5xgguLxUIG1X55pCId0ULGdkfmDyLzmiQ
B6MeJqmue5U1dLfptBf40ExhhhHb0OioHpSdyRj7n0fXTEih32svbENxqO/WNNCj
X4ecCU60VOgDIxJXWqmMvBkejUuYi3kPMvhpOeWROqwc7ggv1jEHlQ+FSS90vm7e
yNhqQFtc6zVIeCAWQeyiL7XR25+WO4vceBWks7j4j2eNoqrBNXQ7nSdnHNaLFJ/F
Pss/0i85xAve4Xh/ykM2v6BJHRHM83EZ08puufLZhKVuekI8WHGuxzuiTu3eaIQO
I+CtxvMU+ftmGtqf0Ebfg4ZOv7LHM1HLlYtDCKsh0QKBgQDXiYe0iVUQ96Nbjicx
19AXDg7yx0fraWZqOxPRGkKavH8Ejzga7Wa7rKIUUTvIkkneBJPYj1uPOJIv/Z/R
jYYXwP7nU0x4zFKAHfsb0H1CfpK/N1qnW2mVtl4/h8/il38ngFwyo3+SeIeX5Zvf
eAM9ib0pcv5t7zs+bwwOYUxKZQKBgQDaTv0wFSFF3OI2j+ajinw0WFZKrugHVbrA
mUzpNASnItUWxxMqFsZ3UTE+oHojM2V8otVeYK6U+stsEsmXDQ1Ex0mXV/9keWdJ
C+xMlF72G//7I+YYSpigk9976bgAk61wZaY8IHTmJn12n51RLB4i/+WmB1RMggGj
waa+EmO/rQKBgQCZgeYY+saPMxAxoOjhYuddxDF5T901GPhMKI9Qmfdd5WpBgQ9g
fjxw5d75wXFmxGm/qlryHggD1TKo42X0BWu/d0EU2Ara7grEHJY/lRnhReyWK4Jx
N3XXnu85KC0zINr68zy3BCNT2mwYDvwZCIymQ3dqEfCLs5rqOITJqRqA0QKBgFJ7
D4vwH88eglVtDw3xD7ZTPd8fsEi9Kj8EbJubbLqdHXdqpaH8UuXXxkxMI3lTPN/X
QdhTnQJqsxrVCldIth+rT/GfbL3QZKajm5bfY/WGZLPFP3UkEgBxfjl592w4X4oc
za7f8GrYVgTQj4aQrZ45otGU6VOytt3hF5euqQNNAoGAI0Ckzja7JG5DY+CdG4JB
lZZgsChYCP2NYjJXtwDkA0TTshZfPWwCfIC18RP69fODG2jKh29AwrayNQQIv4RE
s68+Y5x16wTEju4Mbh8t5T/O5KEtNHSobB+eJV9t3PUffdp1fpT3tee4Db7a8xti
NfI6QA6OUXeDdcapoN1PQ3c=
-----END PRIVATE KEY-----`

const publicKEY = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr5PQMTMGVJ1Je2NsfMyO
hkpQRZfIqQRThAwoIjtmbh6MCoU4r2UFiihR5abrqz7/CwSUGQtJRGYD2mKyOn7B
YFqBksck7LKitY8HL6mS9hlEZWeLOymHQNdcHLrLnI1nu7+B2HoUHneCzQkjU/Ry
/NEClQ6S6SD4TWg9HHjP+5s3LnwHmghFdFnmhsLdyh1BvQ0QCkOLdVoE5Lp5WHiz
KYEDq8VIYC9kHW7Dnl2n5SSy8nUWJ1qjQkJnnJ5+LmD0qNNZy1ZIdUa86Npd3PPu
JQzfE6v1Rwgm+fLfQfJrIbcN6ZwFh5CAjFmtD6XI7ho+p7GO9x9gLoHYSg6m8vyt
oQIDAQAB
-----END PUBLIC KEY-----`

func main() {
	fmt.Println("hello world - jws/jwe")

	jws := jws()
	fmt.Println("JWS: ")
	fmt.Println(jws)

	jwe := jweCert(jws)
	fmt.Println("JWE: ")
	fmt.Println(jwe)
}

func PublicKeyToPemStringOther(key *rsa.PublicKey) string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(key),
			},
		),
	)
}

func GeneratePublicKeyFile() {
	var rsaPublicKey = getCertificateKey(rootPEM)
	//pemPubKey := PublicKeyToPemString(rsaPublicKey)
	//fmt.Println(pemPubKey)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}

func jws() string {
	var privateKey = getPrivateKey(privateKEY)
	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS512, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}
	var payload = []byte(`{"tag":"armando-1"}`)
	object, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()
	return serialized
}

func getPrivateKey(data string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	if key, ok := key.(*rsa.PrivateKey); ok {
		return key
	}
	panic("key is not of type *rsa.PrivateKey")
}

func getPublicKey(data string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	if key, ok := key.(*rsa.PublicKey); ok {
		return key
	}
	panic("key is not of type *rsa.PrivateKey")
}

func jwe(jws string) string {
	//var key = getCertificateKey(rootPEM)
	var keyDirect = getPublicKey(publicKEY)

	encrypter, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: keyDirect}, nil)
	if err != nil {
		panic(err)
	}

	var plaintext = []byte(jws)
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()
	//fmt.Println("COMPACT")
	//compact, _ := object.CompactSerialize()
	//fmt.Println(compact)

	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	return serialized
}

func getCertificateKey(data string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	var algo = cert.PublicKeyAlgorithm
	fmt.Println(cert.DNSNames)
	fmt.Println(cert.NotAfter)
	fmt.Println(algo.String())

	parsedKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		panic("Parsed key was not an RSA key")
	}
	return parsedKey
}

func jweCert(jws string) string {
	var cert = getCertificate(rootPEM)

	encrypter, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: cert.PublicKey}, nil)
	if err != nil {
		panic(err)
	}

	var plaintext = []byte(jws)
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()

	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	return serialized
}

func getCertificate(data string) *x509.Certificate {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}

func getJWK() *jose.JSONWebKeySet {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := getCertificate(rootPEM)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	certificate, _ := x509.ParseCertificate(derBytes)

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Certificates: []*x509.Certificate{certificate},
				Key:          &rsaKey.PublicKey,
				KeyID:        "someKeyID",
				Use:          "sig",
			},
		},
	}
}

func verifySignature(serialized string, privateKey *rsa.PrivateKey) {
	// Parse the serialized, protected JWS object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseSigned(serialized)
	if err != nil {
		panic(err)
	}

	// Now we can verify the signature on the payload. An error here would
	// indicate the the message failed to verify, e.g. because the signature was
	// broken or the message was tampered with.
	output, err := object.Verify(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(output))
}

func decode() {
	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	fmt.Println("paso decode certificate")
	//fmt.Println(block)
	/*_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}*/
	//fmt.Println(string(block.Bytes))
	block2, _ := pem.Decode([]byte(pubPEM))
	if block2 == nil {
		panic("failed to parse PEM block containing the public key")
	}
	fmt.Println("paso decode pubKey")

	block3, _ := pem.Decode([]byte(privateKEY))
	if block3 == nil {
		panic("failed to parse PEM block containing the public key")
	}
	fmt.Println("paso decode privateKey")
}

func jweOriginal() {
	// Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := &privateKey.PublicKey
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		panic(err)
	}

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	var plaintext = []byte("Lorem ipsum dolor sit amet")
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// Serialize the encrypted object using the JWE JSON Serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate the the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Print(string(decrypted))
}

func jwsOriginal() {
	// Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}

	// Sign a sample payload. Calling the signer returns a protected JWS object,
	// which can then be serialized for output afterwards. An error would
	// indicate a problem in an underlying cryptographic primitive.
	var payload = []byte("Lorem ipsum dolor sit amet")
	object, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}

	// Serialize the signed object using the JWS JSON Serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()

	// Parse the serialized, protected JWS object. An error would indicate that
	// the given input did not represent a valid message.
	object, err = jose.ParseSigned(serialized)
	if err != nil {
		panic(err)
	}

	// Now we can verify the signature on the payload. An error here would
	// indicate the the message failed to verify, e.g. because the signature was
	// broken or the message was tampered with.
	output, err := object.Verify(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	fmt.Print(string(output))
}

func jwkOriginal() *jose.JSONWebKeySet {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)           // XXX Check err
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(100)) // XXX Check err

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKey.PublicKey, rsaKey) // XXX Check err
	certificate, _ := x509.ParseCertificate(derBytes)                                                   // XXX Check err

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Certificates: []*x509.Certificate{certificate},
				Key:          &rsaKey.PublicKey,
				KeyID:        "someKeyID",
				Use:          "sig",
			},
		},
	}
}

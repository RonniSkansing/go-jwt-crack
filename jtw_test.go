package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

var secret = "your-256-bit-secret"
var header = `{"alg":"HS256","typ":"JWT"}`
var payload = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`
var encodedHeader = base64.RawURLEncoding.EncodeToString([]byte(header))
var encodedPayload = base64.RawURLEncoding.EncodeToString([]byte(payload))
var signature []byte
var encodedSignature string
var token string

func init() {
	setSignature()
}

func setSignature() {
	encodedHeaderAndPayload := []byte(encodedHeader + "." + encodedPayload)
	signatureHash := hmac.New(sha256.New, []byte(secret))
	signatureHash.Write(encodedHeaderAndPayload)
	signature = signatureHash.Sum(nil)
	encodedSignature = base64.RawURLEncoding.EncodeToString(signature)
	token = buildToken(encodedHeader, encodedPayload, encodedSignature)
}

func buildToken(header string, payload string, signature string) string {
	return header + "." + payload + "." + signature
}

func jwtToken() JWT {
	jwt, _ := NewFromTokenString(token)
	return jwt
}

func TestNewFromTokenString(t *testing.T) {
	newFromTokenStringErrorsIfNotHavingHeaderAndPayloadAndSignature(t)
	newFromTokenStringErrorsIfNotAbleToDecodeHeader(t)
	newFromTokenStringErrorsIfNotAbleToDecodePayload(t)
	newFromTokenStringErrorsIfNotAbleToDecodeSignature(t)
}

func newFromTokenStringErrorsIfNotHavingHeaderAndPayloadAndSignature(t *testing.T) {
	incompleteToken := "incomplete.token"
	_, err := NewFromTokenString(incompleteToken)
	if err == nil {
		t.Errorf("incomplete token ( %s ) must error", incompleteToken)
	}
	if err.Error() != invalidToken {
		t.Errorf("wrong error message")
	}
}

func newFromTokenStringErrorsIfNotAbleToDecodeHeader(t *testing.T) {
	tokenWithInvalidHeader := buildToken("Ø"+encodedHeader, encodedPayload, encodedSignature)
	_, err := NewFromTokenString(tokenWithInvalidHeader)
	if err == nil {
		t.Errorf("token with invalid Header must error \ntoken %s", tokenWithInvalidHeader)
	}
}

func newFromTokenStringErrorsIfNotAbleToDecodePayload(t *testing.T) {
	tokenWithInvalidPayload := buildToken(encodedHeader, "Ø"+encodedPayload, encodedSignature)
	_, err := NewFromTokenString(tokenWithInvalidPayload)
	if err == nil {
		t.Errorf("token with invalid Payload must error \ntoken %s", tokenWithInvalidPayload)
	}
}

func newFromTokenStringErrorsIfNotAbleToDecodeSignature(t *testing.T) {
	tokenWithInvalidSignature := buildToken(encodedHeader, encodedPayload, "Ø"+encodedSignature)
	_, err := NewFromTokenString(tokenWithInvalidSignature)
	if err == nil {
		t.Errorf("token with invalid Signature must error \ntoken %s", tokenWithInvalidSignature)
	}
}

func TestJwt_Header(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.Header(), []byte(header)) == false {
		t.Errorf("returned header does not match header\n%#v\n!=\n%#v", jwt.Header(), []byte(header))
	}
}

func TestJwt_Payload(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.Payload(), []byte(payload)) == false {
		t.Errorf("returned payload does not match payload\n%#v\n!=\n%#v", jwt.Header(), []byte(payload))
	}
}

func TestJwt_Signature(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.Signature(), signature) == false {
		t.Errorf("returned signature does not match signature\n%#v\n!=\n%#v", jwt.Header(), []byte(payload))
	}
}

func TestJwt_EncodedHeader(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.EncodedHeader(), []byte(encodedHeader)) == false {
		t.Errorf("returned encoded header does not match encoded header ( %v != %s )", jwt.EncodedHeader(), encodedHeader)
	}
}

func TestJwt_EncodedPayload(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.EncodedPayload(), []byte(encodedPayload)) == false {
		t.Errorf("returned encoded payload does not match encoded payload ( %s != %s )", jwt.EncodedPayload(), encodedPayload)
	}
}

func TestJwt_EncodedSignature(t *testing.T) {
	jwt := jwtToken()
	if bytes.Equal(jwt.EncodedSignature(), []byte(encodedSignature)) == false {
		t.Errorf("returned encoded signature does not match encoded signature ( %s != %s )", jwt.EncodedSignature(), encodedSignature)
	}
}

func TestIsSecretUsedForTokenSignature(t *testing.T) {
	jwt := jwtToken()
	correctSecret := secret
	incorrectSecret := "4242"

	testISSecretReturnsTrueWhenSignatureMatches(t, jwt, correctSecret)
	testISSecretReturnsFalseWhenSignatureMatches(t, jwt, incorrectSecret)
}

func testISSecretReturnsTrueWhenSignatureMatches(t *testing.T, jwt JWT, secret string) {
	if IsSecretUsedForTokenSignature(jwt, secret) == false {
		t.Errorf("Signture was expected to match, but did not")
	}
}

func testISSecretReturnsFalseWhenSignatureMatches(t *testing.T, jwt JWT, secret string) {
	if IsSecretUsedForTokenSignature(jwt, secret) == true {
		t.Errorf("Signture was not expected to match, but did")
	}
}

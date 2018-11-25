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
var signature []byte
var encodedHeader = base64.RawURLEncoding.EncodeToString([]byte(header))
var encodedPayload = base64.RawURLEncoding.EncodeToString([]byte(payload))
var encodedSignature = base64.RawURLEncoding.EncodeToString([]byte(signature))
var token = buildToken(encodedHeader, encodedPayload, encodedSignature)

func init() {
	setSignature()
}

func setSignature() {
	signatureHash := hmac.New(sha256.New, []byte(secret))
	signatureHash.Write(signature)
}

func buildToken(header string, payload string, signature string) string {
	return header + "." + payload + "." + signature
}

func jwtToken() JWT {
	jwt, _ := New(token)
	return jwt
}

func TestNew(t *testing.T) {
	newErrorsIfNotHavingHeaderAndPayloadAndSignature(t)
	newErrorsIfNotAbleToDecodeHeader(t)
	newErrorsIfNotAbleToDecodePayload(t)
	newErrorsIfNotAbleToDecodeSignature(t)
}

func newErrorsIfNotHavingHeaderAndPayloadAndSignature(t *testing.T) {
	incompleteToken := "incomplete.token"
	_, err := New(incompleteToken)
	if err == nil {
		t.Errorf("incomplete token ( %s ) must error", incompleteToken)
	}
	if err.Error() != invalidToken {
		t.Errorf("wrong error message")
	}
}

func newErrorsIfNotAbleToDecodeHeader(t *testing.T) {
	tokenWithInvalidHeader := buildToken("Ø"+encodedHeader, encodedPayload, encodedSignature)
	_, err := New(tokenWithInvalidHeader)
	if err == nil {
		t.Errorf("token with invalid Header must error \ntoken %s", tokenWithInvalidHeader)
	}
}

func newErrorsIfNotAbleToDecodePayload(t *testing.T) {
	tokenWithInvalidPayload := buildToken(encodedHeader, "Ø"+encodedPayload, encodedSignature)
	_, err := New(tokenWithInvalidPayload)
	if err == nil {
		t.Errorf("token with invalid Payload must error \ntoken %s", tokenWithInvalidPayload)
	}
}

func newErrorsIfNotAbleToDecodeSignature(t *testing.T) {
	tokenWithInvalidSignature := buildToken(encodedHeader, encodedPayload, "Ø"+encodedSignature)
	_, err := New(tokenWithInvalidSignature)
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

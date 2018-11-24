package main

import (
	"bytes"
	"testing"
)

var encodedHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
var encodedPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
var encodedSignature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
var token = buildToken(encodedHeader, encodedPayload, encodedSignature)

func buildToken(header string, payload string, signature string) string {
	return header + "." + payload + "." + signature
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
	tokenWithInvalidHeader := buildToken("Ø" + encodedHeader, encodedPayload, encodedSignature)
	_, err :=  New(tokenWithInvalidHeader)
	if err == nil {
		t.Errorf("token with invalid Header must error \ntoken %s", tokenWithInvalidHeader)
	}
}

func newErrorsIfNotAbleToDecodePayload(t *testing.T) {
	tokenWithInvalidPayload := buildToken(encodedHeader, "Ø" + encodedPayload, encodedSignature)
	_, err :=  New(tokenWithInvalidPayload)
	if err == nil {
		t.Errorf("token with invalid Payload must error \ntoken %s", tokenWithInvalidPayload)
	}
}

func newErrorsIfNotAbleToDecodeSignature(t *testing.T) {
	tokenWithInvalidSignature := buildToken(encodedHeader, encodedPayload, "Ø" + encodedSignature)
	_, err :=  New(tokenWithInvalidSignature)
	if err == nil {
		t.Errorf("token with invalid Signature must error \ntoken %s", tokenWithInvalidSignature)
	}
}

func TestJwt_Header(t *testing.T) {
	jwt, _ := New(token)
	// header is not encoded header yo
	if bytes.Equal(jwt.Header(), []byte(encodedHeader)) == false {
		t.Errorf("returned header does not match encoded header\n%#v\n!=\n%#v", jwt.Header(), []byte(encodedHeader))
	}
}

func TestJwt_EncodedHeader(t *testing.T) {
	jwt, _ := New(token)
	if bytes.Equal(jwt.EncodedHeader(), []byte(encodedHeader)) == false {
		t.Errorf("returned encoded header does not match encoded header ( %v != %s )", jwt.EncodedHeader(), encodedHeader)
	}
}

// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

func TestJwt_EncodedPayload(t *testing.T) {
	jwt, _ := New(token)
	if bytes.Equal(jwt.EncodedPayload(), []byte(encodedPayload)) == false {
		t.Errorf("returned encoded payload does not match encoded payload ( %s != %s )", jwt.EncodedPayload(), encodedPayload)
	}
}

func TestJwt_EncodedSignature(t *testing.T) {
	jwt, _ := New(token)
	if bytes.Equal(jwt.EncodedSignature(), []byte(encodedSignature)) == false {
		t.Errorf("returned encoded signature does not match encoded signature ( %s != %s )", jwt.EncodedSignature(), encodedSignature)
	}
}
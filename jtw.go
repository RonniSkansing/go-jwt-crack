package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

var invalidToken = "invalid token. Token must have Header, Payload and Signature"

type jwt struct {
	header           []byte
	payload          []byte
	signature        []byte
	encodedHeader    []byte
	encodedPayload   []byte
	encodedSignature []byte
}

func (j *jwt) Header() []byte {
	return j.header
}

func (j *jwt) Payload() []byte {
	return j.payload
}

func (j *jwt) Signature() []byte {
	return j.signature
}

func (j *jwt) EncodedHeader() []byte {
	return j.encodedHeader
}

func (j *jwt) EncodedPayload() []byte {
	return j.encodedPayload
}

func (j *jwt) EncodedSignature() []byte {
	return j.encodedSignature
}

type JWT interface {
	Header() []byte
	Payload() []byte
	Signature() []byte
	EncodedHeader() []byte
	EncodedPayload() []byte
	EncodedSignature() []byte
}

func IsSecretUsedForTokenSignature(jwt JWT, secret string) bool {
	headerAndPayload := string(jwt.EncodedHeader()) + "." + string(jwt.EncodedPayload())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerAndPayload))
	signature := mac.Sum(nil)

	return bytes.Equal(signature, jwt.Signature())
}

func NewFromTokenString(token string) (JWT, error) {
	var (
		err              error
		encodedHeader    []byte
		encodedPayload   []byte
		encodedSignature []byte
	)
	ts := strings.Split(token, ".")
	tl := len(ts)

	if tl != 3 {
		return nil, errors.New(invalidToken)
	}

	encodedHeader, err = base64.RawURLEncoding.DecodeString(ts[0])
	if err != nil {
		return nil, err
	}
	encodedPayload, err = base64.RawURLEncoding.DecodeString(ts[1])
	if err != nil {
		return nil, err
	}
	encodedSignature, err = base64.RawURLEncoding.DecodeString(ts[2])
	if err != nil {
		return nil, err
	}

	return &jwt{
		header:           encodedHeader,
		payload:          encodedPayload,
		signature:        encodedSignature,
		encodedHeader:    []byte(ts[0]),
		encodedPayload:   []byte(ts[1]),
		encodedSignature: []byte(ts[2]),
	}, nil
}

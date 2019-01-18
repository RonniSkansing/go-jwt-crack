package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	fmt.Println("JTW-CRACK 0.0.2")
	var (
		infoMode     = "info"
		guessMode    = "guess"
		wordlistMode = "wordlist"
	)
	modes := map[string][]string{
		"mode": {infoMode, guessMode, wordlistMode},
	}
	var (
		mode     = flag.String("m", "", "Mode")
		token    = flag.String("t", "", "jwt Token")
		secret   = flag.String("k", "", "Test secret")
		wordList = flag.String("w", "", "Wordlist")
		verbose  = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	if _, ok := modes[*mode]; !ok {
		log.Fatalf("missing or invalid mode. -m must be %s, %s or %s\n", infoMode, guessMode, wordlistMode)
	}

	switch *mode {
	case infoMode:
		t, err := NewFromTokenString(*token)
		if err != nil {
			log.Fatalf("failed to decode token: %v\n", err)
		}
		fmt.Printf("\nHead : %s\nPayload : %s\n", t.Header, t.Payload)
	case guessMode:
		t, err := NewFromTokenString(*token)
		if err != nil {
			log.Fatalf("failed to decode token: %v\n", err)
		}
		if IsSecretUsedForTokenSignature(*t, *secret) == false {
			log.Printf("incorrect guess : %s\n", *secret)
			os.Exit(1)
		}
		fmt.Printf("correct password : %s\n", *secret)
	case wordlistMode:
		wordListInFile, err := os.Open(*wordList)
		defer wordListInFile.Close()
		if err != nil {
			log.Fatalf("failed to open wordlist %s : %v\n", *wordList, err)
		}
		token, err := NewFromTokenString(*token)
		if err != nil {
			log.Fatalf("failed to decode token: %v\n", err)
			return
		}
		stringScanner := bufio.NewScanner(wordListInFile)
		for stringScanner.Scan() {
			secret := stringScanner.Text()
			if IsSecretUsedForTokenSignature(*token, secret) == false {
				if *verbose {
					fmt.Printf("incorrect password : %v", secret)
				}
				continue
			} else {
				fmt.Printf("correct password : %s", secret)
				break
			}
		}
	}
}

var InvalidTokenErrorMessage = "invalid token, token must follow form header.payload.signature"

type Jwt struct {
	Header           []byte
	Payload          []byte
	Signature        []byte
	EncodedHeader    []byte
	EncodedPayload   []byte
	EncodedSignature []byte
}

func IsSecretUsedForTokenSignature(t Jwt, secret string) bool {
	b := fmt.Sprintf("%s.%s",t.EncodedHeader, t.EncodedPayload)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(b))
	signature := m.Sum(nil)

	return bytes.Equal(signature, t.Signature)
}

func NewFromTokenString(token string) (*Jwt, error) {
	t := strings.Split(token, ".")
	tl := len(t)

	if tl != 3 {
		return nil, errors.New(InvalidTokenErrorMessage)
	}
	encodedHeader, err := base64.RawURLEncoding.DecodeString(t[0])
	if err != nil {
		return nil, err
	}
	encodedPayload, err := base64.RawURLEncoding.DecodeString(t[1])
	if err != nil {
		return nil, err
	}
	encodedSignature, err := base64.RawURLEncoding.DecodeString(t[2])
	if err != nil {
		return nil, err
	}

	return &Jwt{
		Header:           encodedHeader,
		Payload:          encodedPayload,
		Signature:        encodedSignature,
		EncodedHeader:    []byte(t[0]),
		EncodedPayload:   []byte(t[1]),
		EncodedSignature: []byte(t[2]),
	}, nil
}

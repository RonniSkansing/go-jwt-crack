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
	"os"
	"strings"
)

var invalidToken = "invalid token. Token must have head, payload and sign. Ex. head.payload.sign"

type flags struct {
	token string
	mode string
	key string
	wordlist string
	verbose bool
}

type jwt struct {
	head []byte
	payload []byte
	sign []byte
}

func main() {
	art()
	flags := getFlags()

	if flags.mode != "identify" && flags.mode != "key" && flags.mode != "wordlist" {
		fmt.Printf("Unknown mode. Mode must be 'identify', 'password' or 'wordlist'\n")
		return
	}
	switch flags.mode {
	case "identify":
		jwt, err := stringToJWT(flags.token)
		if err != nil {
			fmt.Printf("failed to split jwt : %s\n", flags.token)
			fmt.Println(err)
			return
		}

		fmt.Printf("\nHead : %s\nPayload : %s\n", jwt.head, jwt.payload)

	case "key":
		t := strings.Split(flags.token, ".")
		if len(t) != 3 {
			fmt.Printf(invalidToken)
			return
		}
		headAndPayload := t[0] + "." + t[1]
		oldSign, err := base64.RawURLEncoding.DecodeString(t[2])
		if err != nil {
			fmt.Printf("Could not decode signing of token : %s\n", err)
		}
		mac := hmac.New(sha256.New, []byte(flags.key))
		mac.Write([]byte(headAndPayload))
		newSign := mac.Sum(nil)

		if bytes.Equal(newSign, oldSign) == false {
			fmt.Printf("Incorrect key - %s", flags.key)
			return
		}

		fmt.Printf("Correct key : %s\n", flags.key)
	case "wordlist":
		wl, err := os.Open(flags.wordlist)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer wl.Close()

		t := strings.Split(flags.token, ".")
		if len(t) != 3 {
			fmt.Printf(invalidToken)
			return
		}
		headAndPayload := t[0] + "." + t[1]
		oldSign, err := base64.RawURLEncoding.DecodeString(t[2])
		if err != nil {
			fmt.Println(err)
			return
		}
		reader := bufio.NewReader(wl)
		for {
			key, err := reader.ReadBytes('\n')
			if err != nil {
				break
			}
			strippedKey := key[0:len(key)-1] // strip newline
			mac := hmac.New(sha256.New, strippedKey)
			mac.Write([]byte(headAndPayload))
			newSign := mac.Sum(nil)

			if bytes.Equal(newSign, oldSign) == false {
				if flags.verbose {
					fmt.Printf("Incorrect key - %s\n", strippedKey)
				}
			} else {
				fmt.Printf("Found key - %s\n", strippedKey)
				break
			}
		}
	default:
		fmt.Printf("Unknown mode : %s", flags.mode)
		return
	}
}

func getFlags() *flags {
	token := flag.String("t", "", "JWT Token")
	mode := flag.String("m", "", "Mode")
	key := flag.String("k", "", "Test key")
	wordlist := flag.String("w", "", "Wordlist")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Parse()
	return &flags{token: *token, mode: *mode, key: *key, wordlist: *wordlist, verbose: *verbose}
}

func stringToJWT(token string) (*jwt, error) {
	var (
		err error
		head []byte
		payload []byte
		sign []byte
	)
	ts := strings.Split(token, ".")
	tl := len(ts)

	if tl != 3 {
		return nil, errors.New(invalidToken)
	}
	head, err = base64.RawURLEncoding.DecodeString(ts[0])
	if err != nil {
		return nil, err
	}
	payload, err = base64.RawURLEncoding.DecodeString(ts[1])
	if err != nil {
		return nil, err
	}
	sign, err = base64.RawURLEncoding.DecodeString(ts[2])
	if err != nil {
		return nil, err
	}

	return &jwt{head, payload,sign}, nil
}

func art() {
	fmt.Println("JTW-CRACK 0.0")
}

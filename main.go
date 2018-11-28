package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

type flags struct {
	token    string
	mode     string
	key      string
	wordlist string
	verbose  bool
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
		jwt, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("\nHead : %s\nPayload : %s\n", jwt.EncodedHeader(), jwt.EncodedPayload())
	case "key":
		token, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		if IsSecretUsedForTokenSignature(token, flags.key) == false {
			fmt.Printf("Incorrect key - %s\n", flags.key)
			return
		}
		fmt.Printf("Correct key : %s\n", flags.key)
	case "wordlist":
		wordListInFile, err := os.Open(flags.wordlist)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer func() {
			err := wordListInFile.Close()
			if err != nil {
				fmt.Println(err)
			}
		}()

		token, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		reader := bufio.NewReader(wordListInFile)
		for {
			key, err := reader.ReadBytes('\n')
			if err != nil {
				break
			}
			strippedKey := string(key[0 : len(key)-1]) // strip newline
			if IsSecretUsedForTokenSignature(token, strippedKey) == false {
				if flags.verbose {
					fmt.Printf("Incorrect key - %s\n", strippedKey)
				}
				continue
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

func art() {
	fmt.Println("JTW-CRACK 0.0")
}

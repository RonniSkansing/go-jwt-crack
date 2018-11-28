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
	secret   string
	wordlist string
	verbose  bool
}

func main() {
	art()
	flags := getFlags()

	if flags.mode != "identify" && flags.mode != "secret" && flags.mode != "wordlist" {
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
		fmt.Printf("\nHead : %s\nPayload : %s\n", jwt.Header(), jwt.Payload())
	case "secret":
		token, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		if IsSecretUsedForTokenSignature(token, flags.secret) == false {
			fmt.Printf("Incorrect secret - %s\n", flags.secret)
			return
		}
		fmt.Printf("Correct secret : %s\n", flags.secret)
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
			secret, err := reader.ReadBytes('\n')
			if err != nil {
				break
			}
			strippedSecret := string(secret[0 : len(secret)-1]) // strip newline
			if IsSecretUsedForTokenSignature(token, strippedSecret) == false {
				if flags.verbose {
					fmt.Printf("Incorrect secret - %s\n", strippedSecret)
				}
				continue
			} else {
				fmt.Printf("Found secret - %s\n", strippedSecret)
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
	secret := flag.String("k", "", "Test secret")
	wordlist := flag.String("w", "", "Wordlist")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Parse()
	return &flags{token: *token, mode: *mode, secret: *secret, wordlist: *wordlist, verbose: *verbose}
}

func art() {
	fmt.Println("JTW-CRACK 0.0")
}

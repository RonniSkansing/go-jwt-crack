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
	wordList string
	verbose  bool
}

func main() {
	art()
	flags := getFlags()

	if flags.mode != "identify" && flags.mode != "secret" && flags.mode != "wordList" {
		printUnknownMode()
		return
	}
	switch flags.mode {
	case "identify":
		jwt, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		printDecodedTokenHeaderAndPayload(jwt.Header(), jwt.Payload())
	case "secret":
		token, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		if IsSecretUsedForTokenSignature(token, flags.secret) == false {
			printIncorrectGuessAtSecret(flags.secret)
			return
		}
		printCorrectGuessAtSecret(flags.secret)
	case "wordList":
		wordListInFile, err := os.Open(flags.wordList)
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
			secretLine, err := reader.ReadBytes('\n')
			if err != nil {
				break
			}
			secret := string(secretLine[0 : len(secretLine)-1]) // strip newline
			if IsSecretUsedForTokenSignature(token, secret) == false {
				if flags.verbose {
					printIncorrectGuessAtSecret(secret)
				}
				continue
			} else {
				printCorrectGuessAtSecret(secret)
				break
			}
		}
	default:
		printUnknownMode()
		return
	}
}

func getFlags() *flags {
	token := flag.String("t", "", "JWT Token")
	mode := flag.String("m", "", "Mode")
	secret := flag.String("k", "", "Test secret")
	wordList := flag.String("w", "", "Wordlist")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Parse()
	return &flags{token: *token, mode: *mode, secret: *secret, wordList: *wordList, verbose: *verbose}
}

func printCorrectGuessAtSecret(secret string) {
	fmt.Printf("Correct secret : %s\n", secret)
}

func printIncorrectGuessAtSecret(secret string) {
	fmt.Printf("Incorrect secret - %s\n", secret)
}

func printDecodedTokenHeaderAndPayload(decodedHeader []byte, decodedPayload []byte) {
	fmt.Printf("\nHead : %s\nPayload : %s\n", decodedHeader, decodedPayload)
}

func printUnknownMode() {
	fmt.Printf("Unknown mode. Mode must be 'identify', 'password' or 'wordList'\n")
}

func art() {
	fmt.Println("JTW-CRACK 0.0")
}

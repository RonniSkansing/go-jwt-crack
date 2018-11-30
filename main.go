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

const (
	modeShowInformation           = "info"
	modeTryGuessAtPassword        = "guess"
	modeGuessPasswordWithWordList = "wordlist"
)

var modes = []string{
	modeShowInformation,
	modeTryGuessAtPassword,
	modeGuessPasswordWithWordList,
}

func main() {
	printAppHeader()
	flags := getFlags()

	if isValidModeInFlags(flags) == false {
		printUnknownMode()
		return
	}

	switch flags.mode {
	case modeShowInformation:
		jwt, err := NewFromTokenString(flags.token)
		if err != nil {
			fmt.Println(err)
			return
		}
		printDecodedTokenHeaderAndPayload(jwt.Header(), jwt.Payload())
	case modeTryGuessAtPassword:
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
	case modeGuessPasswordWithWordList:
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
		stringScanner := bufio.NewScanner(wordListInFile)
		for stringScanner.Scan() {
			secret := stringScanner.Text()
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

func isValidModeInFlags(flags *flags) bool {
	isValidMode := false
	for _, mode := range modes {
		if mode == flags.mode {
			isValidMode = true
		}
	}

	return isValidMode
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
	fmt.Printf("Unknown mode. Mode must be 'info', 'guess' or 'wordList'\n")
}

func printAppHeader() {
	fmt.Println("JTW-CRACK 0.0.1")
}

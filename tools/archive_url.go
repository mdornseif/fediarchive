package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// ArchiveConfig holds ArchiveBox configuration
type ArchiveConfig struct {
	ArchiveBox struct {
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"archivebox"`
}

type ArchiveBoxArchiveClient struct {
	config        *ArchiveConfig
	httpClient    *http.Client
	csrfToken     string
	sessionCookie string
	isLoggedIn    bool
}

func NewArchiveBoxArchiveClient(config *ArchiveConfig) *ArchiveBoxArchiveClient {
	// Load existing session cookie from cookies.txt
	sessionCookie := loadSessionCookieFromFile("cookies.txt")
	if sessionCookie != "" {
		log.Printf("Loaded existing session cookie: %s", sessionCookie)
	}

	return &ArchiveBoxArchiveClient{
		config:        config,
		httpClient:    &http.Client{Timeout: 60 * time.Second},
		sessionCookie: sessionCookie,
		isLoggedIn:    sessionCookie != "",
	}
}

func loadSessionCookieFromFile(filename string) string {
	log.Printf("Attempting to load session cookie from %s", filename)
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Could not open cookies file %s: %v", filename, err)
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		log.Printf("Reading line: %s", line)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_")) {
			continue
		}

		// Handle HttpOnly cookies (remove #HttpOnly_ prefix)
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = strings.TrimPrefix(line, "#HttpOnly_")
		}

		// Parse Netscape cookie format
		fields := strings.Split(line, "\t")
		log.Printf("Fields: %v", fields)
		if len(fields) >= 7 {
			name := fields[5]
			value := fields[6]
			log.Printf("Found cookie: %s = %s", name, value)
			if name == "sessionid" {
				log.Printf("Found sessionid cookie: %s", value)
				return value
			}
		}
	}

	log.Printf("No sessionid cookie found in file")
	return ""
}

func (c *ArchiveBoxArchiveClient) login() error {
	if c.isLoggedIn && c.sessionCookie != "" {
		log.Printf("Already logged in with session cookie")
		return nil
	}

	// If we have a session cookie from cookies.txt, try to use it
	if c.sessionCookie != "" {
		log.Printf("Testing existing session cookie")
		// Test if the session is still valid by accessing the add page
		addURL := c.config.ArchiveBox.URL + "/add/"
		req, err := http.NewRequest("GET", addURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		// Add the session cookie
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to test session: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "Add URLs to Archive") || strings.Contains(string(body), "Archived Sites") {
			log.Printf("Existing session cookie is valid")
			c.isLoggedIn = true
			return nil
		} else {
			log.Printf("Existing session cookie is invalid, will try to login")
			c.sessionCookie = ""
			c.isLoggedIn = false
		}
	}

	// Step 1: Try to access the add page directly first
	addURL := c.config.ArchiveBox.URL + "/add/"
	resp, err := c.httpClient.Get(addURL)
	if err != nil {
		return fmt.Errorf("failed to access add page: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Initial /add/ response status: %d", resp.StatusCode)
	log.Printf("Initial /add/ response cookies: %v", resp.Cookies())

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read add page: %v", err)
	}

	// Check if we're already authenticated (got the add page)
	if strings.Contains(string(body), "Add URLs to Archive") || strings.Contains(string(body), "Archived Sites") {
		// Extract CSRF token from the add page
		csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
		csrfMatches := csrfRegex.FindStringSubmatch(string(body))
		if len(csrfMatches) >= 2 {
			c.csrfToken = csrfMatches[1]
			log.Printf("Already authenticated, extracted CSRF token from add page: %s", c.csrfToken)

			// Check for session cookie
			for _, cookie := range resp.Cookies() {
				if cookie.Name == "sessionid" {
					c.sessionCookie = cookie.Value
					log.Printf("Found existing session cookie: %s", cookie.Value)
				}
			}

			if c.sessionCookie != "" {
				c.isLoggedIn = true
				log.Printf("Successfully authenticated using existing session")
				return nil
			}
		}
	}

	previewLen := 500
	if len(body) < previewLen {
		previewLen = len(body)
	}
	log.Printf("Response body preview: %s", string(body[:previewLen]))

	// Check if we got the login page directly (not a redirect)
	if strings.Contains(string(body), "Log in") || strings.Contains(string(body), "login-form") {
		log.Printf("Got login page directly, extracting CSRF token")
		// Extract CSRF token from the login form
		csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
		csrfMatches := csrfRegex.FindStringSubmatch(string(body))
		if len(csrfMatches) >= 2 {
			c.csrfToken = csrfMatches[1]
			log.Printf("Extracted CSRF token from login page: %s", c.csrfToken)

			// Try both /admin/login/ and /accounts/login/ endpoints
			loginEndpoints := []string{"/admin/login/", "/accounts/login/"}
			for _, endpoint := range loginEndpoints {
				loginURL := c.config.ArchiveBox.URL + endpoint
				loginData := url.Values{}
				loginData.Set("username", c.config.ArchiveBox.Username)
				loginData.Set("password", c.config.ArchiveBox.Password)
				loginData.Set("csrfmiddlewaretoken", c.csrfToken)
				loginData.Set("next", "/add/")

				loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(loginData.Encode()))
				if err != nil {
					log.Printf("Failed to create login request for %s: %v", endpoint, err)
					continue
				}

				loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				loginReq.Header.Set("Referer", addURL)

				// Add cookies from the response
				for _, cookie := range resp.Cookies() {
					loginReq.AddCookie(cookie)
				}
				// Also add CSRF token as a cookie
				loginReq.AddCookie(&http.Cookie{Name: "csrftoken", Value: c.csrfToken})

				// Log request headers and body
				log.Printf("Login POST to %s", loginURL)
				for k, v := range loginReq.Header {
					log.Printf("Header: %s: %v", k, v)
				}
				log.Printf("Login POST body: %s", loginData.Encode())

				loginResp, err := c.httpClient.Do(loginReq)
				if err != nil {
					log.Printf("Failed to submit login to %s: %v", endpoint, err)
					continue
				}
				defer loginResp.Body.Close()

				log.Printf("Login response status: %d", loginResp.StatusCode)
				log.Printf("Login response cookies: %v", loginResp.Cookies())

				respBody, _ := io.ReadAll(loginResp.Body)
				if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusMovedPermanently {
					log.Printf("Login response body for %s: %s", endpoint, string(respBody))
				}

				// Store session cookies
				for _, cookie := range loginResp.Cookies() {
					if cookie.Name == "sessionid" {
						c.sessionCookie = cookie.Value
						log.Printf("Got session cookie: %s", cookie.Value)
					}
				}

				if c.sessionCookie != "" {
					c.isLoggedIn = true
					log.Printf("Successfully logged in to ArchiveBox using %s", endpoint)
					return nil
				}
				// If login was successful, we should get a redirect
				if loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusMovedPermanently {
					location := loginResp.Header.Get("Location")
					if location != "" {
						if !strings.HasPrefix(location, "http") {
							if strings.HasPrefix(location, "/") {
								location = c.config.ArchiveBox.URL + location
							} else {
								location = addURL + "/" + location
							}
						}
						followReq, err := http.NewRequest("GET", location, nil)
						if err == nil {
							for _, cookie := range loginResp.Cookies() {
								followReq.AddCookie(cookie)
							}
							followResp, err := c.httpClient.Do(followReq)
							if err == nil {
								defer followResp.Body.Close()
								log.Printf("Follow redirect response status: %d", followResp.StatusCode)
								log.Printf("Follow redirect response cookies: %v", followResp.Cookies())
								for _, cookie := range followResp.Cookies() {
									if cookie.Name == "sessionid" {
										c.sessionCookie = cookie.Value
										log.Printf("Got session cookie after redirect: %s", cookie.Value)
									}
								}
								if c.sessionCookie != "" {
									c.isLoggedIn = true
									log.Printf("Successfully logged in to ArchiveBox using %s (after redirect)", endpoint)
									return nil
								}
							}
						}
					}
				}
			}

			return fmt.Errorf("login failed: no session cookie received from any endpoint")
		}
	}

	// If not authenticated, follow redirects to get to the login page
	currentURL := addURL
	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Handle relative URLs
		if !strings.HasPrefix(location, "http") {
			if strings.HasPrefix(location, "/") {
				location = c.config.ArchiveBox.URL + location
			} else {
				location = currentURL + "/" + location
			}
		}

		currentURL = location
		resp, err = c.httpClient.Get(location)
		if err != nil {
			return fmt.Errorf("failed to follow redirect to %s: %v", location, err)
		}
		defer resp.Body.Close()
		log.Printf("Redirected to: %s, status: %d", location, resp.StatusCode)
		log.Printf("Redirect response cookies: %v", resp.Cookies())
	}

	// Now we should be at the login page
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login page: %v", err)
	}

	// Extract CSRF token from the login form
	csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
	csrfMatches := csrfRegex.FindStringSubmatch(string(body))
	if len(csrfMatches) < 2 {
		return fmt.Errorf("failed to extract CSRF token from login page")
	}
	c.csrfToken = csrfMatches[1]
	log.Printf("Extracted CSRF token: %s", c.csrfToken)

	// Try both /admin/login/ and /accounts/login/ endpoints
	loginEndpoints := []string{"/admin/login/", "/accounts/login/"}
	for _, endpoint := range loginEndpoints {
		loginURL := c.config.ArchiveBox.URL + endpoint
		loginData := url.Values{}
		loginData.Set("username", c.config.ArchiveBox.Username)
		loginData.Set("password", c.config.ArchiveBox.Password)
		loginData.Set("csrfmiddlewaretoken", c.csrfToken)
		loginData.Set("next", "/add/")

		loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(loginData.Encode()))
		if err != nil {
			log.Printf("Failed to create login request for %s: %v", endpoint, err)
			continue
		}

		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginReq.Header.Set("Referer", currentURL)

		// Add cookies from the login page response
		for _, cookie := range resp.Cookies() {
			loginReq.AddCookie(cookie)
		}
		// Also add CSRF token as a cookie
		loginReq.AddCookie(&http.Cookie{Name: "csrftoken", Value: c.csrfToken})

		// Log request headers and body
		log.Printf("Login POST to %s", loginURL)
		for k, v := range loginReq.Header {
			log.Printf("Header: %s: %v", k, v)
		}
		log.Printf("Login POST body: %s", loginData.Encode())

		loginResp, err := c.httpClient.Do(loginReq)
		if err != nil {
			log.Printf("Failed to submit login to %s: %v", endpoint, err)
			continue
		}
		defer loginResp.Body.Close()

		log.Printf("Login response status: %d", loginResp.StatusCode)
		log.Printf("Login response cookies: %v", loginResp.Cookies())

		respBody, _ := io.ReadAll(loginResp.Body)
		if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusMovedPermanently {
			log.Printf("Login response body for %s: %s", endpoint, string(respBody))
		}

		// Store session cookies
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "sessionid" {
				c.sessionCookie = cookie.Value
				log.Printf("Got session cookie: %s", cookie.Value)
			}
		}

		if c.sessionCookie != "" {
			c.isLoggedIn = true
			log.Printf("Successfully logged in to ArchiveBox using %s", endpoint)
			return nil
		}
		// If login was successful, we should get a redirect
		if loginResp.StatusCode == http.StatusFound || loginResp.StatusCode == http.StatusMovedPermanently {
			location := loginResp.Header.Get("Location")
			if location != "" {
				if !strings.HasPrefix(location, "http") {
					if strings.HasPrefix(location, "/") {
						location = c.config.ArchiveBox.URL + location
					} else {
						location = currentURL + "/" + location
					}
				}
				followReq, err := http.NewRequest("GET", location, nil)
				if err == nil {
					for _, cookie := range loginResp.Cookies() {
						followReq.AddCookie(cookie)
					}
					followResp, err := c.httpClient.Do(followReq)
					if err == nil {
						defer followResp.Body.Close()
						log.Printf("Follow redirect response status: %d", followResp.StatusCode)
						log.Printf("Follow redirect response cookies: %v", followResp.Cookies())
						for _, cookie := range followResp.Cookies() {
							if cookie.Name == "sessionid" {
								c.sessionCookie = cookie.Value
								log.Printf("Got session cookie after redirect: %s", cookie.Value)
							}
						}
						if c.sessionCookie != "" {
							c.isLoggedIn = true
							log.Printf("Successfully logged in to ArchiveBox using %s (after redirect)", endpoint)
							return nil
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("login failed: no session cookie received from any endpoint")
}

func (c *ArchiveBoxArchiveClient) addURL(targetURL string) error {
	if err := c.login(); err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	// Step 1: Get the add page to extract CSRF token
	addURL := c.config.ArchiveBox.URL + "/add/"
	addReq, err := http.NewRequest("GET", addURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add session cookie
	if c.sessionCookie != "" {
		addReq.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})
	}

	resp, err := c.httpClient.Do(addReq)
	if err != nil {
		return fmt.Errorf("failed to access add page: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Add page response status: %d", resp.StatusCode)
	log.Printf("Add page response cookies: %v", resp.Cookies())

	// Check if we got redirected to login (session expired)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "login") {
			c.isLoggedIn = false
			return c.addURL(targetURL)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read add page: %v", err)
	}

	// Extract CSRF token from the add form
	csrfRegex := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]+)"`)
	csrfMatches := csrfRegex.FindStringSubmatch(string(body))
	if len(csrfMatches) < 2 {
		return fmt.Errorf("failed to extract CSRF token from add page")
	}
	c.csrfToken = csrfMatches[1]
	log.Printf("Extracted CSRF token for add: %s", c.csrfToken)

	// Step 2: Submit the URL addition form
	addData := url.Values{}
	addData.Set("url", targetURL)
	addData.Set("parser", "url_list")
	addData.Set("depth", "0")
	addData.Set("tag", "test")
	addData.Set("force", "true")
	addData.Set("csrfmiddlewaretoken", c.csrfToken)

	addPostReq, err := http.NewRequest("POST", addURL, strings.NewReader(addData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create add request: %v", err)
	}

	addPostReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addPostReq.Header.Set("Referer", addURL)

	// Add session cookie
	if c.sessionCookie != "" {
		addPostReq.AddCookie(&http.Cookie{Name: "sessionid", Value: c.sessionCookie})
	}

	addResp, err := c.httpClient.Do(addPostReq)
	if err != nil {
		return fmt.Errorf("failed to submit add request: %v", err)
	}
	defer addResp.Body.Close()

	log.Printf("Add URL response status: %d", addResp.StatusCode)
	log.Printf("Add URL response cookies: %v", addResp.Cookies())

	respBody, err := io.ReadAll(addResp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
	} else {
		log.Printf("Add URL response body: %s", string(respBody))
	}

	if addResp.StatusCode != http.StatusOK && addResp.StatusCode != http.StatusFound {
		return fmt.Errorf("add URL failed with status %d: %s", addResp.StatusCode, string(respBody))
	}

	log.Printf("Successfully added URL: %s", targetURL)
	return nil
}

func main() {
	urlFlag := flag.String("url", "", "URL to archive")
	flag.Parse()

	if *urlFlag == "" {
		log.Fatal("Please provide a URL to archive using -url flag")
	}

	// Read config file
	configData, err := os.ReadFile("../config.json")
	if err != nil {
		log.Fatalf("Failed to read config.json: %v", err)
	}

	var config ArchiveConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse config.json: %v", err)
	}

	client := NewArchiveBoxArchiveClient(&config)
	if err := client.addURL(*urlFlag); err != nil {
		log.Fatalf("Failed to archive URL: %v", err)
	}

	fmt.Printf("✅ Successfully queued URL for archiving: %s\n", *urlFlag)
}

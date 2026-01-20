package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hardwaylabs/learn-oauth-go/internal/logger"
	"github.com/hardwaylabs/learn-oauth-go/internal/oauth"
	"github.com/spf13/viper"
)

type Client struct {
	templates         *template.Template
	pkceChallenge     *oauth.PKCEChallenge
	authCode          string
	accessToken       string
	clientPort        string
	authServerURL     string
	resourceServerURL string
	clientID          string
	redirectURI       string
	scope             string
}

type PageData struct {
	Error           string
	PKCEDetails     *oauth.PKCEChallenge
	AuthURL         string
	Code            string
	AccessToken     string
	ResourceContent string
	UserInfo        string
	RedirectURI     string
	ClientID        string
	Scope           string
}

func deriveRedirectURI(port string) string {
	// Remove leading colon if present (e.g., ":8088" -> "8088")
	portNum := strings.TrimPrefix(port, ":")
	return fmt.Sprintf("http://localhost:%s/callback", portNum)
}

func (c *Client) basePageData() PageData {
	return PageData{
		RedirectURI: c.redirectURI,
		ClientID:    c.clientID,
		Scope:       c.scope,
	}
}

func NewClient() (*Client, error) {
	templates, err := template.ParseGlob("web/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	clientPort := viper.GetString("client.port")
	redirectURI := deriveRedirectURI(clientPort)

	return &Client{
		templates:         templates,
		clientPort:        clientPort,
		authServerURL:     viper.GetString("client.auth_server_url"),
		resourceServerURL: viper.GetString("client.resource_server_url"),
		clientID:          viper.GetString("client.client_id"),
		redirectURI:       redirectURI,
		scope:             viper.GetString("client.scope"),
	}, nil
}

func (c *Client) home(w http.ResponseWriter, r *http.Request) {
	pkce, err := oauth.GeneratePKCEChallenge()
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to generate PKCE challenge"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	c.pkceChallenge = pkce

	authURL := fmt.Sprintf("%s/authorize?"+
		"response_type=code&"+
		"client_id=%s&"+
		"redirect_uri=%s&"+
		"scope=%s&"+
		"state=%s&"+
		"code_challenge=%s&"+
		"code_challenge_method=%s",
		c.authServerURL,
		url.QueryEscape(c.clientID),
		url.QueryEscape(c.redirectURI),
		url.QueryEscape(c.scope),
		url.QueryEscape("demo-state-123"),
		url.QueryEscape(pkce.Challenge),
		url.QueryEscape(pkce.Method))

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "USER-BROWSER",
		MessageType: "Authorization URL Generated",
		Payload: map[string]interface{}{
			"authorization_url": authURL,
			"pkce_challenge":    pkce.Challenge,
			"pkce_method":       pkce.Method,
		},
	})

	data := c.basePageData()
	data.PKCEDetails = pkce
	data.AuthURL = authURL

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Authorization Callback",
		Payload: map[string]interface{}{
			"code":  code,
			"state": state,
			"error": errorParam,
		},
	})

	if errorParam != "" {
		data := c.basePageData()
		data.Error = fmt.Sprintf("Authorization error: %s", errorParam)
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if code == "" {
		data := c.basePageData()
		data.Error = "No authorization code received"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if state != "demo-state-123" {
		data := c.basePageData()
		data.Error = "Invalid state parameter"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	// Store the authorization code for later use
	c.authCode = code

	data := c.basePageData()
	data.Code = code
	data.PKCEDetails = c.pkceChallenge

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) exchange(w http.ResponseWriter, r *http.Request) {
	if c.pkceChallenge == nil {
		data := c.basePageData()
		data.Error = "No PKCE challenge available. Please start the flow again."
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if c.authCode == "" {
		data := c.basePageData()
		data.Error = "No authorization code available. Please complete the authorization flow first."
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {c.authCode},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"code_verifier": {c.pkceChallenge.Verifier},
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Token Exchange Request",
		Payload: map[string]interface{}{
			"grant_type":    "authorization_code",
			"redirect_uri":  c.redirectURI,
			"client_id":     c.clientID,
			"code_verifier": c.pkceChallenge.Verifier[:20] + "...",
		},
	})

	resp, err := http.PostForm(c.authServerURL+"/token", tokenData)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to exchange code for token"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to read token response"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.LogError("CLIENT", fmt.Errorf("token request failed: %s", string(body)))
		data := c.basePageData()
		data.Error = fmt.Sprintf("Token request failed: %s", string(body))
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	var tokenResponse oauth.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to parse token response"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	c.accessToken = tokenResponse.AccessToken

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Token Exchange Response",
		Payload: map[string]interface{}{
			"access_token": tokenResponse.AccessToken,
			"token_type":   tokenResponse.TokenType,
			"expires_in":   tokenResponse.ExpiresIn,
			"scope":        tokenResponse.Scope,
		},
	})

	data := c.basePageData()
	data.AccessToken = tokenResponse.AccessToken
	data.PKCEDetails = c.pkceChallenge

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) resource(w http.ResponseWriter, r *http.Request) {
	if c.accessToken == "" {
		data := c.basePageData()
		data.Error = "No access token available. Please complete the OAuth flow first."
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req, err := http.NewRequest("GET", c.resourceServerURL+"/protected", nil)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to create resource request"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "RESOURCE-SERVER",
		MessageType: "Protected Resource Request",
		Headers: map[string]string{
			"Authorization": "Bearer " + c.accessToken[:20] + "...",
		},
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to access protected resource"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to read resource response"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.LogError("CLIENT", fmt.Errorf("resource request failed: %s", string(body)))
		data := c.basePageData()
		data.Error = fmt.Sprintf("Resource access failed: %s", string(body))
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "RESOURCE-SERVER",
		Destination: "CLIENT",
		MessageType: "Protected Resource Response",
		Payload: map[string]interface{}{
			"content_length": len(body),
			"status":         "success",
		},
	})

	data := c.basePageData()
	data.AccessToken = c.accessToken
	data.ResourceContent = string(body)
	data.PKCEDetails = c.pkceChallenge

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) userinfo(w http.ResponseWriter, r *http.Request) {
	if c.accessToken == "" {
		data := c.basePageData()
		data.Error = "No access token available. Please complete the OAuth flow first."
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req, err := http.NewRequest("GET", c.resourceServerURL+"/userinfo", nil)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to create userinfo request"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to get user info"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := c.basePageData()
		data.Error = "Failed to read userinfo response"
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
		prettyJSON.Write(body)
	}

	data := c.basePageData()
	data.AccessToken = c.accessToken
	data.UserInfo = prettyJSON.String()
	data.PKCEDetails = c.pkceChallenge

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) status(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"has_pkce_challenge": c.pkceChallenge != nil,
		"has_access_token":   c.accessToken != "",
		"timestamp":          time.Now().Format(time.RFC3339),
	}

	if c.pkceChallenge != nil {
		status["pkce_challenge"] = c.pkceChallenge.Challenge[:20] + "..."
	}

	if c.accessToken != "" {
		status["access_token"] = c.accessToken[:20] + "..."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func initConfig() {
	// Set defaults
	viper.SetDefault("client.port", ":8080")
	viper.SetDefault("client.auth_server_url", "http://localhost:8081")
	viper.SetDefault("client.resource_server_url", "http://localhost:8082")
	viper.SetDefault("client.client_id", "demo-client")
	viper.SetDefault("client.scope", "read")

	// Bind environment variables
	viper.BindEnv("client.port", "CLIENT_PORT")
	viper.BindEnv("client.auth_server_url", "CLIENT_AUTH_SERVER_URL")
	viper.BindEnv("client.resource_server_url", "CLIENT_RESOURCE_SERVER_URL")
	viper.BindEnv("client.client_id", "CLIENT_CLIENT_ID")
	viper.BindEnv("client.scope", "CLIENT_SCOPE")

	// Define command-line flags
	var port, authServerURL, resourceServerURL, clientID, scope string
	flag.StringVar(&port, "port", viper.GetString("client.port"), "Client server port")
	flag.StringVar(&authServerURL, "auth-server-url", viper.GetString("client.auth_server_url"), "Authorization server URL")
	flag.StringVar(&resourceServerURL, "resource-server-url", viper.GetString("client.resource_server_url"), "Resource server URL")
	flag.StringVar(&clientID, "client-id", viper.GetString("client.client_id"), "OAuth client ID")
	flag.StringVar(&scope, "scope", viper.GetString("client.scope"), "OAuth scope")
	flag.Parse()

	// Set viper values from flags (flags have highest priority)
	viper.Set("client.port", port)
	viper.Set("client.auth_server_url", authServerURL)
	viper.Set("client.resource_server_url", resourceServerURL)
	viper.Set("client.client_id", clientID)
	viper.Set("client.scope", scope)
}

func main() {
	initConfig()

	clientPort := viper.GetString("client.port")
	logger.LogInfo("CLIENT", fmt.Sprintf("Starting OAuth 2.1 Demo Client on port %s", clientPort))

	client, err := NewClient()
	if err != nil {
		logger.LogError("CLIENT", err)
		return
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", client.home)
	r.Get("/callback", client.callback)
	r.Get("/exchange", client.exchange)
	r.Get("/resource", client.resource)
	r.Get("/userinfo", client.userinfo)
	r.Get("/status", client.status)

	// Handle common browser requests to avoid 404s in logs
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	r.Get("/_static/*", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })

	logger.LogInfo("CLIENT", "Client ready to start OAuth flow")
	logger.LogInfo("CLIENT", fmt.Sprintf("Visit http://localhost%s to begin", clientPort))

	if err := http.ListenAndServe(client.clientPort, r); err != nil {
		logger.LogError("CLIENT", err)
	}
}

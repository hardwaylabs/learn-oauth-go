package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hardwaylabs/learn-oauth-go/internal/logger"
	"github.com/hardwaylabs/learn-oauth-go/internal/oauth"
	"github.com/spf13/viper"
)

type ResourceServer struct {
	store         *oauth.Store
	port          string
	authServerURL string
}

func NewResourceServer() *ResourceServer {
	return &ResourceServer{
		store:         oauth.NewStore(),
		port:          viper.GetString("resource.port"),
		authServerURL: viper.GetString("resource.auth_server_url"),
	}
}

func (rs *ResourceServer) validateToken(token string) (*oauth.AccessToken, error) {
	req, err := http.NewRequest("GET", rs.authServerURL+"/validate", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	accessToken := &oauth.AccessToken{
		Token:     token,
		UserID:    "validated-user",
		ClientID:  "demo-client",
		Scope:     "read",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	return accessToken, nil
}

func (rs *ResourceServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		logger.LogOAuthMessage(logger.LogEntry{
			Timestamp:   time.Now(),
			Direction:   logger.Incoming,
			Source:      "CLIENT",
			Destination: "RESOURCE-SERVER",
			MessageType: "Resource Request",
			Headers: map[string]string{
				"Authorization": authHeader,
			},
			Payload: map[string]interface{}{
				"path":   r.URL.Path,
				"method": r.Method,
			},
		})

		if authHeader == "" {
			logger.LogError("RESOURCE-SERVER", fmt.Errorf("missing authorization header"))
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			logger.LogError("RESOURCE-SERVER", fmt.Errorf("invalid authorization header format"))
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		accessToken, err := rs.validateToken(token)
		if err != nil {
			logger.LogError("RESOURCE-SERVER", err)
			http.Error(w, "invalid_token", http.StatusUnauthorized)
			return
		}

		logger.LogOAuthMessage(logger.LogEntry{
			Timestamp:   time.Now(),
			Direction:   logger.Incoming,
			Source:      "RESOURCE-SERVER",
			Destination: "RESOURCE-SERVER",
			MessageType: "Token Validation Success",
			Payload: map[string]interface{}{
				"user_id":   accessToken.UserID,
				"client_id": accessToken.ClientID,
				"scope":     accessToken.Scope,
			},
		})

		next(w, r)
	}
}

func (rs *ResourceServer) getProtectedResource(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("data/protected-resource.txt")
	if err != nil {
		logger.LogError("RESOURCE-SERVER", err)
		http.Error(w, "resource not found", http.StatusNotFound)
		return
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "RESOURCE-SERVER",
		Destination: "CLIENT",
		MessageType: "Protected Resource Response",
		Payload: map[string]interface{}{
			"resource_size": len(content),
			"content_type":  "text/plain",
		},
	})

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

func (rs *ResourceServer) getUserInfo(w http.ResponseWriter, r *http.Request) {
	userInfo := map[string]interface{}{
		"sub":                "demo-user",
		"name":               "Demo User",
		"preferred_username": "demo",
		"email":              "demo@example.com",
		"scope":              "read",
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "RESOURCE-SERVER",
		Destination: "CLIENT",
		MessageType: "User Info Response",
		Payload:     userInfo,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (rs *ResourceServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "oauth-resource-server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func initConfig() {
	// Set defaults
	viper.SetDefault("resource.port", ":8082")
	viper.SetDefault("resource.auth_server_url", "http://localhost:8081")

	// Bind environment variables
	viper.BindEnv("resource.port", "RESOURCE_PORT")
	viper.BindEnv("resource.auth_server_url", "RESOURCE_AUTH_SERVER_URL")

	// Define command-line flags
	var port, authServerURL string
	flag.StringVar(&port, "port", viper.GetString("resource.port"), "Resource server port")
	flag.StringVar(&authServerURL, "auth-server-url", viper.GetString("resource.auth_server_url"), "Authorization server URL")
	flag.Parse()

	// Set viper values from flags (flags have highest priority)
	viper.Set("resource.port", port)
	viper.Set("resource.auth_server_url", authServerURL)
}

func main() {
	initConfig()

	resourcePort := viper.GetString("resource.port")
	logger.LogInfo("RESOURCE-SERVER", fmt.Sprintf("Starting OAuth 2.1 Resource Server on port %s", resourcePort))

	resourceServer := NewResourceServer()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/health", resourceServer.healthCheck)

	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resourceServer.requireAuth(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r)
				})(w, r)
			})
		})

		r.Get("/protected", resourceServer.getProtectedResource)
		r.Get("/userinfo", resourceServer.getUserInfo)
	})

	logger.LogInfo("RESOURCE-SERVER", "Server ready to serve protected resources")
	if err := http.ListenAndServe(resourceServer.port, r); err != nil {
		logger.LogError("RESOURCE-SERVER", err)
	}
}

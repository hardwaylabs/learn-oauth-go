.PHONY: help build run-auth run-resource run-client run-all clean test fmt vet

# Client configuration defaults
CLIENT_PORT ?= :8088
CLIENT_AUTH_SERVER_URL ?= http://localhost:8081
CLIENT_RESOURCE_SERVER_URL ?= http://localhost:8082
CLIENT_CLIENT_ID ?= demo-client
CLIENT_SCOPE ?= read
# Note: CLIENT_REDIRECT_URI is automatically derived from CLIENT_PORT

# Auth server configuration defaults
AUTH_PORT ?= :8081
AUTH_CLIENT_ID ?= demo-client
AUTH_CLIENT_NAME ?= Demo OAuth Client

# Resource server configuration defaults
RESOURCE_PORT ?= :8082
RESOURCE_AUTH_SERVER_URL ?= http://localhost:8081

help: ## Show this help message
	@echo 'Usage: make [target] [VARIABLE=value ...]'
	@echo ''
	@echo 'Configuration variables:'
	@echo '  Client:'
	@echo '    CLIENT_PORT=:8080                    Client server port (redirect URI auto-derived)'
	@echo '    CLIENT_AUTH_SERVER_URL=http://localhost:8081  Auth server URL'
	@echo '    CLIENT_RESOURCE_SERVER_URL=http://localhost:8082  Resource server URL'
	@echo '    CLIENT_CLIENT_ID=demo-client          OAuth client ID'
	@echo '    CLIENT_SCOPE=read                     OAuth scope'
	@echo '  Auth Server:'
	@echo '    AUTH_PORT=:8081                       Auth server port'
	@echo '    AUTH_CLIENT_ID=demo-client            Default client ID'
	@echo '    AUTH_CLIENT_NAME="Demo OAuth Client"  Default client name'
	@echo '  Resource Server:'
	@echo '    RESOURCE_PORT=:8082                   Resource server port'
	@echo '    RESOURCE_AUTH_SERVER_URL=http://localhost:8081  Auth server URL'
	@echo ''
	@echo 'Examples:'
	@echo '  make run-client CLIENT_PORT=:9090'
	@echo '  make run-auth AUTH_PORT=:9091 AUTH_CLIENT_ID=my-client'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all applications
	@echo "Building OAuth 2.1 applications..."
	@go build -o bin/auth-server cmd/auth-server/main.go
	@go build -o bin/resource-server cmd/resource-server/main.go
	@go build -o bin/client cmd/client/main.go
	@echo "Build complete. Binaries in bin/ directory."

run-auth: ## Run authorization server
	@echo "Starting Authorization Server on port $(AUTH_PORT)..."
	@go run cmd/auth-server/main.go \
		--port "$(AUTH_PORT)" \
		--client-id "$(AUTH_CLIENT_ID)" \
		--client-name "$(AUTH_CLIENT_NAME)"

run-resource: ## Run resource server
	@echo "Starting Resource Server on port $(RESOURCE_PORT)..."
	@go run cmd/resource-server/main.go \
		--port "$(RESOURCE_PORT)" \
		--auth-server-url "$(RESOURCE_AUTH_SERVER_URL)"

run-client: ## Run client application
	@echo "Starting Client Application on port $(CLIENT_PORT)..."
	@go run cmd/client/main.go \
		--port "$(CLIENT_PORT)" \
		--auth-server-url "$(CLIENT_AUTH_SERVER_URL)" \
		--resource-server-url "$(CLIENT_RESOURCE_SERVER_URL)" \
		--client-id "$(CLIENT_CLIENT_ID)" \
		--scope "$(CLIENT_SCOPE)"

run-all: ## Run all servers in background (requires terminal multiplexer)
	@echo "Starting all OAuth 2.1 components..."
	@echo "Authorization Server: http://localhost$(AUTH_PORT)"
	@echo "Resource Server: http://localhost$(RESOURCE_PORT)"
	@echo "Client Application: http://localhost$(CLIENT_PORT)"
	@echo ""
	@echo "Run in separate terminals:"
	@echo "  make run-auth"
	@echo "  make run-resource"
	@echo "  make run-client"
	@echo ""
	@echo "Or with custom configuration:"
	@echo "  make run-auth AUTH_PORT=:9091"
	@echo "  make run-resource RESOURCE_PORT=:9092 RESOURCE_AUTH_SERVER_URL=http://localhost:9091"
	@echo "  make run-client CLIENT_PORT=:9090 CLIENT_AUTH_SERVER_URL=http://localhost:9091 CLIENT_RESOURCE_SERVER_URL=http://localhost:9092"

test: ## Run tests
	@go test ./...

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...

clean: ## Clean build artifacts
	@rm -rf bin/
	@echo "Clean complete."

deps: ## Download dependencies
	@go mod tidy
	@go mod download

check: fmt vet test ## Run all checks (format, vet, test)

demo: ## Show demo instructions
	@echo "OAuth 2.1 Demo Instructions:"
	@echo "1. Start all three servers in separate terminals:"
	@echo "   Terminal 1: make run-auth"
	@echo "   Terminal 2: make run-resource"
	@echo "   Terminal 3: make run-client"
	@echo ""
	@echo "   Or with custom ports:"
	@echo "   Terminal 1: make run-auth AUTH_PORT=:9091"
	@echo "   Terminal 2: make run-resource RESOURCE_PORT=:9092 RESOURCE_AUTH_SERVER_URL=http://localhost:9091"
	@echo "   Terminal 3: make run-client CLIENT_PORT=:9090 CLIENT_AUTH_SERVER_URL=http://localhost:9091 CLIENT_RESOURCE_SERVER_URL=http://localhost:9092"
	@echo ""
	@echo "2. Open browser to: http://localhost$(CLIENT_PORT)"
	@echo ""
	@echo "3. Demo accounts:"
	@echo "   alice / password123"
	@echo "   bob / secret456"
	@echo "   carol / mypass789"
	@echo ""
	@echo "4. Follow the OAuth flow in the browser"
	@echo "5. Watch the colored message logs in each terminal"
# SoftPOS API Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help install dev test lint format clean build run docker

# Default target
.DEFAULT_GOAL := help

# Colors for output
CYAN := \033[96m
GREEN := \033[92m
YELLOW := \033[93m
RED := \033[91m
RESET := \033[0m

help: ## Show this help message
	@echo "$(CYAN)SoftPOS API Development Commands$(RESET)"
	@echo "================================="
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install dependencies with Poetry
	@echo "$(CYAN)Installing dependencies...$(RESET)"
	poetry install
	@echo "$(GREEN)Dependencies installed successfully!$(RESET)"

dev: ## Install development dependencies
	@echo "$(CYAN)Installing development dependencies...$(RESET)"
	poetry install --with dev
	@echo "$(GREEN)Development dependencies installed!$(RESET)"

test: ## Run all tests
	@echo "$(CYAN)Running all tests...$(RESET)"
	python run_tests.py

test-unit: ## Run unit tests only
	@echo "$(CYAN)Running unit tests...$(RESET)"
	python run_tests.py --unit

test-integration: ## Run integration tests only
	@echo "$(CYAN)Running integration tests...$(RESET)"
	python run_tests.py --integration

test-security: ## Run security tests only
	@echo "$(CYAN)Running security tests...$(RESET)"
	python run_tests.py --security

test-payment: ## Run payment processing tests
	@echo "$(CYAN)Running payment tests...$(RESET)"
	python run_tests.py --payment

test-terminal: ## Run terminal management tests
	@echo "$(CYAN)Running terminal tests...$(RESET)"
	python run_tests.py --terminal

test-webhook: ## Run webhook tests
	@echo "$(CYAN)Running webhook tests...$(RESET)"
	python run_tests.py --webhook

test-monitoring: ## Run monitoring tests
	@echo "$(CYAN)Running monitoring tests...$(RESET)"
	python run_tests.py --monitoring

test-e2e: ## Run end-to-end tests
	@echo "$(CYAN)Running E2E tests...$(RESET)"
	python run_tests.py --e2e

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)Running tests with coverage...$(RESET)"
	python run_tests.py --coverage
	@echo "$(GREEN)Coverage report generated in htmlcov/index.html$(RESET)"

test-ci: ## Run tests in CI mode
	@echo "$(CYAN)Running tests in CI mode...$(RESET)"
	python run_tests.py --ci

lint: ## Run code linting
	@echo "$(CYAN)Running linting...$(RESET)"
	ruff check app/ tests/
	@echo "$(GREEN)Linting completed!$(RESET)"

lint-fix: ## Run linting with auto-fix
	@echo "$(CYAN)Running linting with auto-fix...$(RESET)"
	ruff check --fix app/ tests/
	@echo "$(GREEN)Linting with auto-fix completed!$(RESET)"

format: ## Format code with ruff
	@echo "$(CYAN)Formatting code...$(RESET)"
	ruff format app/ tests/
	@echo "$(GREEN)Code formatting completed!$(RESET)"

check: ## Run all checks (lint + format + tests)
	@echo "$(CYAN)Running all checks...$(RESET)"
	make lint
	make format
	make test-unit
	@echo "$(GREEN)All checks completed!$(RESET)"

clean: ## Clean up generated files
	@echo "$(CYAN)Cleaning up...$(RESET)"
	find . -type d -name "__pycache__" -delete
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*.pyd" -delete
	find . -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	@echo "$(GREEN)Cleanup completed!$(RESET)"

run: ## Run the development server
	@echo "$(CYAN)Starting development server...$(RESET)"
	poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-prod: ## Run the production server
	@echo "$(CYAN)Starting production server...$(RESET)"
	poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

migrate: ## Run database migrations
	@echo "$(CYAN)Running database migrations...$(RESET)"
	poetry run alembic upgrade head
	@echo "$(GREEN)Database migrations completed!$(RESET)"

migrate-create: ## Create a new migration
	@echo "$(CYAN)Creating new migration...$(RESET)"
	@read -p "Enter migration message: " msg; \
	poetry run alembic revision --autogenerate -m "$$msg"
	@echo "$(GREEN)Migration created!$(RESET)"

db-reset: ## Reset database (WARNING: destructive)
	@echo "$(RED)WARNING: This will delete all data!$(RESET)"
	@read -p "Are you sure? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		poetry run alembic downgrade base; \
		poetry run alembic upgrade head; \
		echo "$(GREEN)Database reset completed!$(RESET)"; \
	else \
		echo "$(YELLOW)Database reset cancelled.$(RESET)"; \
	fi

build: ## Build the application
	@echo "$(CYAN)Building application...$(RESET)"
	poetry build
	@echo "$(GREEN)Build completed!$(RESET)"

docker-build: ## Build Docker image
	@echo "$(CYAN)Building Docker image...$(RESET)"
	docker build -t softpos-api:latest .
	@echo "$(GREEN)Docker image built successfully!$(RESET)"

docker-run: ## Run Docker container
	@echo "$(CYAN)Running Docker container...$(RESET)"
	docker run -p 8000:8000 --env-file .env softpos-api:latest

docker-compose-up: ## Start services with Docker Compose
	@echo "$(CYAN)Starting services with Docker Compose...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)Services started!$(RESET)"

docker-compose-down: ## Stop services with Docker Compose
	@echo "$(CYAN)Stopping services with Docker Compose...$(RESET)"
	docker-compose down
	@echo "$(GREEN)Services stopped!$(RESET)"

logs: ## Show application logs
	@echo "$(CYAN)Showing application logs...$(RESET)"
	docker-compose logs -f api

psql: ## Connect to PostgreSQL database
	@echo "$(CYAN)Connecting to database...$(RESET)"
	docker-compose exec postgres psql -U postgres -d softpos

redis-cli: ## Connect to Redis
	@echo "$(CYAN)Connecting to Redis...$(RESET)"
	docker-compose exec redis redis-cli

shell: ## Start Python shell with app context
	@echo "$(CYAN)Starting Python shell...$(RESET)"
	poetry run python -i -c "from app.main import app; import asyncio"

docs: ## Generate API documentation
	@echo "$(CYAN)Generating API documentation...$(RESET)"
	poetry run python -c "
import json
from app.main import app
with open('openapi.json', 'w') as f:
    json.dump(app.openapi(), f, indent=2)
"
	@echo "$(GREEN)API documentation generated in openapi.json$(RESET)"

security-scan: ## Run security vulnerability scan
	@echo "$(CYAN)Running security scan...$(RESET)"
	poetry run safety check
	@echo "$(GREEN)Security scan completed!$(RESET)"

deps-update: ## Update dependencies
	@echo "$(CYAN)Updating dependencies...$(RESET)"
	poetry update
	@echo "$(GREEN)Dependencies updated!$(RESET)"

deps-audit: ## Audit dependencies for security issues
	@echo "$(CYAN)Auditing dependencies...$(RESET)"
	poetry run pip-audit
	@echo "$(GREEN)Dependency audit completed!$(RESET)"

pre-commit: ## Set up pre-commit hooks
	@echo "$(CYAN)Setting up pre-commit hooks...$(RESET)"
	poetry run pre-commit install
	@echo "$(GREEN)Pre-commit hooks installed!$(RESET)"

benchmark: ## Run performance benchmarks
	@echo "$(CYAN)Running performance benchmarks...$(RESET)"
	poetry run python -m pytest tests/test_integration.py::TestPerformanceAndLoad -v
	@echo "$(GREEN)Benchmarks completed!$(RESET)"

health-check: ## Check service health
	@echo "$(CYAN)Checking service health...$(RESET)"
	curl -f http://localhost:8000/health || exit 1
	@echo "$(GREEN)Service is healthy!$(RESET)"

env-example: ## Create example environment file
	@echo "$(CYAN)Creating .env.example...$(RESET)"
	@cat > .env.example << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost:5432/softpos
TEST_DATABASE_URL=sqlite+aiosqlite:///:memory:

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Payment Processors
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# HSM Configuration
HSM_PROVIDER=mock
HSM_ENDPOINT=https://hsm.example.com
HSM_KEY_ID=your-hsm-key-id

# Monitoring
SENTRY_DSN=https://...
LOG_LEVEL=INFO

# Environment
ENVIRONMENT=development
DEBUG=true
TESTING=false
EOF
	@echo "$(GREEN).env.example created!$(RESET)"

init: ## Initialize project for development
	@echo "$(CYAN)Initializing project...$(RESET)"
	make install
	make env-example
	make pre-commit
	@echo "$(GREEN)Project initialized! Copy .env.example to .env and configure.$(RESET)"

ci-test: ## Run tests for CI/CD pipeline
	@echo "$(CYAN)Running CI tests...$(RESET)"
	make lint
	make test-ci
	make security-scan
	@echo "$(GREEN)CI tests completed!$(RESET)"

deploy-staging: ## Deploy to staging environment
	@echo "$(CYAN)Deploying to staging...$(RESET)"
	# Add your staging deployment commands here
	@echo "$(GREEN)Deployed to staging!$(RESET)"

deploy-prod: ## Deploy to production environment
	@echo "$(CYAN)Deploying to production...$(RESET)"
	# Add your production deployment commands here
	@echo "$(GREEN)Deployed to production!$(RESET)"
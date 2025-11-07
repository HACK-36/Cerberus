.PHONY: help build up down restart logs demo test test-unit test-integration test-e2e clean

# Default target
help:
	@echo "Cerberus - Active Defense Security Fabric"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build all Docker images"
	@echo "  make up             - Start all services"
	@echo "  make down           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - View logs (all services)"
	@echo "  make demo           - Run interactive demo"
	@echo "  make test           - Run all tests"
	@echo "  make test-unit      - Run unit tests"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-e2e       - Run end-to-end tests"
	@echo "  make clean          - Clean up containers and volumes"
	@echo "  make status         - Show service status"
	@echo ""

# Build Docker images
build:
	@echo "Building Docker images..."
	docker-compose build

# Start services
up:
	@echo "Starting Cerberus services..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Services started!"
	@make status

# Stop services
down:
	@echo "Stopping Cerberus services..."
	docker-compose down

# Restart services
restart: down up

# View logs
logs:
	docker-compose logs -f

# View logs for specific service
logs-gatekeeper:
	docker-compose logs -f gatekeeper

logs-switch:
	docker-compose logs -f switch

logs-labyrinth:
	docker-compose logs -f labyrinth

logs-sentinel:
	docker-compose logs -f sentinel

# Service status
status:
	@echo "Cerberus Service Status:"
	@echo "========================"
	@docker-compose ps

# Run demo
demo:
	@./scripts/demo.sh

# Install dependencies (local development)
install:
	pip install -r requirements.txt

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	pytest tests/unit/ -v

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@echo "Note: Services must be running (make up)"
	pytest tests/integration/ -v

# Run E2E acceptance test
test-e2e:
	@echo "Running end-to-end acceptance test..."
	@echo "Note: Services must be running (make up)"
	pytest tests/integration/test_e2e_flow.py::TestE2EFlow::test_complete_attack_to_block_flow -v -s

# Clean up
clean:
	@echo "Cleaning up containers, networks, and volumes..."
	docker-compose down -v
	@echo "Removing data directory contents..."
	rm -rf data/events/* data/captures/* data/models/*
	@echo "Clean complete!"

# Deep clean (includes images)
clean-all: clean
	@echo "Removing Docker images..."
	docker-compose down --rmi all -v
	@echo "Deep clean complete!"

# Health check all services
health:
	@echo "Checking service health..."
	@curl -sf http://localhost:8000/health && echo "✓ Gatekeeper: healthy" || echo "✗ Gatekeeper: down"
	@curl -sf http://localhost:8001/health && echo "✓ Switch: healthy" || echo "✗ Switch: down"
	@curl -sf http://localhost:8002/health && echo "✓ Labyrinth: healthy" || echo "✗ Labyrinth: down"
	@curl -sf http://localhost:8003/health && echo "✓ Sentinel: healthy" || echo "✗ Sentinel: down"

# Initialize data directories
init:
	@echo "Initializing data directories..."
	mkdir -p data/events data/captures data/models data/simulations data/captures/uploads
	@echo "Directories created!"

# Panic button - emergency shutdown
panic:
	@echo "🚨 PANIC: Emergency shutdown initiated!"
	@./scripts/panic.sh || (docker-compose down && echo "Emergency stop completed")

# Development mode (with hot reload)
dev:
	@echo "Starting in development mode..."
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Generate sample data
sample-data:
	@echo "Generating sample decoy data..."
	@python -c "from labyrinth.decoy_gen.data_generator import get_generator; g = get_generator(); import json; print(json.dumps(g.generate_users(10), indent=2))"

# View metrics
metrics:
	@echo "Opening Grafana dashboard..."
	@open http://localhost:3001 || xdg-open http://localhost:3001 || echo "Open http://localhost:3001 in your browser"

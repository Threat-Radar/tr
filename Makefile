.PHONY: help docker-build docker-shell docker-shell-project

# Default target
.DEFAULT_GOAL := help

# Variables
IMAGE_NAME := threat-radar
IMAGE_TAG := latest

help: ## Show this help message
	@echo "Threat Radar - Docker Commands"
	@echo "==============================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

docker-build: ## Build Docker image
	docker build -f docker/Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✓ Docker image built: $(IMAGE_NAME):$(IMAGE_TAG)"

docker-shell: ## Open interactive shell in container
	@DOCKER_GID=$$(stat -f '%g' /var/run/docker.sock 2>/dev/null || stat -c '%g' /var/run/docker.sock 2>/dev/null || echo "0"); \
	docker run --rm -it \
		--group-add $$DOCKER_GID \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/storage:/app/storage \
		-v $(PWD)/sbom_storage:/app/sbom_storage \
		-v $(PWD)/cache:/app/cache \
		--env-file .env \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-shell-project: ## Open shell with project mounted (PROJECT=/path/to/project)
	@if [ -z "$(PROJECT)" ]; then \
		echo "Error: PROJECT not set."; \
		echo "Usage: make docker-shell-project PROJECT=/path/to/project"; \
		exit 1; \
	fi
	@DOCKER_GID=$$(stat -f '%g' /var/run/docker.sock 2>/dev/null || stat -c '%g' /var/run/docker.sock 2>/dev/null || echo "0"); \
	docker run --rm -it \
		--group-add $$DOCKER_GID \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD)/storage:/app/storage \
		-v $(PWD)/sbom_storage:/app/sbom_storage \
		-v $(PWD)/cache:/app/cache \
		-v $(PROJECT):/workspace:ro \
		--env-file .env \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(IMAGE_TAG)

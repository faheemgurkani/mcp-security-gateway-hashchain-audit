COMPOSE = docker compose -f lab/compose/docker-compose.yml

.PHONY: test lint lab-image lab-up lab-down lab-logs

test:
	uv run pytest -q

lint:
	uv run ruff check . && uv run ruff format --check .

lab-image:
	docker build -q -t mcp-gateway-lab:dev -f lab/compose/Dockerfile .

lab-up: lab-image
	uv run python -m lab.setup
	$(COMPOSE) up -d --wait

lab-down:
	$(COMPOSE) down -v

lab-logs:
	$(COMPOSE) logs --tail=100

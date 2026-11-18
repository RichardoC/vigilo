# Vigilo — grey-box scans from the command line.
# The white-box engine runs on the web platform (see README.md).

.PHONY: help build-greybox build-greybox-opencode build-greybox-codex \
        greybox greybox-opencode greybox-codex \
        greybox-logs greybox-graph greybox-ui greybox-stop greybox-clean

SHELL := /bin/bash
-include .env
export

URL    ?=
CREDS  ?=
CONFIG ?=
W      ?=

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

BOLD  := \033[1m
DIM   := \033[2m
CYAN  := \033[36m
GREEN := \033[32m
RED   := \033[31m
YEL   := \033[33m
RESET := \033[0m

# $(call banner,Title)
define banner
	@printf '\n$(BOLD)$(CYAN)  ▌ Vigilo$(RESET)$(BOLD) · %s$(RESET)\n$(DIM)  ──────────────────────────────────────────────$(RESET)\n\n' "$(1)"
endef

ok   = printf '  $(GREEN)✓$(RESET)  %s\n'
kv   = printf '  $(DIM)%-12s$(RESET) %s\n'
step = printf '  $(YEL)⟳$(RESET)  %s\n'

# ---------------------------------------------------------------------------
# Compose files per executor
# ---------------------------------------------------------------------------

COMPOSE          := docker compose -f docker-compose.greybox.yml
COMPOSE_CLAUDE   := $(COMPOSE)
COMPOSE_OPENCODE := $(COMPOSE) -f docker-compose.opencode.yml
COMPOSE_CODEX    := $(COMPOSE) -f docker-compose.codex.yml
SCAN_ENV         := CREDS_FILE="$(CURDIR)/configs" OUTPUT_DIR="$(CURDIR)/.vigilo"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show this help
	@printf '\n$(BOLD)$(CYAN)  ▌ Vigilo$(RESET)$(BOLD) · grey-box pentest from the command line$(RESET)\n'
	@printf '$(DIM)  Tests a running web application without its source code.$(RESET)\n'
	@awk 'BEGIN {FS = ":.*?## "} \
		/^##@/ { printf "\n$(BOLD)  %s$(RESET)\n", substr($$0, 5); next } \
		/^help:/ { next } \
		/^[a-zA-Z_-]+:.*?## / { printf "    $(CYAN)%-24s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '\n$(BOLD)  Example$(RESET)\n'
	@printf '    make build-greybox\n'
	@printf '    make greybox URL=https://app.example.com CREDS=configs/creds.yaml\n'
	@printf '\n$(DIM)  CREDS and CONFIG must be files under configs/ (see configs/greybox-*-example.yaml).$(RESET)\n\n'

##@ Build the scanner image (once, and after updating Vigilo)

build-greybox: ## Claude Code executor (default)
	$(call banner,Build grey-box image — Claude Code)
	@$(COMPOSE_CLAUDE) build worker
	@printf '\n'; $(ok) "Image ready. Next: make greybox URL=… CREDS=configs/creds.yaml"; printf '\n'

build-greybox-codex: ## Codex executor (OpenAI-compatible endpoint)
	$(call banner,Build grey-box image — Codex)
	@$(COMPOSE_CODEX) build worker
	@printf '\n'; $(ok) "Image ready. Next: make greybox-codex URL=… CREDS=configs/creds.yaml"; printf '\n'

build-greybox-opencode: ## OpenCode executor (local / self-hosted models via LiteLLM)
	$(call banner,Build grey-box image — OpenCode)
	@$(COMPOSE_OPENCODE) build worker
	@printf '\n'; $(ok) "Image ready. Next: make greybox-opencode URL=… CREDS=configs/creds.yaml"; printf '\n'

##@ Run a scan  (URL=<target>  CREDS=configs/<file>.yaml  [CONFIG=configs/<file>.yaml])

greybox: ## Scan with the Claude Code executor
	@$(MAKE) --no-print-directory _scan EXEC_NAME="Claude Code" COMPOSE_CMD='$(COMPOSE_CLAUDE)' \
		ENTRY='python3 -m src.greybox.temporal.worker' TARGET_NAME=greybox

greybox-codex: ## Scan with the Codex executor
	@$(MAKE) --no-print-directory _scan EXEC_NAME="Codex" COMPOSE_CMD='$(COMPOSE_CODEX)' \
		ENTRY='codex-entrypoint' TARGET_NAME=greybox-codex

greybox-opencode: ## Scan with the OpenCode executor
	@$(MAKE) --no-print-directory _scan EXEC_NAME="OpenCode" COMPOSE_CMD='$(COMPOSE_OPENCODE)' \
		ENTRY='opencode-entrypoint' TARGET_NAME=greybox-opencode

# Shared scan recipe (internal; called by the three targets above).
_scan:
	@if [ -z "$(URL)" ] || [ -z "$(CREDS)" ]; then \
		printf '\n  $(RED)✗$(RESET)  Missing arguments.\n\n'; \
		printf '     Usage: make $(TARGET_NAME) URL=https://app.example.com CREDS=configs/creds.yaml\n'; \
		printf '            [CONFIG=configs/scan.yaml]\n\n'; exit 1; fi
	@if [ ! -f "$(CREDS)" ]; then \
		printf '\n  $(RED)✗$(RESET)  Credentials file not found: %s\n' "$(CREDS)"; \
		printf '     Copy configs/greybox-creds-example.yaml to configs/ and edit it.\n\n'; exit 1; fi
	@case "$(CREDS)$(CONFIG)" in *..*) printf '\n  $(RED)✗$(RESET)  Use paths inside configs/.\n\n'; exit 1;; esac
	@if [ -n "$(CONFIG)" ] && [ ! -f "$(CONFIG)" ]; then \
		printf '\n  $(RED)✗$(RESET)  Config file not found: %s\n\n' "$(CONFIG)"; exit 1; fi
	@mkdir -p "$(CURDIR)/.vigilo" && chmod 777 "$(CURDIR)/.vigilo"
	$(call banner,Grey-box scan — $(EXEC_NAME))
	@$(kv) "Target" "$(URL)"
	@$(kv) "Identities" "$(CREDS)"
	@$(kv) "Config" "$(if $(CONFIG),$(CONFIG),—)"
	@$(kv) "Executor" "$(EXEC_NAME)"
	@$(kv) "Results" ".vigilo/<session-id>/"
	@printf '\n'; $(step) "Starting the knowledge graph and the orchestrator…"
	@$(SCAN_ENV) $(COMPOSE_CMD) up -d --quiet-pull temporal surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 2; done
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-temporal-greybox 2>/dev/null | grep -q healthy; do sleep 2; done
	@$(ok) "Knowledge graph   http://localhost:8800  (Surrealist)"
	@$(ok) "Workflow view     http://localhost:8233"
	@printf '\n'; $(step) "Scanning — follow along in another terminal with: make greybox-logs"; printf '\n'
	@$(SCAN_ENV) $(COMPOSE_CMD) run --rm worker \
		$(ENTRY) --url "$(URL)" --creds "/app/configs/$(CREDS:configs/%=%)" \
		$(if $(CONFIG),--config "/app/configs/$(CONFIG:configs/%=%)")
	@latest=$$(ls -td .vigilo/gb-* 2>/dev/null | head -1); \
		printf '\n'; $(ok) "Scan finished. Results: $${latest:-.vigilo/}"; \
		[ -n "$$latest" ] && $(kv) "Report" "$$latest/deliverables/greybox_assessment_report.md"; printf '\n'

##@ Inspect a scan

greybox-logs: ## Follow a scan's log (latest scan, or W=.vigilo/<session-id>)
	@target="$(W)"; [ -n "$$target" ] || target=$$(ls -td .vigilo/gb-* 2>/dev/null | head -1); \
		if [ -z "$$target" ] || [ ! -f "$$target/workflow.log" ]; then \
			printf '\n  $(RED)✗$(RESET)  No scan log found yet (looked for %s/workflow.log).\n\n' "$${target:-.vigilo/gb-*}"; exit 1; fi; \
		printf '\n'; $(kv) "Following" "$$target/workflow.log  (Ctrl-C to stop)"; printf '\n'; \
		tail -f "$$target/workflow.log"

greybox-graph: ## Export the knowledge graph of the running scan (YAML)
	@$(COMPOSE) exec worker graph-tool export --format yaml

greybox-ui: ## Open the knowledge-graph browser (Surrealist) on port 8800
	$(call banner,Knowledge graph browser)
	@$(COMPOSE) up -d --quiet-pull surrealdb surrealist
	@until docker inspect --format='{{.State.Health.Status}}' vigilo-surrealdb 2>/dev/null | grep -q healthy; do sleep 1; done
	@$(ok) "Surrealist   http://localhost:8800"
	@printf '\n  Connect with:\n'
	@$(kv) "URL" "ws://localhost:$${SURREALDB_HOST_PORT:-8010}"
	@$(kv) "Namespace" "vigilo"
	@$(kv) "Database" "<session-id> of the scan"
	@$(kv) "User" "root"
	@$(kv) "Password" "SURREALDB_PASS from your .env"
	@printf '\n'

##@ Housekeeping

greybox-stop: ## Stop the grey-box containers (keeps scan state)
	@$(step) "Stopping grey-box containers…"
	@$(COMPOSE) down >/dev/null 2>&1
	@$(ok) "Stopped"

greybox-clean: ## Stop and wipe orchestrator + knowledge-graph state (aborts stale scans)
	@$(step) "Stopping grey-box containers and wiping their volumes…"
	@$(COMPOSE) down -v >/dev/null 2>&1
	@$(ok) "Clean — scan results in .vigilo/ are kept"

.DEFAULT_GOAL := help
.PHONY: help dev dev-down dev-clean dev-logs dev-seed dev-shell-kc dev-shell-pg dev-route-add dev-route-list

COMPOSE := docker compose -f dev/compose.yaml

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nLayer 1 (local dev):\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

dev: ## Layer 1: bring up Postgres+Redis+Keycloak+OpenResty+MailHog
	$(COMPOSE) up -d
	@echo
	@echo "Postgres:  localhost:15432  (postgres / dev)"
	@echo "Redis:     localhost:16379"
	@echo "Keycloak:  http://localhost:8180  (admin / admin)"
	@echo "OpenResty: http://localhost:8090  (try: curl -H 'Host: bank1.local' http://localhost:8090)"
	@echo "MailHog:   http://localhost:8025"
	@echo
	@echo "Next: cd apps/auth-manager && mvn spring-boot:run -Dspring-boot.run.profiles=local"
	@echo "      cd apps/admin-ui     && npm run dev"

dev-down: ## Layer 1: stop services (preserves volumes)
	$(COMPOSE) down

dev-clean: ## Layer 1: stop AND drop volumes (full reset)
	$(COMPOSE) down -v

dev-logs: ## Layer 1: tail all service logs
	$(COMPOSE) logs -f --tail=50

dev-seed: ## Re-import realm.json into running Keycloak
	$(COMPOSE) exec keycloak \
	  /opt/keycloak/bin/kc.sh import \
	  --file=/opt/keycloak/data/import/realm.json --override=true

dev-shell-kc: ## Open a kcadm shell against the local KC (auths as admin)
	$(COMPOSE) exec keycloak \
	  /opt/keycloak/bin/kcadm.sh config credentials \
	  --server http://localhost:8180 --realm master \
	  --user admin --password admin

dev-shell-pg: ## Open a psql shell on the authmanager DB
	$(COMPOSE) exec postgres psql -U postgres -d authmanager

dev-route-add: ## Add a routing entry: make dev-route-add HOST=bank1.local BACKEND=auth-manager:8080
	@test -n "$(HOST)" || (echo "HOST required" && exit 1)
	@test -n "$(BACKEND)" || (echo "BACKEND required" && exit 1)
	$(COMPOSE) exec redis redis-cli HSET host:$(HOST) backend $(BACKEND)
	@echo "Routed $(HOST) → $(BACKEND). Test with:"
	@echo "  curl -H 'Host: $(HOST)' http://localhost:8090"

dev-route-list: ## List all routing entries in Redis
	$(COMPOSE) exec redis sh -c 'for k in $$(redis-cli --scan --pattern "host:*"); do printf "%-40s " "$$k"; redis-cli HGETALL "$$k" | paste - - ; done'

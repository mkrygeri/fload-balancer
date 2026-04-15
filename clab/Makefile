.PHONY: images image-lb image-sender image-collector deploy destroy logs status stats help

CLAB  ?= sudo containerlab
TOPO  := fload-lab.clab.yml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ── Image builds ───────────────────────────────────────────────
images: image-lb image-sender image-collector ## Build all container images

image-lb: ## Build fload-balancer image
	docker build -t fload-balancer:latest ..

image-sender: ## Build sender image
	docker build -t fload-sender:latest sender/

image-collector: ## Build collector image
	docker build -t fload-collector:latest collector/

# ── Lab lifecycle ──────────────────────────────────────────────
deploy: ## Deploy the containerlab topology
	$(CLAB) deploy -t $(TOPO)

destroy: ## Destroy the containerlab topology
	$(CLAB) destroy -t $(TOPO) --cleanup

# ── Monitoring ─────────────────────────────────────────────────
logs: ## Tail logs from all containers
	@for c in $$(docker ps --filter "label=clab-node-name" --format '{{.Names}}' | sort); do \
		echo "=== $$c ==="; \
		docker logs --tail 5 $$c 2>&1; \
		echo; \
	done

logs-lb: ## Follow LB logs
	docker logs -f clab-fload-lab-lb

logs-collectors: ## Tail collector logs
	@for i in 01 02 03 04; do \
		echo "=== collector$$i ==="; \
		docker logs --tail 3 clab-fload-lab-collector$$i 2>&1; \
		echo; \
	done

status: ## Show node status table
	$(CLAB) inspect -t $(TOPO)

stats: ## Show LB stats via lbctl
	docker exec clab-fload-lab-lb lbctl -addr localhost:50051 stats

backends: ## Show backend status via lbctl
	docker exec clab-fload-lab-lb lbctl -addr localhost:50051 backends

sessions: ## Show active sessions via lbctl
	docker exec clab-fload-lab-lb lbctl -addr localhost:50051 sessions

flow-stats: ## Show per-flow-type stats via lbctl
	docker exec clab-fload-lab-lb lbctl -addr localhost:50051 flow-stats

seq-stats: ## Show sequence tracking stats via lbctl
	docker exec clab-fload-lab-lb lbctl -addr localhost:50051 seq-stats

ui: ## Open the web UI in default browser
	@echo "Web UI: http://localhost:18080"
	@echo "   or:  http://10.100.0.100:8080"
	@xdg-open http://localhost:18080 2>/dev/null || echo "(open manually)"

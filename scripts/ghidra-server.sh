#!/usr/bin/env bash
set -euo pipefail

COMPOSE="docker-compose.yml"
APPS="ghidra-api-1 ghidra-api-2 traefik"

case "${1:-}" in
  start|up)
    docker compose -f "$COMPOSE" up -d --build $APPS
    echo "➡  Ghidra API: http://localhost:8000  (add header: X-Api-Key: ${MCPO_API_KEY:-top-secret})"
    echo "➡  Swagger UI: http://localhost:8000/docs"
    ;;
  stop|down)
    docker compose -f "$COMPOSE" down $APPS
    ;;
  restart)
    docker compose -f "$COMPOSE" restart $APPS
    ;;
  logs)
    docker compose -f "$COMPOSE" logs -f $APPS
    ;;
  status)
    docker compose -f "$COMPOSE" ps $APPS
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|logs|status}"
    exit 1
    ;;
esac

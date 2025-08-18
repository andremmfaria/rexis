#!/usr/bin/env bash
set -euo pipefail

COMPOSE="docker-compose.yml"
APPS="db"

case "${1:-}" in
  start|up)
    docker compose -f "$COMPOSE" up -d $APPS
    echo "➡  PostgreSQL is starting on localhost:5432"
    ;;
  stop|down)
    docker compose -f "$COMPOSE" stop $APPS
    ;;
  restart)
    docker compose -f "$COMPOSE" restart $APPS
    ;;
  logs)
    docker compose -f "$COMPOSE" logs -f --tail=200 $APPS
    ;;
  status)
    docker compose -f "$COMPOSE" ps $APPS
    ;;
  shell)
    # quick psql shell inside the container (requires psql in image)
    docker exec -it rexis-db psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-rexis}"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|logs|status|shell}"
    exit 1
    ;;
esac

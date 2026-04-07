#!/usr/bin/env bash
#
# Database Audit Pipeline Health Check
# Wazuh 4.14.4 | Database Activity Monitoring
#
# Verifica se cada SGBD está a enviar eventos dentro do intervalo esperado.
# Se não houver eventos nos últimos THRESHOLD_MINUTES, alerta via syslog/stderr.
#
# Referências regulatórias:
#   PCI-DSS 10.6.1: Revisão diária de logs
#   RGPD Art. 32: Garantir disponibilidade e resiliência dos sistemas de tratamento
#
# Variáveis obrigatórias:
#   WAZUH_API_URL   — URL da API Wazuh (ex: https://wazuh-master:55000)
#   WAZUH_API_TOKEN — Bearer token para autenticação na API
#
# Cron (a cada 30 minutos):
#   */30 * * * * /var/ossec/integrations/check-db-pipeline.sh >> /var/log/db-pipeline-health.log 2>&1
#

set -euo pipefail

THRESHOLD_MINUTES="${THRESHOLD_MINUTES:-30}"
WAZUH_API_URL="${WAZUH_API_URL:?ERROR: WAZUH_API_URL não definida}"
WAZUH_API_TOKEN="${WAZUH_API_TOKEN:?ERROR: WAZUH_API_TOKEN não definido}"
LOG_TAG="db-pipeline-health"

SGBD_GROUPS=("db_mariadb" "db_postgresql" "db_mssql")

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_info() {
    echo "[$(timestamp)] INFO: $*"
    logger -t "$LOG_TAG" "INFO: $*" 2>/dev/null || true
}

log_error() {
    echo "[$(timestamp)] ERROR: $*" >&2
    logger -t "$LOG_TAG" -p user.err "ERROR: $*" 2>/dev/null || true
}

check_group_events() {
    local group="$1"
    local since
    since=$(date -u -v-${THRESHOLD_MINUTES}M '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || \
            date -u -d "${THRESHOLD_MINUTES} minutes ago" '+%Y-%m-%dT%H:%M:%S')

    local response
    response=$(curl -sk \
        -H "Authorization: Bearer ${WAZUH_API_TOKEN}" \
        -H "Content-Type: application/json" \
        "${WAZUH_API_URL}/alerts?q=rule.groups=${group}&date_from=${since}&limit=1" \
        2>/dev/null)

    local total
    total=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('total_affected_items',0))" 2>/dev/null || echo "0")

    if [ "$total" -eq 0 ] 2>/dev/null; then
        log_error "SEM EVENTOS do grupo '${group}' nos últimos ${THRESHOLD_MINUTES} minutos — pipeline possivelmente em falha"
        return 1
    else
        log_info "OK: ${group} — ${total} evento(s) nos últimos ${THRESHOLD_MINUTES} minutos"
        return 0
    fi
}

main() {
    log_info "Início da verificação do pipeline de auditoria de BD"

    local failures=0

    for group in "${SGBD_GROUPS[@]}"; do
        if ! check_group_events "$group"; then
            ((failures++))
        fi
    done

    if [ "$failures" -gt 0 ]; then
        log_error "${failures}/${#SGBD_GROUPS[@]} grupo(s) sem eventos — investigar"
        exit 1
    else
        log_info "Todos os pipelines activos — ${#SGBD_GROUPS[@]}/${#SGBD_GROUPS[@]} OK"
        exit 0
    fi
}

main "$@"

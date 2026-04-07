#!/bin/bash
# ============================================================
# run-logtest.sh — Testes automatizados wazuh-logtest para MSSQL
# Uso: sudo bash run-logtest.sh
# ============================================================

set -euo pipefail

LOGTEST="/var/ossec/bin/wazuh-logtest"
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS=0; FAIL=0

[ ! -x "$LOGTEST" ] && echo -e "${RED}Erro: executar no Wazuh Manager.${NC}" && exit 1

run_test() {
  local desc="$1" log_line="$2" expected_decoder="$3" expected_rule="$4"
  local output
  output=$(echo "$log_line" | "$LOGTEST" 2>&1)
  if echo "$output" | grep -q "decoder: '$expected_decoder'" && \
     echo "$output" | grep -q "Rule id: '$expected_rule'"; then
    echo -e "  ${GREEN}[PASS]${NC} $desc"
    ((PASS++)) || true
  else
    echo -e "  ${RED}[FAIL]${NC} $desc (esperado decoder=$expected_decoder rule=$expected_rule)"
    echo "$output" | grep -E "decoder:|Rule id:" | head -4 | sed 's/^/         /'
    ((FAIL++)) || true
  fi
}

echo ""
echo "=== Testes wazuh-logtest — MSSQL Audit ==="
echo ""

echo "1. Sessões"
run_test "Login bem-sucedido → 100270" \
  '{"ts":"2024-01-15T10:30:00","source":"mssql_audit","action_id":"LGIS","succeeded":true,"server_principal_name":"app_saga","database_name":"SAGA","object_name":"","statement":"","client_ip":"192.168.100.50","application_name":"SAGA Application"}' \
  "mssql-wazuh-audit" "100270"

echo "2. Autenticação"
run_test "Login falhado → 100271" \
  '{"ts":"2024-01-15T10:30:01","source":"mssql_audit","action_id":"LGFL","succeeded":false,"server_principal_name":"baduser","database_name":"master","object_name":"","statement":"","client_ip":"203.0.113.45","application_name":"sqlcmd"}' \
  "mssql-wazuh-audit" "100271"

echo "3. Privilégios"
run_test "GRANT → 100273" \
  '{"ts":"2024-01-15T10:30:10","source":"mssql_audit","action_id":"GRTO","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"","statement":"GRANT SELECT ON SCHEMA::dbo TO new_report_user","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  "mssql-wazuh-audit" "100273"

echo "4. DDL"
run_test "CREATE TABLE → 100275" \
  '{"ts":"2024-01-15T10:30:11","source":"mssql_audit","action_id":"CR","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"temp_export","statement":"CREATE TABLE temp_export (id INT)","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  "mssql-wazuh-audit" "100275"

run_test "DROP TABLE → 100276" \
  '{"ts":"2024-01-15T10:30:12","source":"mssql_audit","action_id":"DR","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"logs_antigos","statement":"DROP TABLE logs_antigos","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  "mssql-wazuh-audit" "100276"

echo "5. Exfiltração"
run_test "SELECT INTO → 100277" \
  '{"ts":"2024-01-15T10:30:13","source":"mssql_audit","action_id":"SL","succeeded":true,"server_principal_name":"app_saga","database_name":"SAGA","object_name":"clientes","statement":"SELECT nif, iban INTO #temp FROM clientes","client_ip":"192.168.100.50","application_name":"SAGA"}' \
  "mssql-wazuh-audit" "100277"

echo "6. Estado do servidor"
run_test "ALTER SERVER STATE → 100281" \
  '{"ts":"2024-01-15T10:30:14","source":"mssql_audit","action_id":"ALSS","succeeded":true,"server_principal_name":"sa","database_name":"master","object_name":"","statement":"ALTER SERVER STATE","client_ip":"192.168.100.8","application_name":"sqlcmd"}' \
  "mssql-wazuh-audit" "100281"

echo "7. Backup"
run_test "BACKUP DATABASE → 100282" \
  '{"ts":"2024-01-15T10:30:15","source":"mssql_audit","action_id":"BKDB","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"","statement":"BACKUP DATABASE [SAGA]","client_ip":"192.168.100.10","application_name":"SQL Server Agent"}' \
  "mssql-wazuh-audit" "100282"

echo ""
echo "=== Resumo: Passed=$PASS Failed=$FAIL ==="
[ $FAIL -gt 0 ] && exit 1 || echo ""

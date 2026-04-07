#!/bin/bash
# ============================================================
# run-logtest.sh — Testes automatizados wazuh-logtest para Oracle
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
    ((FAIL++)) || true
  fi
}

echo ""
echo "=== Testes wazuh-logtest — Oracle Audit ==="
echo ""

echo "1. Sessões"
run_test "LOGON bem-sucedido → 100230" \
  '{"ts":"2024-01-15T10:30:00Z","source":"unified_audit","user":"APP_USER","action":"LOGON","schema":"N/A","object":"N/A","sql":"","client":"sqlplus","host":"appserver","auth_type":"PASSWORD","return_code":0,"session_id":12345}' \
  "oracle-unified-audit" "100230"

echo "2. Autenticação"
run_test "LOGON falhado ORA-1017 → 100231" \
  '{"ts":"2024-01-15T10:30:02Z","source":"unified_audit","user":"BADUSER","action":"LOGON","schema":"N/A","object":"N/A","sql":"","client":"jdbc","host":"203.0.113.45","auth_type":"PASSWORD","return_code":1017,"session_id":0}' \
  "oracle-unified-audit" "100231"

echo "3. DDL"
run_test "CREATE TABLE → 100233" \
  '{"ts":"2024-01-15T10:30:01Z","source":"unified_audit","user":"APP_USER","action":"CREATE TABLE","schema":"APP_SCHEMA","object":"TEMP_EXPORT","sql":"CREATE TABLE TEMP_EXPORT AS SELECT 1","client":"sqlplus","host":"appserver","auth_type":"PASSWORD","return_code":0,"session_id":12345}' \
  "oracle-unified-audit" "100233"

run_test "DROP TABLE → 100234" \
  '{"ts":"2024-01-15T10:30:12Z","source":"unified_audit","user":"APP_USER","action":"DROP TABLE","schema":"APP_SCHEMA","object":"CLIENTES_BACKUP","sql":"DROP TABLE CLIENTES_BACKUP","client":"sqlplus","host":"appserver","auth_type":"PASSWORD","return_code":0,"session_id":12345}' \
  "oracle-unified-audit" "100234"

echo "4. Privilégios"
run_test "GRANT → 100235" \
  '{"ts":"2024-01-15T10:30:10Z","source":"unified_audit","user":"DBA_USER","action":"GRANT","schema":"N/A","object":"N/A","sql":"GRANT DBA TO NEWUSER","client":"SQL Developer","host":"mgmt","auth_type":"PASSWORD","return_code":0,"session_id":12346}' \
  "oracle-unified-audit" "100235"

run_test "Conta SYS → 100250" \
  '{"ts":"2024-01-15T10:30:11Z","source":"unified_audit","user":"SYS","action":"ALTER USER","schema":"N/A","object":"APP_USER","sql":"ALTER USER APP_USER IDENTIFIED BY newpassword","client":"sqlplus","host":"localhost","auth_type":"OS","return_code":0,"session_id":12347}' \
  "oracle-unified-audit" "100250"

echo "5. FGA — Dados PII"
run_test "Acesso PII (FGA) → 100240" \
  '{"ts":"2024-01-15T10:31:00Z","source":"fga_audit","user":"REPORT_USER","schema":"APP_SCHEMA","object":"CLIENTES","policy":"AUDIT_CLIENTES_PII","sql":"SELECT NIF, IBAN FROM CLIENTES WHERE ESTADO = '\''ATIVO'\''","return_code":3}' \
  "oracle-fga-audit" "100240"

echo ""
echo "=== Resumo: Passed=$PASS Failed=$FAIL ==="
[ $FAIL -gt 0 ] && exit 1 || echo ""

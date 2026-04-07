#!/bin/bash
# ============================================================
# run-logtest.sh — Testes automatizados wazuh-logtest para PostgreSQL
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
echo "=== Testes wazuh-logtest — PostgreSQL Audit ==="
echo ""

echo "1. Conexões"
run_test "Conexão autorizada → 100210" \
  "Jan 15 10:30:01 dbserver postgresql[1234]: [2-1] LOG:  connection authorized: user=app_user database=prod_db" \
  "postgresql-connection" "100210"

echo "2. Autenticação"
run_test "Password auth failed → 100211" \
  "Jan 15 10:30:04 dbserver postgresql[1235]: [1-1] FATAL:  password authentication failed for user \"baduser\"" \
  "postgresql-auth-failure" "100211"

run_test "No pg_hba entry → 100211" \
  "Jan 15 10:30:13 dbserver postgresql[1241]: [1-1] FATAL:  no pg_hba.conf entry for host \"203.0.113.45\", user \"scanner\", database \"postgres\", SSL off" \
  "postgresql-auth-failure" "100211"

echo "3. DDL"
run_test "CREATE TABLE → 100213" \
  "Jan 15 10:30:02 dbserver postgresql[1234]: [3-1] LOG:  AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.clientes,CREATE TABLE clientes (id INT),<not logged>" \
  "postgresql-audit" "100213"

run_test "DROP TABLE → 100214" \
  "Jan 15 10:30:14 dbserver postgresql[1234]: [8-1] LOG:  AUDIT: SESSION,6,1,DDL,DROP TABLE,TABLE,public.temp_exports,DROP TABLE temp_exports,<not logged>" \
  "postgresql-audit" "100214"

echo "4. Roles"
run_test "GRANT → 100215" \
  "Jan 15 10:30:09 dbserver postgresql[1240]: [1-1] LOG:  AUDIT: SESSION,3,1,ROLE,GRANT,,,GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user,<not logged>" \
  "postgresql-audit" "100215"

echo "5. Dados PII"
run_test "SELECT dados PII → 100216" \
  "Jan 15 10:30:11 dbserver postgresql[1234]: [6-1] LOG:  AUDIT: SESSION,5,1,READ,SELECT,TABLE,public.dados_pessoais,SELECT * FROM dados_pessoais WHERE nif = \$1,\"123456789\"" \
  "postgresql-audit" "100216"

echo "6. Erros"
run_test "Permission denied → 100219" \
  "Jan 15 10:30:12 dbserver postgresql[1234]: [7-1] ERROR:  permission denied for table documentos_secretos" \
  "postgresql-sql-error" "100219"

echo ""
echo "=== Resumo: Passed=$PASS Failed=$FAIL ==="
[ $FAIL -gt 0 ] && exit 1 || echo ""

#!/bin/bash
# ============================================================
# run-logtest.sh — Testes automatizados wazuh-logtest para MySQL
# Uso: sudo bash run-logtest.sh
# Requer: Wazuh Manager com decoders e regras instalados
# ============================================================

set -euo pipefail

LOGTEST="/var/ossec/bin/wazuh-logtest"
SAMPLE_LOG="$(dirname "$0")/sample-logs/mysql-audit-samples.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

if [ ! -x "$LOGTEST" ]; then
  echo -e "${RED}Erro: $LOGTEST não encontrado. Executar no Wazuh Manager.${NC}"
  exit 1
fi

run_test() {
  local desc="$1"
  local log_line="$2"
  local expected_decoder="$3"
  local expected_rule="$4"

  local output
  output=$(echo "$log_line" | "$LOGTEST" 2>&1)

  local decoder_ok=false
  local rule_ok=false

  if echo "$output" | grep -q "decoder: '$expected_decoder'"; then
    decoder_ok=true
  fi
  if echo "$output" | grep -q "Rule id: '$expected_rule'"; then
    rule_ok=true
  fi

  if $decoder_ok && $rule_ok; then
    echo -e "  ${GREEN}[PASS]${NC} $desc (decoder=$expected_decoder, rule=$expected_rule)"
    ((PASS++)) || true
  else
    echo -e "  ${RED}[FAIL]${NC} $desc"
    if ! $decoder_ok; then
      echo -e "         Esperado decoder: '$expected_decoder'"
      echo "$output" | grep "decoder:" | head -3 | sed 's/^/         Obtido:  /'
    fi
    if ! $rule_ok; then
      echo -e "         Esperada rule: '$expected_rule'"
      echo "$output" | grep "Rule id:" | head -3 | sed 's/^/         Obtida:  /'
    fi
    ((FAIL++)) || true
  fi
}

echo ""
echo "=== Testes wazuh-logtest — MySQL/MariaDB Audit ==="
echo ""

# ─── Teste 1: Sessão Connect (sucesso) ──────────────────────
echo "Grupo 1: Sessões"
run_test "Connect bem-sucedido → regra 100201" \
  '{"audit_record":{"name":"Connect","record":"1_2024-01-15T10:30:00","timestamp":"2024-01-15T10:30:00 UTC","command_class":"connect","connection_id":"12345","status":0,"sqltext":"","user":"app_user","host":"192.168.1.100","os_user":"","ip":"192.168.1.100","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100201"

run_test "Quit → regra 100201" \
  '{"audit_record":{"name":"Quit","record":"2_2024-01-15T10:35:00","timestamp":"2024-01-15T10:35:00 UTC","command_class":"quit","connection_id":"12345","status":0,"sqltext":"","user":"app_user","host":"192.168.1.100","os_user":"","ip":"192.168.1.100","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100201"

# ─── Teste 2: Falha de autenticação ─────────────────────────
echo ""
echo "Grupo 2: Autenticação"
run_test "Login falhado (status=1045) → regra 100202" \
  '{"audit_record":{"name":"Connect","record":"3_2024-01-15T10:31:00","timestamp":"2024-01-15T10:31:00 UTC","command_class":"connect","connection_id":"12346","status":1045,"sqltext":"","user":"baduser","host":"203.0.113.45","os_user":"","ip":"203.0.113.45","db":""}}' \
  "mysql-audit-json" \
  "100202"

# ─── Teste 3: DDL ───────────────────────────────────────────
echo ""
echo "Grupo 3: DDL"
run_test "CREATE TABLE → regra 100204" \
  '{"audit_record":{"name":"Query","record":"4_2024-01-15T10:30:02","timestamp":"2024-01-15T10:30:02 UTC","command_class":"create_table","connection_id":"12345","status":0,"sqltext":"CREATE TABLE test (id INT)","user":"dba_user","host":"mgmt","os_user":"dba","ip":"10.0.0.10","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100204"

run_test "DROP TABLE → regra 100204" \
  '{"audit_record":{"name":"Query","record":"5_2024-01-15T10:30:03","timestamp":"2024-01-15T10:30:03 UTC","command_class":"drop_table","connection_id":"12345","status":0,"sqltext":"DROP TABLE test","user":"dba_user","host":"mgmt","os_user":"dba","ip":"10.0.0.10","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100204"

# ─── Teste 4: Privilege escalation ──────────────────────────
echo ""
echo "Grupo 4: Privilégios"
run_test "GRANT → regra 100205" \
  '{"audit_record":{"name":"Query","record":"6_2024-01-15T10:32:00","timestamp":"2024-01-15T10:32:00 UTC","command_class":"grant","connection_id":"12351","status":0,"sqltext":"GRANT ALL ON prod_db.* TO \"newadmin\"@\"%\"","user":"root","host":"localhost","os_user":"root","ip":"","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100205"

# ─── Teste 5: Exfiltração ────────────────────────────────────
echo ""
echo "Grupo 5: Exfiltração"
run_test "SELECT INTO OUTFILE → regra 100207" \
  '{"audit_record":{"name":"Query","record":"7_2024-01-15T10:33:00","timestamp":"2024-01-15T10:33:00 UTC","command_class":"select","connection_id":"12352","status":0,"sqltext":"SELECT * FROM dados_pessoais INTO OUTFILE \"/tmp/export.csv\"","user":"app_user","host":"192.168.1.100","os_user":"","ip":"192.168.1.100","db":"prod_db"}}' \
  "mysql-audit-json" \
  "100207"

# ─── Teste de todas as amostras ──────────────────────────────
echo ""
echo "Teste de lote: processar sample-logs/mysql-audit-samples.log"
if [ -f "$SAMPLE_LOG" ]; then
  TOTAL=$(wc -l < "$SAMPLE_LOG")
  DECODED=0
  while IFS= read -r line; do
    if echo "$line" | "$LOGTEST" 2>&1 | grep -q "decoder:"; then
      ((DECODED++)) || true
    fi
  done < "$SAMPLE_LOG"
  echo -e "  Linhas processadas: $TOTAL | Decodificadas: $DECODED"
  if [ "$DECODED" -eq "$TOTAL" ]; then
    echo -e "  ${GREEN}[OK]${NC} Todas as linhas decodificadas"
    ((PASS++)) || true
  else
    echo -e "  ${YELLOW}[WARN]${NC} $((TOTAL - DECODED)) linhas não decodificadas"
  fi
fi

# ─── Resumo ──────────────────────────────────────────────────
echo ""
echo "=== Resumo ==="
echo -e "  ${GREEN}Passed: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
  echo -e "  ${RED}Failed: $FAIL${NC}"
  echo ""
  echo "Verificar se os decoders e regras estão instalados:"
  echo "  ls /var/ossec/etc/decoders/mysql-audit-decoders.xml"
  echo "  ls /var/ossec/etc/rules/mysql-audit-rules.xml"
  echo "  /var/ossec/bin/wazuh-analysisd -t"
  exit 1
fi
echo ""

#!/bin/bash
# ============================================================
# validate.sh — Verificação pós-instalação do Percona Audit Plugin
# Uso: sudo bash validate.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

AUDIT_LOG="/var/log/mysql/audit.log"
PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"   # "ok" ou "fail"
  local detail="$3"

  if [ "$result" = "ok" ]; then
    echo -e "  ${GREEN}[OK]${NC}  $desc"
    ((PASS++)) || true
  else
    echo -e "  ${RED}[FAIL]${NC} $desc — $detail"
    ((FAIL++)) || true
  fi
}

warn() {
  local desc="$1"
  local detail="$2"
  echo -e "  ${YELLOW}[WARN]${NC} $desc — $detail"
}

echo ""
echo "=== Validação Percona Audit Log Plugin ==="
echo ""

# ─── 1. MySQL em execução ────────────────────────────────────
echo "1. Estado do serviço MySQL"
if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null; then
  check "mysqld em execução" "ok" ""
else
  check "mysqld em execução" "fail" "systemctl start mysql"
fi

# ─── 2. Plugin carregado ─────────────────────────────────────
echo "2. Plugin de auditoria"
if mysql -u root -p"${MYSQL_ROOT_PASS:-}" -e "SHOW PLUGINS;" 2>/dev/null | grep -q "audit_log.*ACTIVE"; then
  check "audit_log plugin ACTIVE" "ok" ""
else
  check "audit_log plugin ACTIVE" "fail" \
    "Executar: mysql -u root -p -e \"INSTALL PLUGIN audit_log SONAME 'audit_log.so';\""
fi

# ─── 3. Formato JSON ─────────────────────────────────────────
echo "3. Formato de output"
FORMAT=$(mysql -u root -p"${MYSQL_ROOT_PASS:-}" -sN -e \
  "SHOW VARIABLES LIKE 'audit_log_format';" 2>/dev/null | awk '{print $2}')
if [ "$FORMAT" = "JSON" ]; then
  check "audit_log_format = JSON" "ok" ""
else
  check "audit_log_format = JSON" "fail" \
    "Valor atual: '$FORMAT'. Adicionar audit_log_format = JSON ao my.cnf"
fi

# ─── 4. Ficheiro de log existe e é legível ───────────────────
echo "4. Ficheiro de log"
LOG_PATH=$(mysql -u root -p"${MYSQL_ROOT_PASS:-}" -sN -e \
  "SHOW VARIABLES LIKE 'audit_log_file';" 2>/dev/null | awk '{print $2}')
LOG_PATH="${LOG_PATH:-$AUDIT_LOG}"

if [ -f "$LOG_PATH" ]; then
  check "Ficheiro existe: $LOG_PATH" "ok" ""
  SIZE=$(du -sh "$LOG_PATH" | cut -f1)
  echo "       Tamanho atual: $SIZE"
else
  check "Ficheiro existe: $LOG_PATH" "fail" \
    "Gerar um evento: mysql -u root -p -e 'SELECT 1;'"
fi

# ─── 5. Permissões do ficheiro ───────────────────────────────
echo "5. Permissões"
if [ -f "$LOG_PATH" ]; then
  PERMS=$(stat -c "%a" "$LOG_PATH")
  OWNER=$(stat -c "%U" "$LOG_PATH")
  if [[ "$PERMS" =~ ^6[04][04]$ ]] || [ "$PERMS" = "644" ]; then
    check "Permissões $PERMS (legível pelo wazuh-agent)" "ok" ""
  else
    check "Permissões $PERMS" "fail" \
      "Executar: chmod 644 $LOG_PATH"
  fi
  if [ "$OWNER" = "mysql" ]; then
    check "Owner: $OWNER" "ok" ""
  else
    warn "Owner: $OWNER" "Esperado: mysql"
  fi
fi

# ─── 6. Formato do log (JSON válido) ────────────────────────
echo "6. Validação de formato JSON"
if [ -f "$LOG_PATH" ] && [ -s "$LOG_PATH" ]; then
  LAST_LINE=$(tail -1 "$LOG_PATH")
  if echo "$LAST_LINE" | python3 -m json.tool > /dev/null 2>&1; then
    check "Última linha é JSON válido" "ok" ""
  else
    check "Última linha é JSON válido" "fail" \
      "Verificar: tail -1 $LOG_PATH | python3 -m json.tool"
  fi
else
  warn "Log vazio" "Gerar evento: mysql -u root -p -e 'SELECT 1;'"
fi

# ─── 7. Wazuh Agent a monitorizar o ficheiro ────────────────
echo "7. Wazuh Agent"
if [ -f "/var/ossec/etc/ossec.conf" ]; then
  if grep -q "$LOG_PATH\|/var/log/mysql/audit.log" /var/ossec/etc/ossec.conf; then
    check "ossec.conf contém referência ao audit.log" "ok" ""
  else
    check "ossec.conf contém referência ao audit.log" "fail" \
      "Adicionar bloco <localfile> ao /var/ossec/etc/ossec.conf"
  fi

  if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    check "wazuh-agent em execução" "ok" ""
  else
    check "wazuh-agent em execução" "fail" "systemctl start wazuh-agent"
  fi
else
  warn "Wazuh Agent" "Não encontrado em /var/ossec — instalar primeiro"
fi

# ─── 8. Logrotate configurado ───────────────────────────────
echo "8. Logrotate"
if [ -f "/etc/logrotate.d/mysql-audit" ]; then
  check "/etc/logrotate.d/mysql-audit existe" "ok" ""
  if logrotate -d /etc/logrotate.d/mysql-audit > /dev/null 2>&1; then
    check "Configuração logrotate válida" "ok" ""
  else
    check "Configuração logrotate válida" "fail" \
      "Verificar: logrotate -d /etc/logrotate.d/mysql-audit"
  fi
else
  warn "logrotate não configurado" \
    "Copiar: cp mysql/config/logrotate.conf /etc/logrotate.d/mysql-audit"
fi

# ─── Resumo ──────────────────────────────────────────────────
echo ""
echo "=== Resumo ==="
echo -e "  ${GREEN}Passed: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
  echo -e "  ${RED}Failed: $FAIL${NC}"
  echo ""
  echo "Resolver os itens FAIL antes de avançar para a configuração do Wazuh."
  exit 1
else
  echo -e "  Todos os checks passaram. Avançar para o Passo 6 (decoders/regras)."
fi
echo ""

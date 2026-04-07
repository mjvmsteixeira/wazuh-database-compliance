#!/bin/bash
# ============================================================
# oracle-audit-forwarder.sh
# Extrai eventos do Unified Audit Trail e FGA para JSON
# compatível com o Wazuh json_decoder.
#
# Mecanismo de watermark: garante entrega at-least-once —
# cada execução processa apenas eventos novos desde o último run.
#
# Uso: executar como utilizador 'oracle' via cron
#   * * * * * /etc/oracle/oracle-audit-forwarder.sh
#
# Pré-requisitos:
#   - sqlplus disponível em $PATH ou $ORACLE_HOME/bin
#   - Utilizador wazuh_audit com SELECT em UNIFIED_AUDIT_TRAIL
#   - Ficheiro /etc/oracle/audit_pwd com a password (chmod 400)
# ============================================================

set -euo pipefail

# ─── Configuração ────────────────────────────────────────────
# [AJUSTAR] conforme o ambiente Oracle
ORACLE_HOME="${ORACLE_HOME:-/u01/app/oracle/product/19.0.0/dbhome_1}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_USER="wazuh_audit"
ORACLE_PWD_FILE="/etc/oracle/audit_pwd"

# Diretórios de output
LOG_DIR="/var/log/oracle/audit"
LOG_OUTPUT="${LOG_DIR}/wazuh_oracle_audit.log"
WATERMARK_FILE="${LOG_DIR}/watermark.txt"
LOCK_FILE="${LOG_DIR}/forwarder.lock"

# Número máximo de eventos por execução (protege contra backlog excessivo)
BATCH_SIZE=1000

# ─── Validações iniciais ─────────────────────────────────────
export ORACLE_HOME ORACLE_SID
export PATH="$ORACLE_HOME/bin:$PATH"
export NLS_DATE_FORMAT="YYYY-MM-DD HH24:MI:SS"

if [ ! -f "$ORACLE_PWD_FILE" ]; then
  echo "$(date -u +%FT%TZ) [ERROR] Ficheiro de password não encontrado: $ORACLE_PWD_FILE" >&2
  exit 1
fi

if ! command -v sqlplus &>/dev/null; then
  echo "$(date -u +%FT%TZ) [ERROR] sqlplus não encontrado em PATH" >&2
  exit 1
fi

# ─── Lock: evitar execuções sobrepostas ──────────────────────
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date -u +%FT%TZ) [WARN] Execução anterior ainda em curso. A ignorar." >&2
  exit 0
fi

# ─── Watermark: ler timestamp da última execução ─────────────
if [ -f "$WATERMARK_FILE" ] && [ -s "$WATERMARK_FILE" ]; then
  LAST_TS=$(cat "$WATERMARK_FILE")
else
  # Primeira execução: processar últimas 24 horas
  LAST_TS=$(date -u -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
            date -u -v-24H '+%Y-%m-%d %H:%M:%S')
  echo "$LAST_TS" > "$WATERMARK_FILE"
fi

ORACLE_PWD=$(cat "$ORACLE_PWD_FILE")

# ─── Query principal: Unified Audit Trail ────────────────────
# Converte cada evento para uma linha JSON compatível com Wazuh.
# REPLACE nas strings: garante que aspas duplas não quebram o JSON.
# FETCH FIRST ... ROWS ONLY: limita o batch para evitar sobrecarga.
sqlplus -S "${ORACLE_USER}/${ORACLE_PWD}@${ORACLE_SID}" << EOF >> "$LOG_OUTPUT" 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF TRIMSPOOL ON
SET LINESIZE 32767 LONG 4000 LONGCHUNKSIZE 4000

-- Desativar substituição de variáveis (evitar conflito com & em SQL_TEXT)
SET DEFINE OFF

SELECT
  '{"ts":"'       || TO_CHAR(EVENT_TIMESTAMP,'YYYY-MM-DD"T"HH24:MI:SS"Z"') ||
  '","source":"unified_audit"' ||
  ',"audit_user":"'     || REPLACE(NVL(DBUSERNAME,'N/A'),'"','\"')     ||
  '","audit_action":"'  || REPLACE(NVL(ACTION_NAME,'N/A'),'"','\"')    ||
  '","schema":"'  || REPLACE(NVL(OBJECT_SCHEMA,'N/A'),'"','\"')  ||
  '","object":"'  || REPLACE(NVL(OBJECT_NAME,'N/A'),'"','\"')    ||
  '","sql":"'     || REPLACE(REPLACE(SUBSTR(NVL(SQL_TEXT,''),1,500),'"','\"'),CHR(10),' ') ||
  '","client":"'  || REPLACE(NVL(CLIENT_PROGRAM_NAME,'N/A'),'"','\"') ||
  '","host":"'    || REPLACE(NVL(USERHOST,'N/A'),'"','\"')        ||
  '","auth_type":"' || REPLACE(NVL(AUTHENTICATION_TYPE,'N/A'),'"','\"') ||
  '","return_code":' || NVL(RETURN_CODE,0) ||
  ',"session_id":' || NVL(SESSIONID,0) ||
  '}'
FROM UNIFIED_AUDIT_TRAIL
WHERE EVENT_TIMESTAMP > TO_TIMESTAMP('$LAST_TS','YYYY-MM-DD HH24:MI:SS')
ORDER BY EVENT_TIMESTAMP ASC
FETCH FIRST $BATCH_SIZE ROWS ONLY;

EXIT;
EOF

# ─── Query secundária: FGA Audit Trail ───────────────────────
sqlplus -S "${ORACLE_USER}/${ORACLE_PWD}@${ORACLE_SID}" << EOF >> "$LOG_OUTPUT" 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF TRIMSPOOL ON
SET LINESIZE 32767 LONG 4000 LONGCHUNKSIZE 4000
SET DEFINE OFF

SELECT
  '{"ts":"'         || TO_CHAR(TIMESTAMP,'YYYY-MM-DD"T"HH24:MI:SS"Z"') ||
  '","source":"fga_audit"' ||
  ',"audit_user":"'       || REPLACE(NVL(DB_USER,'N/A'),'"','\"')        ||
  '","schema":"'    || REPLACE(NVL(OBJECT_SCHEMA,'N/A'),'"','\"')  ||
  '","object":"'    || REPLACE(NVL(OBJECT_NAME,'N/A'),'"','\"')    ||
  '","policy":"'    || REPLACE(NVL(POLICY_NAME,'N/A'),'"','\"')    ||
  '","sql":"'       || REPLACE(REPLACE(SUBSTR(NVL(SQL_TEXT,''),1,500),'"','\"'),CHR(10),' ') ||
  '","return_code":' || NVL(STATEMENT_TYPE,0) ||
  '}'
FROM DBA_FGA_AUDIT_TRAIL
WHERE TIMESTAMP > TO_TIMESTAMP('$LAST_TS','YYYY-MM-DD HH24:MI:SS')
ORDER BY TIMESTAMP ASC
FETCH FIRST $BATCH_SIZE ROWS ONLY;

EXIT;
EOF

# ─── Atualizar watermark ──────────────────────────────────────
# Obtém o timestamp máximo dos eventos processados.
# Se não houve eventos novos, o watermark mantém-se.
NEW_TS=$(sqlplus -S "${ORACLE_USER}/${ORACLE_PWD}@${ORACLE_SID}" << EOF 2>/dev/null
SET PAGESIZE 0 FEEDBACK OFF HEADING OFF TRIMSPOOL ON
SET DEFINE OFF
SELECT NVL(
  TO_CHAR(MAX(EVENT_TIMESTAMP),'YYYY-MM-DD HH24:MI:SS'),
  '$LAST_TS'
)
FROM UNIFIED_AUDIT_TRAIL
WHERE EVENT_TIMESTAMP > TO_TIMESTAMP('$LAST_TS','YYYY-MM-DD HH24:MI:SS');
EXIT;
EOF
)

# Limpar espaços e newlines do output do sqlplus
NEW_TS=$(echo "$NEW_TS" | tr -d '\n\r' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')

if [ -n "$NEW_TS" ] && [ "$NEW_TS" != "$LAST_TS" ]; then
  echo "$NEW_TS" > "$WATERMARK_FILE"
  echo "$(date -u +%FT%TZ) [INFO] Watermark atualizado: $LAST_TS → $NEW_TS"
else
  echo "$(date -u +%FT%TZ) [INFO] Sem eventos novos desde $LAST_TS"
fi

# Lock é libertado automaticamente ao terminar o script (flock -n 9)

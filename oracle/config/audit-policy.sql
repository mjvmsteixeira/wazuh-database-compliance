-- ============================================================
-- Oracle Unified Auditing — Políticas para Wazuh DAM
-- Executar como SYSDBA ou utilizador com AUDIT SYSTEM privilege
-- Uso: sqlplus / as sysdba @audit-policy.sql
-- ============================================================

-- ─── Pré-verificação: confirmar modo Unified Auditing ────────
PROMPT Verificando modo de auditoria...
SELECT PARAMETER, VALUE FROM V$OPTION
WHERE PARAMETER IN ('Unified Auditing', 'Traditional Auditing');
-- Se VALUE = FALSE para Unified Auditing, ver README.md Passo 1

-- ─── Limpar políticas anteriores (se existirem) ──────────────
-- Ignorar erros ORA-46358 (política não existe)
WHENEVER SQLERROR CONTINUE;
NOAUDIT POLICY wazuh_sessions;
NOAUDIT POLICY wazuh_ddl;
NOAUDIT POLICY wazuh_privileges;
NOAUDIT POLICY wazuh_privileged_users;
NOAUDIT POLICY wazuh_network;

DROP AUDIT POLICY wazuh_sessions;
DROP AUDIT POLICY wazuh_ddl;
DROP AUDIT POLICY wazuh_privileges;
DROP AUDIT POLICY wazuh_privileged_users;
DROP AUDIT POLICY wazuh_network;
WHENEVER SQLERROR EXIT SQL.SQLCODE;

-- ─── Política 1: Sessões ─────────────────────────────────────
-- PCI-DSS 10.2.1: log de acessos individuais a componentes do sistema
-- RGPD Art. 32.º: medidas técnicas de segurança
-- Excluir SYS (coberto pela política 4) para evitar duplicados
CREATE AUDIT POLICY wazuh_sessions
  ACTIONS LOGON, LOGOFF
  WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') NOT IN (''SYS'', ''SYSMAN'', ''DBSNMP'')'
  EVALUATE PER SESSION;

AUDIT POLICY wazuh_sessions;

-- ─── Política 2: DDL — Alterações de schema ─────────────────
-- PCI-DSS 10.2.5, ISO 27001:2022 A.8.15
CREATE AUDIT POLICY wazuh_ddl
  ACTIONS
    CREATE TABLE,   ALTER TABLE,    DROP TABLE,
    TRUNCATE TABLE,
    CREATE INDEX,   DROP INDEX,
    CREATE VIEW,    DROP VIEW,
    CREATE SEQUENCE, DROP SEQUENCE,
    CREATE PROCEDURE, ALTER PROCEDURE, DROP PROCEDURE,
    CREATE FUNCTION,  ALTER FUNCTION,  DROP FUNCTION,
    CREATE TRIGGER,   ALTER TRIGGER,   DROP TRIGGER,
    CREATE SYNONYM,   DROP SYNONYM,
    CREATE DATABASE LINK, DROP DATABASE LINK;

AUDIT POLICY wazuh_ddl;

-- ─── Política 3: Gestão de identidades e privilégios ─────────
-- PCI-DSS 10.2.5, PCI-DSS 7.1, SOX 404
CREATE AUDIT POLICY wazuh_privileges
  ACTIONS
    CREATE USER, ALTER USER, DROP USER,
    GRANT,        REVOKE,
    CREATE ROLE,  ALTER ROLE,  DROP ROLE,
    SET ROLE,
    CREATE PROFILE, ALTER PROFILE, DROP PROFILE;

AUDIT POLICY wazuh_privileges;

-- ─── Política 4: Contas privilegiadas (SYS, SYSTEM) ──────────
-- PCI-DSS 10.2.2: log de ações com privilégios root/administrativos
-- EVALUATE PER SESSION: uma entrada por sessão (reduz volume)
CREATE AUDIT POLICY wazuh_privileged_users
  ACTIONS ALL
  BY SYS, SYSTEM
  EVALUATE PER SESSION;

AUDIT POLICY wazuh_privileged_users;

-- ─── Política 5: Acessos de rede suspeitos ───────────────────
-- NIS2 Art. 21.º — monitorizar tentativas de acesso de IPs não autorizados
-- Registar falhas de autenticação independentemente do utilizador
CREATE AUDIT POLICY wazuh_auth_failures
  ACTIONS LOGON
  WHEN '1=1'
  EVALUATE PER INSTANCE;

-- Auditar apenas falhas (FAILURE), não sucessos (já cobertos por wazuh_sessions)
AUDIT POLICY wazuh_auth_failures WHENEVER NOT SUCCESSFUL;

-- ─── Verificação final ───────────────────────────────────────
PROMPT
PROMPT === Políticas de auditoria ativas ===
SELECT POLICY_NAME, ENABLED_OPT, USER_NAME,
       DECODE(SUCCESS,'YES','Sim','Não') AS SUCESSO,
       DECODE(FAILURE,'YES','Sim','Não') AS FALHA
FROM AUDIT_UNIFIED_ENABLED_POLICIES
WHERE POLICY_NAME LIKE 'WAZUH_%'
ORDER BY POLICY_NAME;

-- ─── Configurar retenção do Audit Trail ─────────────────────
-- PCI-DSS 10.7: mínimo 12 meses, 3 meses em acesso imediato
-- O audit trail Oracle por defeito não tem limpeza automática
-- Configurar via DBMS_AUDIT_MGMT

BEGIN
  -- Inicializar gestão do audit trail (necessário antes de configurar retenção)
  DBMS_AUDIT_MGMT.INIT_CLEANUP(
    audit_trail_type          => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
    default_cleanup_interval  => 12   -- horas entre limpezas automáticas
  );
END;
/

BEGIN
  -- Definir retenção mínima de 365 dias (PCI-DSS 10.7)
  DBMS_AUDIT_MGMT.SET_AUDIT_TRAIL_PROPERTY(
    audit_trail_type           => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
    audit_trail_property       => DBMS_AUDIT_MGMT.OS_FILE_MAX_AGING_DAYS,
    audit_trail_property_value => 365
  );
END;
/

PROMPT Configuração concluída. Verificar com run-logtest.sh após instalar decoders.
EXIT;

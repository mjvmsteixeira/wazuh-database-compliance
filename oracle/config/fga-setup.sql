-- ============================================================
-- Oracle Fine-Grained Auditing (FGA) — Dados PII
-- Executar como SYSDBA
-- Uso: sqlplus / as sysdba @fga-setup.sql
-- ============================================================
-- O DBMS_FGA permite auditar acessos a linhas/colunas específicas.
-- Essencial para RGPD Art. 32.º quando existem dados pessoais.
-- Diferença do UAT: FGA regista a query exata + valores de bind.
-- ============================================================

-- [AJUSTAR] — definir o schema da aplicação
DEFINE APP_SCHEMA = 'APP_SCHEMA'

-- ─── Limpar políticas FGA anteriores ────────────────────────
WHENEVER SQLERROR CONTINUE;
BEGIN DBMS_FGA.DROP_POLICY('&APP_SCHEMA', 'CLIENTES',     'AUDIT_CLIENTES_PII');   END; /
BEGIN DBMS_FGA.DROP_POLICY('&APP_SCHEMA', 'PAGAMENTOS',   'AUDIT_PAGAMENTOS_PII'); END; /
BEGIN DBMS_FGA.DROP_POLICY('&APP_SCHEMA', 'DADOS_PESSOAIS','AUDIT_DADOS_PII');     END; /
WHENEVER SQLERROR EXIT SQL.SQLCODE;

-- ─── Política FGA 1: Tabela CLIENTES ─────────────────────────
-- Auditar acesso a colunas com dados de identificação pessoal
-- audit_condition: apenas quando NIF ou IBAN não é nulo (dados reais)
-- audit_column: colunas específicas que ativam o trigger de auditoria
BEGIN
  DBMS_FGA.ADD_POLICY(
    object_schema    => '&APP_SCHEMA',
    object_name      => 'CLIENTES',
    policy_name      => 'AUDIT_CLIENTES_PII',
    -- Condição: auditar apenas quando a linha tem dados pessoais reais
    audit_condition  => 'NIF IS NOT NULL OR IBAN IS NOT NULL',
    -- Colunas que ativam auditoria quando acedidas na projeção SELECT
    audit_column     => 'NIF, IBAN, DATA_NASCIMENTO, MORADA, TELEFONE, EMAIL',
    -- audit_column_opts: ANY = qualquer uma das colunas; ALL = todas (AND lógico)
    audit_column_opts => DBMS_FGA.ANY_COLUMNS,
    handler_module   => NULL,
    enable           => TRUE,
    -- Auditar SELECT, INSERT, UPDATE, DELETE
    statement_types  => 'SELECT, INSERT, UPDATE, DELETE'
  );
END;
/

-- ─── Política FGA 2: Tabela PAGAMENTOS ───────────────────────
BEGIN
  DBMS_FGA.ADD_POLICY(
    object_schema    => '&APP_SCHEMA',
    object_name      => 'PAGAMENTOS',
    policy_name      => 'AUDIT_PAGAMENTOS_PII',
    audit_condition  => '1=1',
    audit_column     => 'IBAN_DESTINO, IBAN_ORIGEM, MONTANTE, REFERENCIA',
    audit_column_opts => DBMS_FGA.ANY_COLUMNS,
    handler_module   => NULL,
    enable           => TRUE,
    statement_types  => 'SELECT, INSERT, UPDATE, DELETE'
  );
END;
/

-- ─── Política FGA 3: Tabela DADOS_PESSOAIS (se existir) ──────
BEGIN
  DBMS_FGA.ADD_POLICY(
    object_schema    => '&APP_SCHEMA',
    object_name      => 'DADOS_PESSOAIS',
    policy_name      => 'AUDIT_DADOS_PII',
    audit_condition  => '1=1',
    audit_column     => 'NIF, NOME, MORADA, DATA_NASCIMENTO, ESTADO_CIVIL',
    audit_column_opts => DBMS_FGA.ANY_COLUMNS,
    handler_module   => NULL,
    enable           => TRUE,
    statement_types  => 'SELECT, INSERT, UPDATE, DELETE'
  );
END;
/

-- ─── Verificar políticas FGA ─────────────────────────────────
PROMPT
PROMPT === Políticas FGA ativas ===
SELECT OBJECT_SCHEMA, OBJECT_NAME, POLICY_NAME, ENABLED,
       STATEMENT_TYPES, AUDIT_CONDITION, AUDIT_COLUMN
FROM DBA_AUDIT_POLICIES
WHERE OBJECT_SCHEMA = '&APP_SCHEMA'
ORDER BY OBJECT_NAME;

-- ─── Teste: ver eventos FGA recentes ────────────────────────
PROMPT
PROMPT === Últimos eventos FGA (deve estar vazio em instalação nova) ===
SELECT TO_CHAR(TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS') AS TS,
       DB_USER, OBJECT_SCHEMA, OBJECT_NAME, POLICY_NAME,
       SUBSTR(SQL_TEXT, 1, 100) AS SQL_PREVIEW
FROM DBA_FGA_AUDIT_TRAIL
ORDER BY TIMESTAMP DESC
FETCH FIRST 10 ROWS ONLY;

PROMPT
PROMPT FGA configurado. Gerar acessos de teste e verificar DBA_FGA_AUDIT_TRAIL.
EXIT;

-- ============================================================
-- pgAudit Setup — Auditoria Object-Level para Dados PII
-- Executar como superuser (postgres)
-- Uso: psql -U postgres -f pgaudit-setup.sql
-- ============================================================

-- ─── 1. Criar a extensão pgAudit ────────────────────────────
-- Necessário apenas uma vez por base de dados
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Confirmar instalação
SELECT * FROM pg_extension WHERE extname = 'pgaudit';
-- Esperado: uma linha com extname='pgaudit'

-- ─── 2. Role dedicada para auditoria PII ─────────────────────
-- Esta role não é usada para login — funciona como marcador de política
-- O pgAudit audita qualquer objeto ao qual esta role tem acesso
DROP ROLE IF EXISTS auditoria_pii;
CREATE ROLE auditoria_pii NOLOGIN;

-- ─── 3. Tabelas com dados pessoais (PII) ─────────────────────
-- [AJUSTAR] — substituir pela lista real de tabelas com dados sensíveis
-- Critério: tabelas com NIF, IBAN, data de nascimento, morada, email, etc.

-- Atribuir permissões de leitura e escrita à role de auditoria
-- O pgAudit registará qualquer acesso a estes objetos
GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE
    public.clientes,
    public.pagamentos,
    public.dados_pessoais,
    public.contratos,
    public.enderecos
  TO auditoria_pii;

-- Ativar auditoria específica para esta role
-- 'read, write' = SELECT, INSERT, UPDATE, DELETE, COPY
ALTER ROLE auditoria_pii SET pgaudit.log = 'read, write';

-- ─── 4. Row-Level Security (RLS) para isolamento ─────────────
-- Complementa o logging — impede acessos não autorizados mesmo que o
-- atacante tenha credenciais de utilizador com permissões diretas

-- [AJUSTAR] — ativar RLS nas tabelas mais sensíveis
ALTER TABLE public.dados_pessoais ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dados_pessoais FORCE ROW LEVEL SECURITY;

-- Política de isolamento por utilizador
-- [AJUSTAR] — adaptar a coluna de owner conforme o schema
CREATE POLICY isolamento_por_utilizador
  ON public.dados_pessoais
  USING (criado_por = current_user);

-- Política especial para DBA (acesso total)
-- [AJUSTAR] — substituir 'dba_role' pela role de DBA real
CREATE POLICY acesso_dba
  ON public.dados_pessoais
  TO dba_role
  USING (true);

-- ─── 5. Verificação final ────────────────────────────────────

-- Confirmar configuração da role de auditoria
SELECT rolname, rolconfig
FROM pg_roles
WHERE rolname = 'auditoria_pii';
-- Esperado: rolconfig = {pgaudit.log=read, write}

-- Confirmar permissões nas tabelas PII
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'auditoria_pii'
ORDER BY table_name, privilege_type;

-- Confirmar RLS ativo
SELECT tablename, rowsecurity, forcerowsecurity
FROM pg_tables
WHERE tablename IN ('dados_pessoais', 'clientes', 'pagamentos')
ORDER BY tablename;

-- ─── 6. Teste de auditoria ───────────────────────────────────
-- Executar como utilizador normal (não superuser) e verificar logs

-- Como superuser: criar utilizador de teste
CREATE USER teste_pii_user WITH PASSWORD 'teste_temporario';
GRANT auditoria_pii TO teste_pii_user;

-- Mudar para utilizador de teste e executar query
-- \c prod_db teste_pii_user
-- SELECT * FROM clientes LIMIT 1;

-- Verificar no syslog:
-- grep "AUDIT:" /var/log/postgresql/audit.log | grep "clientes" | tail -5

-- Limpar utilizador de teste após verificação
-- DROP USER teste_pii_user;

-- ============================================================
-- SQL Server — Auditoria DML para tabelas PII específicas
-- Executar APÓS deploy-audit.sql
-- Executar como: sysadmin
--
-- Este script adiciona auditoria SELECT/INSERT/UPDATE/DELETE
-- APENAS em tabelas com dados pessoais (PII).
-- Usar este script em vez de auditar ALL no schema inteiro.
--
-- RGPD Art. 32: rastreabilidade de acesso a dados pessoais
-- PCI-DSS 10.2.1: log de acessos individuais a dados sensíveis
-- ============================================================

-- [AJUSTAR] — preencher com as tabelas PII reais de cada BD
-- Exemplo para a BD SAGA:

USE [SAGA];
GO

-- Remover spec PII anterior se existir
IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'WazuhPIISpec')
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION [WazuhPIISpec] WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION [WazuhPIISpec];
END
GO

-- Auditar acesso a tabelas com dados pessoais
-- [AJUSTAR] as tabelas e schemas conforme a aplicação
CREATE DATABASE AUDIT SPECIFICATION [WazuhPIISpec]
FOR SERVER AUDIT [WazuhAudit]
    -- Exemplo: tabelas com NIF, IBAN, dados pessoais
    -- Descomentar e ajustar conforme o schema real:
    -- ADD (SELECT ON OBJECT::[dbo].[Clientes] BY [public]),
    -- ADD (UPDATE ON OBJECT::[dbo].[Clientes] BY [public]),
    -- ADD (DELETE ON OBJECT::[dbo].[Clientes] BY [public]),
    -- ADD (SELECT ON OBJECT::[dbo].[Pagamentos] BY [public]),
    -- ADD (SELECT ON OBJECT::[dbo].[DadosPessoais] BY [public]),

    -- Placeholder — remover após ajustar:
    ADD (SELECT ON SCHEMA::[dbo] BY [public])
WITH (STATE = OFF);  -- Iniciar DESACTIVADO até ajustar as tabelas
GO

-- ============================================================
-- GUIA: Como descobrir tabelas com dados PII
-- ============================================================
-- Procurar colunas com nomes sugestivos de PII:
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    c.COLUMN_NAME,
    c.DATA_TYPE
FROM INFORMATION_SCHEMA.COLUMNS c
JOIN INFORMATION_SCHEMA.TABLES t
    ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
    AND c.TABLE_NAME = t.TABLE_NAME
WHERE t.TABLE_TYPE = 'BASE TABLE'
  AND (
    c.COLUMN_NAME LIKE '%nif%'
    OR c.COLUMN_NAME LIKE '%iban%'
    OR c.COLUMN_NAME LIKE '%cpf%'
    OR c.COLUMN_NAME LIKE '%ssn%'
    OR c.COLUMN_NAME LIKE '%passport%'
    OR c.COLUMN_NAME LIKE '%birth%'
    OR c.COLUMN_NAME LIKE '%nascimento%'
    OR c.COLUMN_NAME LIKE '%morada%'
    OR c.COLUMN_NAME LIKE '%address%'
    OR c.COLUMN_NAME LIKE '%phone%'
    OR c.COLUMN_NAME LIKE '%telefone%'
    OR c.COLUMN_NAME LIKE '%email%'
    OR c.COLUMN_NAME LIKE '%salary%'
    OR c.COLUMN_NAME LIKE '%salario%'
    OR c.COLUMN_NAME LIKE '%password%'
    OR c.COLUMN_NAME LIKE '%credit_card%'
    OR c.COLUMN_NAME LIKE '%cartao%'
  )
ORDER BY t.TABLE_NAME, c.COLUMN_NAME;
GO

-- Após identificar as tabelas, substituir o placeholder acima
-- e activar:
-- ALTER DATABASE AUDIT SPECIFICATION [WazuhPIISpec] WITH (STATE = ON);

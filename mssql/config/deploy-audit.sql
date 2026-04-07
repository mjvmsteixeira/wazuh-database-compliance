-- ============================================================
-- SQL Server Audit — Deploy automático para Wazuh DAM
-- Descobre TODAS as bases de dados de utilizador e configura
-- auditoria com controlo de volume.
--
-- Executar como: sysadmin (sa ou equivalente)
-- Modo: sqlcmd ou SSMS
-- ============================================================

-- ─── 1. Diretório de output ─────────────────────────────────
-- NOTA: O diretório C:\Logs\MSSQL\Audit deve existir antes
-- de executar este script. Criar com:
--   New-Item -ItemType Directory -Force -Path "C:\Logs\MSSQL\Audit"
--   icacls "C:\Logs\MSSQL" /grant "NT Service\MSSQLSERVER:(OI)(CI)F"

-- ─── 2. Limpar audit anterior (se existir) ──────────────────
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = 'WazuhServerSpec')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION [WazuhServerSpec] WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION [WazuhServerSpec];
END
GO

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'WazuhAudit')
BEGIN
    ALTER SERVER AUDIT [WazuhAudit] WITH (STATE = OFF);
    DROP SERVER AUDIT [WazuhAudit];
END
GO

-- ─── 3. Criar Server Audit ──────────────────────────────────
CREATE SERVER AUDIT [WazuhAudit]
TO FILE (
    FILEPATH = N'C:\Logs\MSSQL\Audit',
    -- Controlo de volume:
    MAXSIZE = 50 MB,              -- ficheiro menor = menos I/O
    MAX_ROLLOVER_FILES = 10,      -- máximo 500 MB em disco
    RESERVE_DISK_SPACE = OFF
)
WITH (
    QUEUE_DELAY = 1000,           -- flush a cada 1s (equilíbrio latência/performance)
    ON_FAILURE = CONTINUE         -- NÃO parar o SQL se o audit falhar
);
GO

ALTER SERVER AUDIT [WazuhAudit] WITH (STATE = ON);
GO

-- ─── 4. Server Audit Specification ──────────────────────────
-- Apenas eventos CRÍTICOS a nível de servidor
-- NÃO inclui SUCCESSFUL_LOGIN_GROUP (volume alto em produção)
-- Inclui FAILED_LOGIN_GROUP (segurança, baixo volume)
CREATE SERVER AUDIT SPECIFICATION [WazuhServerSpec]
FOR SERVER AUDIT [WazuhAudit]
    ADD (FAILED_LOGIN_GROUP),                -- PCI-DSS 10.2.4 (tentativas falhadas)
    ADD (LOGIN_CHANGE_PASSWORD_GROUP),       -- RGPD Art. 32 (alteração credenciais)
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),   -- PCI-DSS 7.1 (alteração privilégios)
    ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP), -- PCI-DSS 7.1
    ADD (SERVER_PERMISSION_CHANGE_GROUP),    -- SOX 404
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),  -- SOX 404
    ADD (SERVER_PRINCIPAL_CHANGE_GROUP),     -- Gestão de utilizadores
    ADD (AUDIT_CHANGE_GROUP)                 -- Alterações ao próprio audit
    -- REMOVIDOS (alto volume):
    -- SUCCESSFUL_LOGIN_GROUP  → milhares/dia em produção
    -- BACKUP_RESTORE_GROUP    → incluir apenas se necessário
    -- SERVER_STATE_CHANGE_GROUP → raro, baixo valor
WITH (STATE = ON);
GO

-- ─── 5. Database Audit Specifications — AUTO-DESCOBERTA ─────
-- Itera sobre TODAS as bases de dados de utilizador
-- Exclui: master, model, msdb, tempdb, ReportServer*
-- Audita APENAS DDL e alterações de permissões (NÃO DML)
-- DML (SELECT/INSERT/UPDATE/DELETE) gera volume MUITO alto
-- e deve ser activado apenas em tabelas PII específicas

DECLARE @dbname NVARCHAR(256)
DECLARE @sql NVARCHAR(MAX)

DECLARE db_cursor CURSOR FOR
    SELECT name FROM sys.databases
    WHERE state_desc = 'ONLINE'
      AND database_id > 4              -- exclui system DBs
      AND name NOT LIKE 'ReportServer%'
      AND name NOT LIKE 'tempdb%'
    ORDER BY name

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @dbname

WHILE @@FETCH_STATUS = 0
BEGIN
    PRINT '--- Configurando auditoria para: ' + @dbname + ' ---'

    -- Remover spec anterior se existir
    SET @sql = N'
    USE [' + @dbname + N'];
    IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = ''WazuhDatabaseSpec'')
    BEGIN
        ALTER DATABASE AUDIT SPECIFICATION [WazuhDatabaseSpec] WITH (STATE = OFF);
        DROP DATABASE AUDIT SPECIFICATION [WazuhDatabaseSpec];
    END

    CREATE DATABASE AUDIT SPECIFICATION [WazuhDatabaseSpec]
    FOR SERVER AUDIT [WazuhAudit]
        -- DDL: CREATE/ALTER/DROP de objectos (baixo volume)
        ADD (SCHEMA_OBJECT_CHANGE_GROUP),
        ADD (DATABASE_OBJECT_CHANGE_GROUP),
        -- Execução de stored procedures (médio volume — ajustar se necessário)
        ADD (EXECUTE ON SCHEMA::[dbo] BY [public])
        -- NÃO incluir SELECT/INSERT/UPDATE/DELETE por defeito (alto volume)
        -- Para tabelas PII específicas, criar spec separada (ver abaixo)
    WITH (STATE = ON);
    '

    BEGIN TRY
        EXEC sp_executesql @sql
        PRINT '  OK: ' + @dbname
    END TRY
    BEGIN CATCH
        PRINT '  ERRO em ' + @dbname + ': ' + ERROR_MESSAGE()
    END CATCH

    FETCH NEXT FROM db_cursor INTO @dbname
END

CLOSE db_cursor
DEALLOCATE db_cursor
GO

-- ─── 6. Verificação ─────────────────────────────────────────
PRINT ''
PRINT '=== Server Audit ==='
SELECT name, type_desc, is_state_enabled,
    CASE WHEN is_state_enabled = 1 THEN 'ACTIVO' ELSE 'INACTIVO' END AS estado
FROM sys.server_audits;

PRINT ''
PRINT '=== Server Audit Specification ==='
SELECT s.name AS spec_name, s.is_state_enabled,
       d.audit_action_name
FROM sys.server_audit_specifications s
JOIN sys.server_audit_specification_details d
    ON s.server_specification_id = d.server_specification_id
WHERE s.name = 'WazuhServerSpec';

PRINT ''
PRINT '=== Database Audit Specifications (por BD) ==='
DECLARE @dbname2 NVARCHAR(256)
DECLARE @sql2 NVARCHAR(MAX)
DECLARE db_cursor2 CURSOR FOR
    SELECT name FROM sys.databases
    WHERE state_desc = 'ONLINE' AND database_id > 4
      AND name NOT LIKE 'ReportServer%'
    ORDER BY name

OPEN db_cursor2
FETCH NEXT FROM db_cursor2 INTO @dbname2

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql2 = N'
    USE [' + @dbname2 + N'];
    IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = ''WazuhDatabaseSpec'')
    BEGIN
        SELECT DB_NAME() AS [Database],
               das.name AS spec_name,
               das.is_state_enabled,
               dasd.audit_action_name
        FROM sys.database_audit_specifications das
        JOIN sys.database_audit_specification_details dasd
            ON das.database_specification_id = dasd.database_specification_id
        WHERE das.name = ''WazuhDatabaseSpec'';
    END
    '
    BEGIN TRY
        EXEC sp_executesql @sql2
    END TRY
    BEGIN CATCH
    END CATCH

    FETCH NEXT FROM db_cursor2 INTO @dbname2
END

CLOSE db_cursor2
DEALLOCATE db_cursor2
GO

PRINT ''
PRINT '=== Estimativa de volume ==='
PRINT 'FAILED_LOGIN: ~10-100 eventos/dia (depende de ataques)'
PRINT 'PERMISSION_CHANGE: ~1-10 eventos/dia'
PRINT 'DDL (SCHEMA_OBJECT_CHANGE): ~10-50 eventos/dia'
PRINT 'EXECUTE: ~100-1000 eventos/dia (depende de stored procedures)'
PRINT 'Total estimado: ~200-1200 eventos/dia por servidor'
PRINT 'Disco: ~5-20 MB/dia por servidor'
PRINT ''
PRINT 'Para adicionar auditoria DML a tabelas PII específicas,'
PRINT 'usar o script deploy-pii-audit.sql'
GO

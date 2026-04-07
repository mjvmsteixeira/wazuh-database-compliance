-- ============================================================
-- Extended Events — Para SQL Server Express
-- A edição Express não suporta SQL Server Audit
-- Extended Events é a alternativa disponível
-- ============================================================

-- Apagar sessão anterior se existir
IF EXISTS (SELECT 1 FROM sys.server_event_sessions WHERE name = 'WazuhAuditExpress')
    DROP EVENT SESSION [WazuhAuditExpress] ON SERVER;
GO

CREATE EVENT SESSION [WazuhAuditExpress] ON SERVER

-- DDL e comandos destrutivos
ADD EVENT sqlserver.sql_statement_completed(
    ACTION(
        sqlserver.username,
        sqlserver.client_hostname,
        sqlserver.client_app_name,
        sqlserver.database_name
    )
    WHERE sqlserver.sql_text LIKE '%DROP%'
       OR sqlserver.sql_text LIKE '%DELETE%'
       OR sqlserver.sql_text LIKE '%TRUNCATE%'
       OR sqlserver.sql_text LIKE '%ALTER%'
       OR sqlserver.sql_text LIKE '%CREATE%'
       OR sqlserver.sql_text LIKE '%GRANT%'
       OR sqlserver.sql_text LIKE '%REVOKE%'
),

-- Logins (sucesso e falha)
ADD EVENT sqlserver.login(
    ACTION(
        sqlserver.username,
        sqlserver.client_hostname,
        sqlserver.client_app_name
    )
),

-- Logout
ADD EVENT sqlserver.logout(
    ACTION(
        sqlserver.username,
        sqlserver.client_hostname
    )
),

-- Erros de severidade >= 14 (segurança e acima)
ADD EVENT sqlserver.error_reported(
    ACTION(
        sqlserver.username,
        sqlserver.client_hostname,
        sqlserver.database_name
    )
    WHERE severity >= 14
)

-- Target: ficheiro .xel
ADD TARGET package0.event_file(
    SET filename = N'C:\Logs\MSSQL\ExtEvents\wazuh_xevents.xel',
        max_file_size = (100),
        max_rollover_files = (10)
);
GO

-- Iniciar a sessão
ALTER EVENT SESSION [WazuhAuditExpress] ON SERVER STATE = START;
GO

-- Verificação
SELECT name, create_time,
    CASE WHEN is_running = 1 THEN 'EM EXECUCAO' ELSE 'PARADA' END AS estado
FROM sys.dm_xe_sessions
WHERE name = 'WazuhAuditExpress';
GO

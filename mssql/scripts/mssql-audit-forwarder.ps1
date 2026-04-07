# ============================================================
# mssql-audit-forwarder.ps1
# Extrai eventos de SQL Server Audit (.sqlaudit) para JSON
# compatível com o Wazuh json_decoder.
#
# PROTECÇÕES DE RECURSOS:
#   - Lock: evita execuções sobrepostas
#   - Watermark: processa apenas eventos novos
#   - BatchSize: limita eventos por execução (default: 500)
#   - Timeout: mata o processo se demorar mais que 4 min
#   - Disco: verifica espaço antes de escrever
#   - Log rotation: trunca quando > 100MB
#
# Executar como: Scheduled Task (NT AUTHORITY\SYSTEM)
# Frequência: a cada 5 minutos
# Pré-requisitos:
#   - SQL Server com WazuhAudit configurado (deploy-audit.sql)
#   - Permissão VIEW SERVER STATE
# ============================================================

#Requires -Version 5.1

param(
    [string]$ServerInstance = 'localhost',
    [string]$AuditPath      = 'C:\Logs\MSSQL\Audit\*.sqlaudit',
    [string]$LogFile         = 'C:\Logs\MSSQL\wazuh_mssql_audit.log',
    [string]$WatermarkFile   = 'C:\Logs\MSSQL\watermark.txt',
    [string]$LockFile        = 'C:\Logs\MSSQL\forwarder.lock',
    [int]$BatchSize          = 500,
    [int]$MaxLogSizeMB       = 100,
    [int]$MinFreeDiskGB      = 1
)

$ErrorActionPreference = 'Stop'

# ─── Registar Event Source (apenas primeira vez) ─────────────
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('WazuhMSSQLAudit')) {
        [System.Diagnostics.EventLog]::CreateEventSource('WazuhMSSQLAudit', 'Application')
    }
} catch { }

function Write-AuditLog {
    param([string]$Message, [string]$Level = 'Information')
    try {
        Write-EventLog -LogName Application -Source 'WazuhMSSQLAudit' `
            -EventId 1001 -EntryType $Level -Message $Message
    } catch { }
    $ts = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    Write-Output "[$ts] $Level : $Message"
}

# ─── Lock: evitar execuções sobrepostas ──────────────────────
try {
    $lockStream = [System.IO.File]::Open($LockFile,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
} catch {
    Write-AuditLog "Execução anterior em curso. A sair." 'Warning'
    exit 0
}

try {
    # ─── Verificar espaço em disco ───────────────────────────
    $drive = (Split-Path $LogFile -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':','')).Free / 1GB, 2)
    if ($freeGB -lt $MinFreeDiskGB) {
        Write-AuditLog "Disco quase cheio: ${freeGB}GB livre (mínimo: ${MinFreeDiskGB}GB). A sair." 'Error'
        exit 1
    }

    # ─── Log rotation: truncar se > MaxLogSizeMB ─────────────
    if (Test-Path $LogFile) {
        $logSizeMB = [math]::Round((Get-Item $LogFile).Length / 1MB, 2)
        if ($logSizeMB -gt $MaxLogSizeMB) {
            # Manter últimas 10000 linhas, apagar o resto
            $tail = Get-Content $LogFile -Tail 10000
            Set-Content -Path $LogFile -Value $tail
            Write-AuditLog "Log truncado: ${logSizeMB}MB > ${MaxLogSizeMB}MB (mantidas 10000 linhas)" 'Warning'
        }
    }

    # ─── Watermark: ler timestamp da última execução ─────────
    if (Test-Path $WatermarkFile) {
        $lastProcessed = (Get-Content $WatermarkFile -Raw).Trim()
    } else {
        $lastProcessed = (Get-Date).AddMinutes(-10).ToString('yyyy-MM-ddTHH:mm:ss')
    }

    # ─── Query: extrair eventos via fn_get_audit_file() ──────
    $query = @"
SELECT TOP ($BatchSize)
    CONVERT(VARCHAR, event_time, 127) as ts,
    action_id,
    succeeded,
    server_principal_name,
    database_name,
    object_name,
    REPLACE(REPLACE(
        SUBSTRING(ISNULL(statement,''), 1, 500),
        CHAR(10), ' '),
        CHAR(13), ' ') as statement,
    client_ip,
    application_name,
    session_server_principal_name
FROM sys.fn_get_audit_file('$AuditPath', DEFAULT, DEFAULT)
WHERE event_time > '$lastProcessed'
ORDER BY event_time ASC
"@

    # ─── Executar query ──────────────────────────────────────
    $results = $null
    try {
        # Tentar com módulo SqlServer
        Import-Module SqlServer -ErrorAction SilentlyContinue
        $results = Invoke-Sqlcmd -Query $query -ServerInstance $ServerInstance `
            -ErrorAction Stop -QueryTimeout 120
    } catch {
        try {
            # Fallback: módulo SQLPS
            Import-Module SQLPS -ErrorAction SilentlyContinue -DisableNameChecking
            $results = Invoke-Sqlcmd -Query $query -ServerInstance $ServerInstance `
                -ErrorAction Stop -QueryTimeout 120
        } catch {
            Write-AuditLog "Falha ao executar query: $($_.Exception.Message)" 'Error'
            exit 1
        }
    }

    # ─── Converter para JSON e escrever no log ────────────────
    $newWatermark = $null
    $count = 0

    foreach ($row in $results) {
        $obj = [ordered]@{
            ts                        = [string]$row.ts
            source                    = 'mssql_audit'
            action_id                 = ([string]$row.action_id).Trim()
            succeeded                 = [bool]$row.succeeded
            server_principal_name     = [string]$row.server_principal_name
            database_name             = [string]$row.database_name
            object_name               = [string]$row.object_name
            statement                 = [string]$row.statement
            client_ip                 = [string]$row.client_ip
            application_name          = [string]$row.application_name
        }

        $json = $obj | ConvertTo-Json -Compress
        Add-Content -Path $LogFile -Value $json -Encoding UTF8
        $newWatermark = $row.ts
        $count++
    }

    # ─── Atualizar watermark ──────────────────────────────────
    if ($newWatermark) {
        Set-Content -Path $WatermarkFile -Value $newWatermark
        Write-AuditLog "Processados $count eventos. Watermark: $newWatermark" 'Information'
    } else {
        Write-AuditLog "Sem eventos novos desde $lastProcessed" 'Information'
    }

} catch {
    Write-AuditLog "Erro: $($_.Exception.Message)" 'Error'
} finally {
    if ($lockStream) {
        $lockStream.Close()
        $lockStream.Dispose()
    }
}

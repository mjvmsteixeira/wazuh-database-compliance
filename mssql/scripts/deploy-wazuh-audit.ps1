# ============================================================
# deploy-wazuh-audit.ps1
# Script unificado de deploy — executa todos os passos:
#   1. Cria diretórios
#   2. Configura SQL Server Audit (auto-descobre BDs)
#   3. Instala o script de forwarding
#   4. Regista a Scheduled Task
#
# Executar como: Administrador local com acesso sysadmin ao SQL
# Modo: PowerShell (Run as Administrator)
#
# Uso:
#   .\deploy-wazuh-audit.ps1
#   .\deploy-wazuh-audit.ps1 -ServerInstance "SERVIDOR\INSTANCIA"
#   .\deploy-wazuh-audit.ps1 -WhatIf    # dry-run
# ============================================================

#Requires -RunAsAdministrator
#Requires -Version 5.1

param(
    [string]$ServerInstance = 'localhost',
    [switch]$WhatIf,
    [switch]$SkipSQLAudit,
    [switch]$SkipScheduledTask
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Wazuh Database Audit — Deploy ===" -ForegroundColor White
Write-Host "Servidor: $ServerInstance"
Write-Host "Data: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Host ""

# ─── Passo 1: Diretórios ─────────────────────────────────────
Write-Step "1/4" "Criar diretórios"

$dirs = @(
    'C:\Logs\MSSQL\Audit',
    'C:\Logs\MSSQL',
    'C:\Scripts\Wazuh'
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        if (-not $WhatIf) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
        }
        Write-OK "Criado: $dir"
    } else {
        Write-OK "Existe: $dir"
    }
}

# Permissões para o serviço SQL Server
$sqlService = "NT Service\MSSQLSERVER"
# Verificar se é instância nomeada
$instanceName = ($ServerInstance -split '\\')[-1]
if ($instanceName -ne 'localhost' -and $instanceName -ne $env:COMPUTERNAME) {
    $sqlService = "NT Service\MSSQL`$$instanceName"
}

if (-not $WhatIf) {
    try {
        $acl = Get-Acl "C:\Logs\MSSQL"
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sqlService, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl "C:\Logs\MSSQL" $acl
        Write-OK "Permissões: $sqlService → FullControl"
    } catch {
        Write-Warn "Não foi possível definir permissões para '$sqlService': $($_.Exception.Message)"
        Write-Warn "Verificar manualmente: icacls C:\Logs\MSSQL /grant `"$sqlService`":(OI)(CI)F"
    }
}

# ─── Passo 2: SQL Server Audit ────────────────────────────────
if (-not $SkipSQLAudit) {
    Write-Step "2/4" "Configurar SQL Server Audit"

    $scriptPath = Join-Path $PSScriptRoot '..\config\deploy-audit.sql'
    if (-not (Test-Path $scriptPath)) {
        $scriptPath = Join-Path $PSScriptRoot 'deploy-audit.sql'
    }

    if (Test-Path $scriptPath) {
        if (-not $WhatIf) {
            try {
                Import-Module SqlServer -ErrorAction SilentlyContinue
                Invoke-Sqlcmd -InputFile $scriptPath -ServerInstance $ServerInstance `
                    -ErrorAction Stop -QueryTimeout 300 -Verbose
                Write-OK "SQL Audit configurado em todas as BDs de utilizador"
            } catch {
                try {
                    Import-Module SQLPS -ErrorAction SilentlyContinue -DisableNameChecking
                    Invoke-Sqlcmd -InputFile $scriptPath -ServerInstance $ServerInstance `
                        -ErrorAction Stop -QueryTimeout 300
                    Write-OK "SQL Audit configurado (via SQLPS)"
                } catch {
                    Write-Fail "Erro ao configurar SQL Audit: $($_.Exception.Message)"
                    Write-Warn "Executar manualmente: sqlcmd -S $ServerInstance -i `"$scriptPath`""
                }
            }
        } else {
            Write-OK "DRY-RUN: Executaria $scriptPath"
        }
    } else {
        Write-Warn "Script deploy-audit.sql não encontrado em: $scriptPath"
        Write-Warn "Executar manualmente via SSMS"
    }

    # Listar BDs descobertas
    try {
        $dbs = Invoke-Sqlcmd -Query "SELECT name FROM sys.databases WHERE database_id > 4 AND state_desc = 'ONLINE' AND name NOT LIKE 'ReportServer%'" `
            -ServerInstance $ServerInstance -ErrorAction Stop
        Write-Host ""
        Write-Host "  Bases de dados descobertas:" -ForegroundColor White
        foreach ($db in $dbs) {
            Write-Host "    - $($db.name)" -ForegroundColor Gray
        }
    } catch { }
} else {
    Write-Step "2/4" "SQL Server Audit — IGNORADO (SkipSQLAudit)"
}

# ─── Passo 3: Script de forwarding ───────────────────────────
Write-Step "3/4" "Instalar script de forwarding"

$forwarderSource = Join-Path $PSScriptRoot 'mssql-audit-forwarder.ps1'
$forwarderDest = 'C:\Scripts\Wazuh\mssql-audit-forwarder.ps1'

if (Test-Path $forwarderSource) {
    if (-not $WhatIf) {
        Copy-Item $forwarderSource $forwarderDest -Force
    }
    Write-OK "Copiado: $forwarderDest"
} else {
    Write-Warn "Script não encontrado: $forwarderSource"
    Write-Warn "Copiar manualmente para $forwarderDest"
}

# ─── Passo 4: Scheduled Task ─────────────────────────────────
if (-not $SkipScheduledTask) {
    Write-Step "4/4" "Registar Scheduled Task"

    $taskName = "WazuhMSSQLAudit"

    # Remover task anterior
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        if (-not $WhatIf) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        Write-OK "Task anterior removida"
    }

    if (-not $WhatIf) {
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$forwarderDest`" -ServerInstance `"$ServerInstance`""
        $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) `
            -Once -At (Get-Date).Date
        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
            -MultipleInstances IgnoreNew `
            -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

        Register-ScheduledTask -TaskName $taskName `
            -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal | Out-Null

        Write-OK "Scheduled Task '$taskName' registada (cada 5 min, SYSTEM)"
    } else {
        Write-OK "DRY-RUN: Registaria task '$taskName'"
    }
} else {
    Write-Step "4/4" "Scheduled Task — IGNORADO (SkipScheduledTask)"
}

# ─── Resumo ──────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Deploy concluído ===" -ForegroundColor Green
Write-Host ""
Write-Host "Próximos passos:" -ForegroundColor White
Write-Host "  1. Verificar que C:\Logs\MSSQL\wazuh_mssql_audit.log é criado (aguardar 5 min)"
Write-Host "  2. O Wazuh Agent já está configurado via agent.conf do grupo db_mssql"
Write-Host "  3. Para auditar tabelas PII: executar deploy-pii-audit.sql no SSMS"
Write-Host "  4. Verificar alertas no Wazuh Dashboard: rule.id >= 100270"
Write-Host ""

if ($WhatIf) {
    Write-Warn "Executado em modo DRY-RUN — nenhuma alteração foi feita"
}

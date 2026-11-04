# ============================================================
# GERENCIAR OPENSSH SERVER
# Script interativo para instalação ou remoção do OpenSSH Server.
#
# Fluxo:
# 1. Solicita execução como administrador quando necessário.
# 2. Permite escolher entre instalar e remover o OpenSSH Server.
# 3. Configura ou remove o serviço sshd e as regras de firewall pertinentes.
# 4. Valida a operação e exibe o resultado.
# 5. Preserva o OpenSSH Client.
# ============================================================

param(
    [ValidateSet('Instalar', 'Remover')]
    [string]$Acao
)

$ErrorActionPreference = 'Stop'

$serverCapability = 'OpenSSH.Server~~~~0.0.1.0'
$firewallRuleName = 'OpenSSH'
$blockRuleName = 'Local-Block-Inbound-SSH-TCP-22'
$installerRuleNames = @('OpenSSH', 'OpenSSH-Server-In-TCP')

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $PSCommandPath) {
        throw 'Salve o script em um arquivo .ps1 antes de executá-lo como administrador.'
    }

    try {
        $scriptArgument = '"{0}"' -f $PSCommandPath
        $elevatedProcess = Start-Process `
            -FilePath 'powershell.exe' `
            -Verb RunAs `
            -ArgumentList @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', $scriptArgument
            ) `
            -Wait `
            -PassThru

        exit $elevatedProcess.ExitCode
    }
    catch {
        throw "Não foi possível solicitar privilégios de administrador: $($_.Exception.Message)"
    }
}

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Step,
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    Write-Host ''
    Write-Host "[$Step] $Title" -ForegroundColor Cyan
    Write-Host ('-' * 62) -ForegroundColor DarkCyan
}

function Test-RuleAllowsSsh {
    param(
        [Parameter(Mandatory = $true)]
        $Rule
    )

    if ($Rule.Direction -ne 'Inbound' -or $Rule.Action -ne 'Allow') {
        return $false
    }

    $portFilters = @(
        Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $Rule `
            -ErrorAction Stop
    )

    foreach ($filter in $portFilters) {
        $protocol = [string]$filter.Protocol
        if ($protocol -in @('TCP', '6') -and [string]$filter.LocalPort -eq '22') {
            return $true
        }
    }

    return $false
}

function Install-OpenSshServer {
    Write-Section -Step '1/4' -Title 'INSTALAÇÃO'
    Write-Host 'Verificando a capacidade do OpenSSH Server...'

    $capability = Get-WindowsCapability -Online -Name $serverCapability -ErrorAction Stop
    if ($capability.State -ne 'Installed') {
        Write-Host 'OpenSSH Server não está instalado. Iniciando instalação...'
        Add-WindowsCapability -Online -Name $serverCapability -ErrorAction Stop |
            Out-Null
        $capability = Get-WindowsCapability `
            -Online `
            -Name $serverCapability `
            -ErrorAction Stop
    }
    else {
        Write-Host 'OpenSSH Server já está instalado.' -ForegroundColor Green
    }

    if ($capability.State -ne 'Installed') {
        throw "A instalação da capacidade '$serverCapability' não foi concluída."
    }

    Write-Host '[OK] Componente instalado.' -ForegroundColor Green

    Write-Section -Step '2/4' -Title 'SERVIÇO SSHD'
    Write-Host 'Configurando inicialização automática e iniciando o serviço...'
    Set-Service -Name 'sshd' -StartupType Automatic -ErrorAction Stop
    Start-Service -Name 'sshd' -ErrorAction Stop
    Write-Host '[OK] Serviço configurado.' -ForegroundColor Green

    Write-Section -Step '3/4' -Title 'FIREWALL'
    Write-Host 'Procurando uma regra de entrada que permita conexões TCP na porta 22...'

    $namedRules = @(
        Get-NetFirewallRule `
            -Name $firewallRuleName `
            -ErrorAction SilentlyContinue
    )
    $matchingRule = $null

    if ($namedRules.Count -gt 0) {
        foreach ($rule in $namedRules) {
            if (-not (Test-RuleAllowsSsh -Rule $rule)) {
                throw "A regra de firewall '$firewallRuleName' existe, mas não permite conexões de entrada em TCP/22. Revise-a manualmente."
            }
        }

        $matchingRule = $namedRules | Select-Object -First 1
        Write-Host "Regra '$($matchingRule.Name)' encontrada." -ForegroundColor Green
    }
    else {
        $inboundAllowRules = @(
            Get-NetFirewallRule `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction Stop
        )
        $matchingRules = @(
            foreach ($rule in $inboundAllowRules) {
                if (Test-RuleAllowsSsh -Rule $rule) {
                    $rule
                }
            }
        )

        if ($matchingRules.Count -gt 0) {
            $matchingRule = $matchingRules | Select-Object -First 1
            if ($matchingRules.Count -gt 1) {
                Write-Warning (
                    "Foram encontradas $($matchingRules.Count) regras " +
                    "que permitem SSH; uma delas será reutilizada."
                )
            }

            Write-Host "Reutilizando a regra existente '$($matchingRule.Name)'." -ForegroundColor Green
        }
        else {
            Write-Host 'Nenhuma regra equivalente encontrada. Criando regra para TCP/22...'
            $matchingRule = New-NetFirewallRule `
                -Name $firewallRuleName `
                -DisplayName 'OpenSSH Server (sshd)' `
                -Description 'OpenSSH Server: Online' `
                -Enabled True `
                -Direction Inbound `
                -Protocol TCP `
                -Action Allow `
                -LocalPort 22 `
                -ErrorAction Stop
        }
    }

    if ($matchingRule.Enabled -ne 'True') {
        Write-Host 'A regra está desabilitada. Habilitando...'
        Enable-NetFirewallRule -InputObject $matchingRule -ErrorAction Stop |
            Out-Null
    }

    Write-Host "[OK] Regra de firewall ativa: $($matchingRule.Name)." -ForegroundColor Green

    Write-Section -Step '4/4' -Title 'VALIDAÇÃO'
    Write-Host 'Confirmando o serviço e a escuta na porta TCP/22...'
    $service = Get-Service -Name 'sshd' -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw 'O serviço sshd não está em execução.'
    }

    Write-Host 'Verificando se o sshd está escutando na porta TCP/22...'
    $listener = $null

    for ($attempt = 0; $attempt -lt 10 -and -not $listener; $attempt++) {
        $listeners = @(
            Get-NetTCPConnection `
                -State Listen `
                -LocalPort 22 `
                -ErrorAction SilentlyContinue
        )

        foreach ($connection in $listeners) {
            $process = Get-Process `
                -Id $connection.OwningProcess `
                -ErrorAction SilentlyContinue

            if ($process -and $process.ProcessName -ieq 'sshd') {
                $listener = $connection
                break
            }
        }

        if (-not $listener) {
            Start-Sleep -Seconds 1
        }
    }

    if (-not $listener) {
        throw 'O serviço está em execução, mas não foi detectado um processo sshd escutando na porta TCP/22.'
    }

    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host '             CONFIGURAÇÃO CONCLUÍDA' -ForegroundColor Green
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host 'OpenSSH Server: Instalado'
    Write-Host "Serviço sshd:   $($service.Status)"
    Write-Host "Regra ativa:    $($matchingRule.Name)"
    Write-Host "Porta TCP/22:   Escutando... ($($listener.LocalAddress))"
}

function Remove-OpenSshServer {
    Write-Section -Step '1/4' -Title 'REGRAS DE FIREWALL DO OPENSSH'

    foreach ($commandName in @(
        'Get-NetFirewallRule',
        'Remove-NetFirewallRule',
        'Get-WindowsCapability',
        'Remove-WindowsCapability'
    )) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "O comando '$commandName' não está disponível neste Windows."
        }
    }

    $removedInstallerRules = 0
    foreach ($ruleName in $installerRuleNames) {
        $rules = @(
            Get-NetFirewallRule `
                -Name $ruleName `
                -ErrorAction SilentlyContinue
        )

        foreach ($rule in $rules) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removedInstallerRules++
            Write-Host "Regra de firewall removida: $($rule.Name)"
        }
    }

    $previousBlockRules = @(
        Get-NetFirewallRule `
            -Name $blockRuleName `
            -ErrorAction SilentlyContinue
    )

    foreach ($rule in $previousBlockRules) {
        Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
        Write-Host (
            "Regra de bloqueio criada pela versão anterior do reversor " +
            "removida: $($rule.Name)"
        )
    }

    if ($removedInstallerRules -eq 0) {
        Write-Host 'Nenhuma regra com os nomes usados pelo instalador foi encontrada.'
    }
    else {
        Write-Host "Total de regras do instalador removidas: $removedInstallerRules." -ForegroundColor Green
    }

    Write-Host 'Regras com outros nomes foram preservadas; se alguma delas permitir TCP/22, o acesso poderá continuar autorizado pelo firewall.'

    Write-Section -Step '2/4' -Title 'SERVIÇO SSHD'
    $sshdService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($sshdService) {
        if ($sshdService.Status -ne 'Stopped') {
            Stop-Service -Name 'sshd' -Force -ErrorAction Stop
        }

        Set-Service -Name 'sshd' -StartupType Disabled -ErrorAction Stop
        Write-Host 'Serviço sshd parado e desabilitado.' -ForegroundColor Green
    }
    else {
        Write-Host 'Serviço sshd não está instalado.'
    }

    Write-Section -Step '3/4' -Title 'OPENSSH SERVER'
    $capability = Get-WindowsCapability `
        -Online `
        -Name $serverCapability `
        -ErrorAction Stop

    if ($capability.State -eq 'Installed') {
        Write-Host "Desinstalando $serverCapability..."
        Remove-WindowsCapability `
            -Online `
            -Name $serverCapability `
            -ErrorAction Stop |
            Out-Null

        $capability = Get-WindowsCapability `
            -Online `
            -Name $serverCapability `
            -ErrorAction Stop
    }

    if ($capability.State -eq 'Installed') {
        throw "A capacidade '$serverCapability' ainda aparece como instalada após a tentativa de remoção."
    }

    Write-Host "Estado de $serverCapability`: $($capability.State)." -ForegroundColor Green

    Write-Section -Step '4/4' -Title 'VERIFICAÇÃO'
    $sshdService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($sshdService -and $sshdService.Status -ne 'Stopped') {
        throw 'O serviço sshd continua em execução após a remoção.'
    }

    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host '                 PROCESSO CONCLUÍDO' -ForegroundColor Green
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host "Regras nomeadas do instalador removidas: $removedInstallerRules"
    Write-Host 'OpenSSH Server: desinstalado, se estava instalado'
    Write-Host 'OpenSSH Client: preservado'
    Write-Host 'Observação: servidores SSH de terceiros em portas diferentes não são removidos por este script.'
    Write-Host ''
}

Clear-Host
Write-Host ('=' * 62) -ForegroundColor DarkCyan
Write-Host '             GERENCIAR OPENSSH SERVER' -ForegroundColor Cyan
Write-Host ('=' * 62) -ForegroundColor DarkCyan
Write-Host ''
Write-Host '[1] Instalar OpenSSH Server'
Write-Host '[2] Remover OpenSSH Server'
Write-Host ''

if (-not $Acao) {
    $escolha = Read-Host 'Escolha uma opção (1 ou 2)'

    switch ($escolha) {
        '1' { $Acao = 'Instalar' }
        '2' { $Acao = 'Remover' }
        default {
            Write-Host ''
            Write-Host '[ERRO] Opção inválida. Execute novamente e escolha 1 ou 2.' -ForegroundColor Red
            exit 1
        }
    }
}

try {
    switch ($Acao) {
        'Instalar' {
            Write-Host '[INFO] Ação selecionada: instalar OpenSSH Server.' -ForegroundColor Cyan
            Install-OpenSshServer
        }

        'Remover' {
            Write-Host '[INFO] Ação selecionada: remover OpenSSH Server.' -ForegroundColor Cyan
            Remove-OpenSshServer
        }
    }
}
catch {
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Red
    Write-Host "          FALHA AO $($Acao.ToUpperInvariant()) OPENSSH SERVER" -ForegroundColor Red
    Write-Host ('=' * 62) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
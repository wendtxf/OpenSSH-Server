$ErrorActionPreference= 'silentlycontinue'

# Executa como administrador, libera a politica de execu��o de Scripts e permanece no diret�rio atual.
if(-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Unrestricted -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        Exit;
    }
}
Clear-Host

# Instala o servidor OpenSSH.
Write-Output("Realizando a Instala��o do Servidor OpenSSH.")
Write-Output("Aguarde...")
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Inicia o servi�o sshd.
Start-Service sshd

# Seta o servi�o do sshd como inicializa��o autom�tica.
Set-Service -Name sshd -StartupType 'Automatic'

# Verifica se a regra no Firewall j� exite, caso n�o exista ela ser� criada e adicionada ao Firewall.
if(!(Get-NetFirewallRule -Name "OpenSSH" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output("")
    Write-Output("========================================================================================")
    New-NetFirewallRule -Name 'OpenSSH' -DisplayName 'OpenSSH Server (sshd)' -Description 'OpenSSH Server: Online' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    Write-Output("========================================================================================")
    Write-Output("")
    Write-Output("Instala��o Conclu�da!!")
    Write-Output("")
    Pause
}else{
    Clear-Host
    Write-Output("Regra 'OpenSSH' j� presente ao Firewall do Windows.")
    Write-Output("")
    Pause
    Clear-Host
}
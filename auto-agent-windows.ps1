# install-agent.ps1
# PowerShell script to auto install Wazuh agent on Windows Server & Desktop

# Prompt for required values
$AGENT_VERSION = Read-Host "Wazuh Agent version (e.g., 4.12.0-1)"
$MANAGER_IP = Read-Host "Wazuh Manager IP address"
$AGENT_GROUP = Read-Host "Wazuh Agent group (e.g., server, default) [default]"
if ([string]::IsNullOrWhiteSpace($AGENT_GROUP)) {
    $AGENT_GROUP = "default"
}

# Download and install Wazuh agent
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AGENT_VERSION.msi"
$msiPath = "$env:TEMP\wazuh-agent-$AGENT_VERSION.msi"
Write-Host "[+] Downloading Wazuh agent: $msiUrl"
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath

Write-Host "[+] Installing Wazuh agent..."
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msiPath`" /qn WAZUH_MANAGER=$MANAGER_IP WAZUH_AGENT_GROUP=$AGENT_GROUP"

# Optionally configure AUTH_KEY
$y = Read-Host "Do you want to use an AUTH_KEY for authentication? (y/n)"
if ($y -eq 'y' -or $y -eq 'Y') {
    $AUTH_KEY = Read-Host -AsSecureString "Enter Wazuh AUTH_KEY"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AUTH_KEY)
    $PlainAuthKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $authdPassPath = "C:\Program Files (x86)\ossec-agent\authd.pass"
    Set-Content -Path $authdPassPath -Value $PlainAuthKey
    Write-Host "[+] AUTH_KEY written to $authdPassPath"
}
Start-Service -Name WazuhSvc
Write-Host "Wazuh agent installation and configuration complete."
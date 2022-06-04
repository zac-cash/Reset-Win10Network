#basic networking reset script
#written by Zac Cash
$github = "https://raw.githubusercontent.com/zac-cash/Reset-Win10Network/main/Reset-NetworkConfig.ps1"

#functions
function Test-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}
function Invoke-elevation {
    do {$2decision = read-host "[1] Pull Script from online`n[2] Open Powershell as Administrator for script to be pasted"} while (($2decision -ne "1") -and ($2decision -ne  "2"))
    switch ($2decision) {
        1 { 
            $command = "Invoke-RestMethod $github | invoke-expression"
            Start-Process powershell -ArgumentList "-NoExit -Command $command" -Credential (Get-credential -Credential "$env:COMPUTERNAME\LocalAdmin or Admin")
            Pause
            exit
        }
        2 {
            $command = "Get-Date"
            Start-Process powershell -ArgumentList "-NoExit -Command $command" -Credential (Get-credential -Credential "$env:COMPUTERNAME\LocalAdmin or Admin")
            Pause
            exit
        }
    }
}
function show-currentNetworking {
    do {$decision = read-host "[1] All Adapters or [2] Active Adapters"} while (($decision -ne "1") -and ($decision -ne  "2"))
    if ($decision -eq "2") {
        $filter = "Disconnected"
    } else {
        $filter = "" 
    }

    get-netadapter | Where-Object status -ne $filter | ForEach-Object {
        $AdapterIPinfo = Get-NetIPConfiguration | Where-Object interfaceindex -EQ $_.InterfaceIndex
        [PSCustomObject]@{
            AdapterName = $_.name
            AdapterDescription = $_.InterfaceDescription
            AdapterMacAddress = $_.MacAddress
            AdapterDriverInfor = $_.DriverInformation
            AdapterNetProfileName = $adapteripinfo.NetProfile.Name
            AdapterIPAddressess = "IPv4: " + $AdapterIPinfo.IPv4Address.IPv4Address,"IPv6: " + $AdapterIPinfo.IPv6Address.IPv6Address
            AdapterIPGateway = "IPv4: " + $AdapterIPinfo.IPv4DefaultGateway.nexthop,"IPv6: " + $AdapterIPinfo.IPv6DefaultGateway.nexthop
            AdapterDNSServers = $AdapterIPinfo.DNSServer.serveraddresses
            Adapteripv4connectivity = $AdapterIPinfo.NetProfile.IPv4Connectivity
            Adapteripv6connectivity = $AdapterIPinfo.NetProfile.IPv6Connectivity
        }
    }
    write-host "Press enter to return to menu." -ForegroundColor Green
    read-host 
}
function Set-GoogleDNS {
    Write-host "Checking connections for if they are non-domain specific." -ForegroundColor Yellow
    Write-host "Will prompt to set to Google DNS." -ForegroundColor Yellow
    $networkadapters = Get-NetAdapter -Physical | Where-Object -Property status -eq up | Get-NetConnectionProfile | Where-Object -Property networkcategory -ne DomainAuthenticated

    foreach ($adapter in $networkadapters) {
        $name = $adapter.name
        Write-host  "Set $name to Google DNS? Type Yes, Choose no if this is a GR network."
        do {$decision = read-host "y/n"} while (($decision -ne "y") -and ($decision -ne  "n"))

        If ($decision -eq "y") {
            Set-DnsClientServerAddress -InterfaceIndex ($adapter.interfaceindex) -ServerAddresses ("8.8.8.8","8.8.4.4")
        Write-host "Set $name to Google DNS`n" -ForegroundColor Green
        }
    }
    start-sleep -Seconds 2
    write-host "`n============================`n"
}
function reset-dnscache {
    Write-host "Flushing DNS cache" -ForegroundColor Yellow
    ipconfig /flushdns
    start-sleep -Seconds 2
    write-host "`n============================`n"
}

function invoke-newDCHPIP {
    Write-host "Leasing a new IP" -ForegroundColor Yellow
    ipconfig /release 
    ipconfig /renew 
    start-sleep -Seconds 2
    write-host "`n============================`n"
}
function reset-Winsock {
    Write-host "Starting Websocket connections" -ForegroundColor Yellow
    write-host "This requires a reboot" -ForegroundColor Yellow
    netsh winsock reset
    start-sleep -Seconds 2
    write-host "`n============================`n"
}
function Set-PreferIPV4 {
    Write-host "Preferring IPv4"
    Write-host "This requires a reboot"
    New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20 -PropertyType “DWord” -ErrorAction SilentlyContinue -Force
    Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20 -ErrorAction SilentlyContinue -Force
    write-host "`n============================`n"

    start-sleep -Seconds 2
}
function Disable-IPv6 {
    Write-host "Invoking: Disable-NetAdapterBinding -InterfaceAlias * -ComponentID ms_tcpip6`n============================"
    Disable-NetAdapterBinding -InterfaceAlias * -ComponentID ms_tcpip6
    write-host "`n============================`n"
}
function reset-TCPIPstack {
    Write-host "Invoking: netsh int ip reset`n============================"
    netsh int ip reset
    start-sleep -Seconds 2
    write-host "`n============================`n"
}
function invoke-fullreset {
    reset-TCPIPstack
    invoke-newDCHPIP
    reset-Winsock
    Set-GoogleDNS
    Set-PreferIPV4
    reset-dnscache
}
function invoke-SubMenu {
    $IndividualMenu = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
    $Options = @(
        ("&Reset TCP/IP Stack ", "netsh int ip reset"),
        ("Re&lease and renew DHCP ", "ipconfig /Release && ipconfig /Renew"),
        ("Reset &Winsock connections", "netsh winsock reset"),
        ("Change DNS to &Google", "Sets DNS servers to 8.8.8.8"),
        ("&Prefer IPv4 over IPv6", "Sets RegKey for prefer IPv4"),
        ("&Clear DNS Cache", "ipconfig /flushdns"),
        ("Disable Ipv&6", "Disable-NetAdapterBinding -InterfaceAlias * -ComponentID ms_tcpip6"),
        ("&Show Current Network Config", "Get-netadapter | get-NetIPConfiguration"),
        ('&Menu', 'Main Menu')
    )
    foreach ($option in $Options) {
        $IndividualMenu.Add((New-Object System.Management.Automation.Host.ChoiceDescription $option ))
    }
    
    $submenu = @"
Current user context: $env:USERNAME
Computer Name: $env:COMPUTERNAME
Public IP: $publicIP

Please select from the following list:

R. Reset TCP/IP Stack .
L. Release and renew DHCP lease. 
W. Reset websocket connections (requires reboot.)
G. Set Google DNS for Adapters.
P. Prefer IPv4 over IPv6
C. Clear DNS Cache
6. Disable Ipv6
S. Show Current Network Config
M. Main Menu


"@
    While ($true){
        Write-host $submenu
        $result = $host.ui.PromptForChoice('Menu:', '', $IndividualMenu, -1)
        Clear-Host
        switch ($result) {
            #backup
            0 { reset-TCPIPstack }
            1 { invoke-newDCHPIP }
            2 { reset-Winsock }
            3 { Set-GoogleDNS }
            4 { Set-PreferIPV4 }
            5 { reset-dnscache }
            6 { Disable-IPv6 }
            7 { show-currentNetworking }
            8 { break }
        }
        if ($result -eq 8) {break}
    }
    
}

#End Functions
#Test if script is running under administrator context.
if ((Test-Administrator)){
    Write-Host "Warning! Script is not running in an administrator context.`nA good portion of these utilites require these permissions."-ForegroundColor Red
    Write-Host "Would you like to attempt to restart as admin? You will be prompted for credentials." -ForegroundColor Yellow
    do {$decision = read-host "y/n"} while (($decision -ne "y") -and ($decision -ne  "n"))
    if ($decision -eq "y") {
        Invoke-elevation
    }
}

#enter Main
$publicIP = Invoke-RestMethod -uri ifconfig.me
$menu = @"
Current user context: $env:USERNAME
Computer Name: $env:COMPUTERNAME
Public IP: $publicIP

Please select from the following list:
F. Full Network Reset
I. Individual Commands
S. Show Current Network Config
Q. Quit


"@

$MainMenu = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
$Options = @(
    ("&Full Reset", "resets the TCP/IP stack, releases and renews IP, flush DNS, attempts to set DNS to google (Internal domain connections should be ignored), resets winsock connections."),
    ("&Individual Commands", "Opens submenu to pick individual networking commands to run")
    ("&Show Current Network Config", "Get-netadapter | get-NetIPConfiguration"),
    ('&Quit', 'Quit Script')
)
foreach ($option in $Options) {
    $MainMenu.Add((New-Object System.Management.Automation.Host.ChoiceDescription $option ))
}

While ($true){
    Write-host $menu
    $result = $host.ui.PromptForChoice('Menu:', '', $MainMenu, -1)
    Clear-Host
    switch ($result) {
        #backup
        0 { invoke-fullreset }
        1 { invoke-SubMenu }
        2 { show-currentNetworking }
        3 { exit }
    }
}
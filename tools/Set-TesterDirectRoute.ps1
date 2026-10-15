param(
    [ValidateSet('Apply', 'Check', 'Remove')][string]$Action = 'Check',
    [string]$ConfigPath = '',
    [int]$InterfaceIndex = 0,
    [switch]$IncludePanel
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ConfigPath) { $ConfigPath = Join-Path $projectRoot 'configs/local.yaml' }
$statusDirectory = Join-Path $projectRoot 'results/.network'
New-Item -ItemType Directory -Path $statusDirectory -Force | Out-Null
$statusPath = Join-Path $statusDirectory 'route-status.json'
$ledgerPath = Join-Path $statusDirectory 'owned-routes.json'
$operation = 'resolve'
try {
    $pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
    $pythonCode = @'
import json,sys,yaml
from urllib.parse import urlparse
d=yaml.safe_load(open(sys.argv[1],encoding='utf-8'))
panel_host=urlparse(d['panel']['url']).hostname
endpoints=[d.get('testing',{}).get('server_address') or panel_host]
if sys.argv[2].lower()=='true':
    endpoints.append(panel_host)
print(json.dumps(list(dict.fromkeys(filter(None,endpoints)))))
'@
    $endpointData = & $pythonPath -c $pythonCode $ConfigPath ([string]$IncludePanel.IsPresent)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read endpoint configuration' }
    $endpoints = ConvertFrom-Json -InputObject ($endpointData -join '')
    $addresses = @($endpoints | ForEach-Object {
        [Net.Dns]::GetHostAddresses($_) | Where-Object AddressFamily -eq InterNetwork | ForEach-Object IPAddressToString
    } | Sort-Object -Unique)
    if (-not $addresses.Count) { throw 'No IPv4 endpoints found; IPv6 requires a separate explicit route' }
    $ownedRoutes = @()
    if (Test-Path -LiteralPath $ledgerPath) { $ownedRoutes = @(Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json) }
    if ($Action -eq 'Remove') {
        foreach ($ownedRoute in $ownedRoutes) {
            Get-NetRoute -DestinationPrefix $ownedRoute.Prefix -InterfaceIndex $ownedRoute.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object NextHop -eq $ownedRoute.NextHop | Remove-NetRoute -Confirm:$false
        }
        @() | ConvertTo-Json | Set-Content -LiteralPath $ledgerPath -Encoding UTF8
        @{ok=$true;action=$Action;direct=$false;removed=$ownedRoutes.Count} | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
        exit 0
    }
    $operation = 'select_gateway'
    $physical = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    $defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {
        $_.InterfaceIndex -in $physical.InterfaceIndex -and ($InterfaceIndex -eq 0 -or $_.InterfaceIndex -eq $InterfaceIndex)
    } | Sort-Object @{Expression={ $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }})
    if (-not $defaultRoutes.Count) { throw 'No connected physical IPv4 gateway found' }
    $gateway = $defaultRoutes[0]
    if ($Action -eq 'Apply') {
        foreach ($address in $addresses) {
            $prefix = "$address/32"
            $existing = @(Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $gateway.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object NextHop -eq $gateway.NextHop)
            if (-not $existing.Count) {
                $operation = 'create_route'
                New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $gateway.InterfaceIndex -NextHop $gateway.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
                $ownedRoutes += @{Prefix=$prefix;InterfaceIndex=$gateway.InterfaceIndex;NextHop=$gateway.NextHop}
                ConvertTo-Json -InputObject @($ownedRoutes) | Set-Content -LiteralPath $ledgerPath -Encoding UTF8
            }
        }
    }
    $operation = 'verify'
    $direct = $true
    foreach ($address in $addresses) {
        $route = Find-NetRoute -RemoteIPAddress $address
        if ($gateway.InterfaceIndex -notin @($route.InterfaceIndex)) { $direct = $false }
    }
    @{ok=$true;action=$Action;direct=$direct;interface_index=$gateway.InterfaceIndex;endpoint_count=$addresses.Count;persistent=$false} |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    if (-not $direct) { exit 2 }
} catch {
    # Never persist the raw exception: it may contain endpoint/credential text.
    $routePrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    @{ok=$false;action=$Action;direct=$false;error_type=$_.Exception.GetType().Name;operation=$operation;error_id=$_.FullyQualifiedErrorId;elevated=$routePrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);requires_administrator=($Action -ne 'Check')} |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    exit 1
}

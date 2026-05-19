<#
.SYNOPSIS
  Windows network environment read-only diagnostic tool.

.DESCRIPTION
  Collects read-only network diagnostics for Windows 10/11 support cases.
  The script does not modify hosts, DNS, proxy, routes, services, registry,
  processes, or router configuration.
#>

[CmdletBinding()]
param(
    [switch]$OutputJson,
    [string]$OutputPath,
    [switch]$SkipConnectivity
)

# Windows support environments vary widely. Keep property access permissive so
# skipped checks render as blank fields instead of interrupting the report.
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

$script:Risks = New-Object System.Collections.Generic.List[object]
$script:PublicDnsMap = @{
    '8.8.8.8' = 'Google Public DNS'
    '8.8.4.4' = 'Google Public DNS'
    '1.1.1.1' = 'Cloudflare DNS'
    '1.0.0.1' = 'Cloudflare DNS'
    '9.9.9.9' = 'Quad9 DNS'
    '114.114.114.114' = '114DNS'
    '114.114.115.115' = '114DNS'
    '223.5.5.5' = 'AliDNS'
    '223.6.6.6' = 'AliDNS'
}

function Add-Risk {
    param(
        [ValidateSet('info','low','medium','high')]
        [string]$Level,
        [string]$Category,
        [string]$Message,
        [string]$Evidence
    )

    $script:Risks.Add([pscustomobject]@{
        level = $Level
        category = $Category
        message = $Message
        evidence = $Evidence
    }) | Out-Null
}

function Invoke-Safe {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        $DefaultValue = $null
    )

    try {
        & $ScriptBlock
    }
    catch {
        Add-Risk -Level 'low' -Category 'runtime' -Message "$Name 检测失败，已跳过该项。" -Evidence $_.Exception.Message
        $DefaultValue
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-PlainText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { return ($Value | Where-Object { $_ } | ForEach-Object { "$_" }) -join ', ' }
    "$Value"
}

function Test-PrivateIPv4 {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    return $false
}

function Test-LocalAddress {
    param([string]$Address)
    return ($Address -eq '127.0.0.1' -or $Address -eq '::1' -or $Address -match '^localhost(:|$)?')
}

function Get-FirstIPv4 {
    param($Values)
    foreach ($value in @($Values)) {
        if ($value -match '^\d{1,3}(\.\d{1,3}){3}$') { return $value }
    }
    return $null
}

function Get-SystemInfo {
    Invoke-Safe -Name '系统信息' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue 2>$null
        $caption = $null
        $version = $null
        $build = $null
        $arch = $null
        if ($os) {
            $caption = $os.Caption
            $version = $os.Version
            $build = $os.BuildNumber
            $arch = $os.OSArchitecture
        }
        else {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
            if ($cv) {
                $caption = $cv.ProductName
                $version = $cv.DisplayVersion
                $build = $cv.CurrentBuild
            }
            $arch = $env:PROCESSOR_ARCHITECTURE
        }
        [pscustomobject]@{
            computerName = $env:COMPUTERNAME
            userName = [Environment]::UserName
            domainName = [Environment]::UserDomainName
            windowsCaption = $caption
            windowsVersion = $version
            buildNumber = $build
            osArchitecture = $arch
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            isAdministrator = Test-IsAdmin
            collectedAt = (Get-Date).ToString('s')
        }
    }
}

function Get-NetworkAdapters {
    Invoke-Safe -Name '网络适配器' -DefaultValue @() -ScriptBlock {
        $adapterByIndex = @{}
        Get-NetAdapter -ErrorAction SilentlyContinue 2>$null | ForEach-Object {
            $adapterByIndex[[int]$_.ifIndex] = $_
        }

        $dnsByIndex = @{}
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue 2>$null | ForEach-Object {
            if (-not $dnsByIndex.ContainsKey([int]$_.InterfaceIndex)) {
                $dnsByIndex[[int]$_.InterfaceIndex] = New-Object System.Collections.Generic.List[string]
            }
            foreach ($server in @($_.ServerAddresses)) {
                if ($server -and -not $dnsByIndex[[int]$_.InterfaceIndex].Contains($server)) {
                    $dnsByIndex[[int]$_.InterfaceIndex].Add($server)
                }
            }
        }

        $metricByIndex = @{}
        Get-NetIPInterface -ErrorAction SilentlyContinue 2>$null | ForEach-Object {
            $key = "$($_.InterfaceIndex)-$($_.AddressFamily)"
            $metricByIndex[$key] = $_.InterfaceMetric
        }

        $configs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue 2>$null)
        foreach ($cfg in $configs) {
            $idx = [int]$cfg.InterfaceIndex
            $adapter = $adapterByIndex[$idx]
            $ipv4 = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress })
            $ipv6 = @($cfg.IPv6Address | ForEach-Object { $_.IPAddress })
            $gateways = @($cfg.IPv4DefaultGateway.NextHop + $cfg.IPv6DefaultGateway.NextHop | Where-Object { $_ })
            $dns = @()
            if ($dnsByIndex.ContainsKey($idx)) { $dns = @($dnsByIndex[$idx]) }

            [pscustomobject]@{
                name = $cfg.InterfaceAlias
                interfaceIndex = $idx
                status = if ($adapter) { $adapter.Status } else { $null }
                type = if ($adapter) { $adapter.MediaType } else { $null }
                description = if ($adapter) { $adapter.InterfaceDescription } else { $null }
                macAddress = if ($adapter) { $adapter.MacAddress } else { $null }
                linkSpeed = if ($adapter) { $adapter.LinkSpeed } else { $null }
                ipv4 = $ipv4
                ipv6 = $ipv6
                ipv4Gateway = @($cfg.IPv4DefaultGateway.NextHop | Where-Object { $_ })
                ipv6Gateway = @($cfg.IPv6DefaultGateway.NextHop | Where-Object { $_ })
                defaultGateway = $gateways
                dnsServers = $dns
                dhcpEnabled = $null
                ipv4Metric = $metricByIndex["$idx-IPv4"]
                ipv6Metric = $metricByIndex["$idx-IPv6"]
                isActive = ($adapter -and $adapter.Status -eq 'Up' -and ($ipv4.Count -gt 0 -or $ipv6.Count -gt 0))
            }
        }
    }
}

function Get-HostsCheck {
    Invoke-Safe -Name 'Hosts 文件' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $exists = Test-Path -LiteralPath $path
        $readable = $false
        $entries = @()
        $keywords = @(
            'openai','chatgpt','oaistatic','oaiusercontent','google','youtube','github',
            'cloudflare','steam','steamcommunity','steampowered','epicgames','riotgames',
            'battle.net','blizzard','dns','akamai','cloudfront','fastly','cdn','uu',
            'leigod','xunyou','qiyou','netpas','golink'
        )

        if ($exists) {
            $lines = @(Get-Content -LiteralPath $path -ErrorAction Stop)
            $readable = $true
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $raw = $lines[$i]
                $clean = ($raw -replace '#.*$', '').Trim()
                if ([string]::IsNullOrWhiteSpace($clean)) { continue }
                $parts = $clean -split '\s+'
                if ($parts.Count -lt 2) { continue }
                $address = $parts[0]
                $names = @($parts[1..($parts.Count - 1)])
                $isLocalhostOnly = ($names | Where-Object { $_ -notin @('localhost','localhost.localdomain') }).Count -eq 0
                $matched = @()
                foreach ($name in $names) {
                    foreach ($kw in $keywords) {
                        if ($name -match [regex]::Escape($kw)) { $matched += $kw }
                    }
                }
                $entries += [pscustomobject]@{
                    line = $i + 1
                    address = $address
                    names = $names
                    isLocalhostOnly = $isLocalhostOnly
                    matchedKeywords = @($matched | Select-Object -Unique)
                    raw = $raw
                }
            }
        }

        $suspicious = @($entries | Where-Object { -not $_.isLocalhostOnly })
        $keywordHits = @($entries | Where-Object { $_.matchedKeywords.Count -gt 0 })
        if ($keywordHits.Count -gt 0) {
            Add-Risk -Level 'medium' -Category 'hosts' -Message 'Hosts 文件存在 AI、游戏平台、CDN、DNS 或加速器相关域名覆盖，可能影响访问路径。' -Evidence (($keywordHits | Select-Object -First 5 | ForEach-Object { "$($_.address) -> $($_.names -join ',')" }) -join '; ')
        }
        elseif ($suspicious.Count -gt 0) {
            Add-Risk -Level 'low' -Category 'hosts' -Message 'Hosts 文件存在 localhost 以外的强制解析。' -Evidence "$($suspicious.Count) 条"
        }

        [pscustomobject]@{
            path = $path
            exists = $exists
            readable = $readable
            activeEntryCount = $entries.Count
            nonLocalhostEntryCount = $suspicious.Count
            keywordEntryCount = $keywordHits.Count
            keywordEntries = @($keywordHits | Select-Object -First 50)
            entriesSample = @($entries | Select-Object -First 50)
        }
    }
}

function Get-DnsCheck {
    param([array]$Adapters)

    Invoke-Safe -Name 'DNS 配置' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $servers = @($Adapters | ForEach-Object { $_.dnsServers } | Where-Object { $_ } | Select-Object -Unique)
        $public = @()
        $private = @()
        $local = @()
        $ipv6 = @()
        foreach ($server in $servers) {
            if ($script:PublicDnsMap.ContainsKey($server)) { $public += [pscustomobject]@{ address = $server; provider = $script:PublicDnsMap[$server] } }
            if (Test-PrivateIPv4 $server) { $private += $server }
            if (Test-LocalAddress $server) { $local += $server }
            if ($server -match ':') { $ipv6 += $server }
        }

        if ($local.Count -gt 0) {
            Add-Risk -Level 'medium' -Category 'dns' -Message 'DNS 指向本机地址，可能由本机代理、DNS 工具或开发环境接管解析。' -Evidence ($local -join ', ')
        }
        if ($public.Count -gt 0) {
            Add-Risk -Level 'low' -Category 'dns' -Message '检测到常见公共 DNS，可能是用户手动配置或路由器下发。' -Evidence (($public | ForEach-Object { "$($_.address) $($_.provider)" }) -join ', ')
        }
        if (($servers | Select-Object -Unique).Count -gt 2) {
            Add-Risk -Level 'low' -Category 'dns' -Message '检测到多个 DNS 服务器来源，解析结果可能因顺序或网络策略不同而变化。' -Evidence ($servers -join ', ')
        }

        $queries = @()
        if (-not $SkipConnectivity) {
            foreach ($domain in @('example.com','cloudflare.com','openai.com','steamcommunity.com')) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $ok = $false
                $addresses = @()
                $errorText = $null
                try {
                    $resolved = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
                    $addresses = @($resolved | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique)
                    $ok = $addresses.Count -gt 0
                }
                catch {
                    $errorText = $_.Exception.Message
                }
                $sw.Stop()
                if (-not $ok) {
                    Add-Risk -Level 'medium' -Category 'dns' -Message "DNS 查询失败：$domain" -Evidence $errorText
                }
                $queries += [pscustomobject]@{
                    domain = $domain
                    success = $ok
                    elapsedMs = [int]$sw.ElapsedMilliseconds
                    addresses = @($addresses | Select-Object -First 8)
                    error = $errorText
                }
            }
        }

        [pscustomobject]@{
            servers = $servers
            publicDns = $public
            privateDns = @($private | Select-Object -Unique)
            localDns = @($local | Select-Object -Unique)
            ipv6Dns = @($ipv6 | Select-Object -Unique)
            queryTests = $queries
        }
    }
}

function Get-ProxyCheck {
    Invoke-Safe -Name '代理配置' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $winHttp = (& netsh winhttp show proxy 2>&1) -join "`n"
        $internetSettings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        $envNames = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy')
        $envValues = foreach ($name in $envNames) {
            $value = [Environment]::GetEnvironmentVariable($name, 'Process')
            if (-not $value) { $value = [Environment]::GetEnvironmentVariable($name, 'User') }
            if ($value) {
                [pscustomobject]@{
                    name = $name
                    value = $value
                    isLocal = ($value -match '127\.0\.0\.1|localhost|\[::1\]|::1')
                    isPrivateLan = ($value -match '10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.')
                }
            }
        }

        $proxyEnable = if ($internetSettings) { [int]($internetSettings.ProxyEnable) } else { 0 }
        $proxyServer = if ($internetSettings) { $internetSettings.ProxyServer } else { $null }
        $autoConfigUrl = if ($internetSettings) { $internetSettings.AutoConfigURL } else { $null }
        $autoDetect = if ($internetSettings) { $internetSettings.AutoDetect } else { $null }
        $winHttpHasProxy = ($winHttp -notmatch '直接访问|Direct access|no proxy server')

        if ($proxyEnable -eq 1 -or $proxyServer -or $autoConfigUrl) {
            Add-Risk -Level 'medium' -Category 'proxy' -Message '系统 Internet 代理配置已启用或存在自动配置，可能影响加速器流量路径。' -Evidence "ProxyEnable=$proxyEnable ProxyServer=$proxyServer AutoConfigURL=$autoConfigUrl"
        }
        if ($winHttpHasProxy) {
            Add-Risk -Level 'medium' -Category 'proxy' -Message 'WinHTTP 代理存在配置，可能影响部分系统服务或工具联网。' -Evidence ($winHttp -replace '\s+', ' ')
        }
        if (@($envValues).Count -gt 0) {
            Add-Risk -Level 'medium' -Category 'proxy' -Message '检测到代理环境变量，可能导致部分应用流量绕过加速器。' -Evidence ((@($envValues) | ForEach-Object { "$($_.name)=$($_.value)" }) -join '; ')
        }

        [pscustomobject]@{
            winHttp = [pscustomobject]@{
                raw = $winHttp
                hasProxy = $winHttpHasProxy
            }
            internetSettings = [pscustomobject]@{
                proxyEnable = $proxyEnable
                proxyServer = $proxyServer
                autoConfigUrl = $autoConfigUrl
                autoDetect = $autoDetect
                isLocalProxy = ($proxyServer -match '127\.0\.0\.1|localhost|\[::1\]|::1')
                isLanProxy = ($proxyServer -match '10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.')
            }
            environment = @($envValues)
        }
    }
}

function Get-PortCheck {
    Invoke-Safe -Name '本地监听端口' -DefaultValue @() -ScriptBlock {
        $watchPorts = @(53,80,443,7890,7891,7892,1080,10808,8080,8888,9090,51820,1194,500,4500)
        $processNames = @('clash','v2ray','xray','sing-box','trojan','shadowsocks','wireguard','openvpn','tailscale','zerotier','uu','leigod','xunyou','qiyou','golink','netpas')
        $connections = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue 2>$null | Where-Object { $_.LocalPort -in $watchPorts })
        $result = foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $name = if ($proc) { $proc.ProcessName } else { $null }
            $isKnown = $false
            foreach ($p in $processNames) {
                if ($name -and $name -match [regex]::Escape($p)) { $isKnown = $true }
            }
            [pscustomobject]@{
                localAddress = $conn.LocalAddress
                localPort = $conn.LocalPort
                state = $conn.State
                pid = $conn.OwningProcess
                processName = $name
                isCommonProxyVpnPort = $true
                isKnownProxyVpnProcess = $isKnown
            }
        }

        $hits = @($result | Where-Object { $_.localPort -in @(53,7890,7891,7892,1080,10808,8080,8888,9090,51820,1194) })
        if ($hits.Count -gt 0) {
            Add-Risk -Level 'low' -Category 'ports' -Message '检测到常见代理、DNS、VPN 或加速器相关端口正在监听。' -Evidence (($hits | Select-Object -First 10 | ForEach-Object { "$($_.localAddress):$($_.localPort) pid=$($_.pid) $($_.processName)" }) -join '; ')
        }
        @($result)
    }
}

function Get-RouteCheck {
    Invoke-Safe -Name '路由表' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue 2>$null)
        $defaultV4 = @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Sort-Object RouteMetric, InterfaceMetric)
        $defaultV6 = @($routes | Where-Object { $_.DestinationPrefix -eq '::/0' } | Sort-Object RouteMetric, InterfaceMetric)
        if ($defaultV4.Count -eq 0) {
            Add-Risk -Level 'high' -Category 'route' -Message '未检测到 IPv4 默认路由，可能无法访问公网 IPv4。' -Evidence '0.0.0.0/0 missing'
        }
        if ($defaultV4.Count -gt 1) {
            Add-Risk -Level 'medium' -Category 'route' -Message '检测到多个 IPv4 默认路由，VPN、虚拟网卡或多出口可能影响加速器选路。' -Evidence (($defaultV4 | ForEach-Object { "$($_.NextHop) if=$($_.InterfaceAlias) metric=$($_.RouteMetric)/$($_.InterfaceMetric)" }) -join '; ')
        }
        $highPriority = @($defaultV4 | Where-Object { $_.RouteMetric -le 5 -or $_.InterfaceMetric -le 5 })
        if ($highPriority.Count -gt 0) {
            Add-Risk -Level 'low' -Category 'route' -Message '存在较高优先级默认路由，需结合网卡类型判断是否为 VPN 或虚拟网卡。' -Evidence (($highPriority | ForEach-Object { "$($_.NextHop) if=$($_.InterfaceAlias) metric=$($_.RouteMetric)/$($_.InterfaceMetric)" }) -join '; ')
        }

        [pscustomobject]@{
            defaultIPv4 = @($defaultV4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,InterfaceMetric,Protocol,PolicyStore)
            defaultIPv6 = @($defaultV6 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,InterfaceMetric,Protocol,PolicyStore)
            routeSample = @($routes | Sort-Object DestinationPrefix | Select-Object -First 100 DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,InterfaceMetric,Protocol)
        }
    }
}

function Test-PingTarget {
    param([string]$Target, [string]$Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $errorText = $null
    try {
        $ok = Test-Connection -ComputerName $Target -Count 2 -Quiet -ErrorAction Stop
    }
    catch {
        $errorText = $_.Exception.Message
    }
    $sw.Stop()
    [pscustomobject]@{
        type = 'ping'
        name = $Name
        target = $Target
        success = [bool]$ok
        elapsedMs = [int]$sw.ElapsedMilliseconds
        error = $errorText
    }
}

function Test-TcpTarget {
    param([string]$HostName, [int]$Port, [string]$Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $resolved = $false
    $errorText = $null
    try {
        $result = Test-NetConnection -ComputerName $HostName -Port $Port -WarningAction SilentlyContinue -InformationLevel Detailed -ErrorAction Stop
        $ok = [bool]$result.TcpTestSucceeded
        $resolved = [bool]$result.ResolvedAddresses
    }
    catch {
        $errorText = $_.Exception.Message
    }
    $sw.Stop()
    [pscustomobject]@{
        type = 'tcp'
        name = $Name
        target = "$HostName`:$Port"
        success = [bool]$ok
        dnsResolved = $resolved
        elapsedMs = [int]$sw.ElapsedMilliseconds
        error = $errorText
    }
}

function Get-ConnectivityCheck {
    param([array]$Adapters)

    Invoke-Safe -Name '网络连通性' -DefaultValue @() -ScriptBlock {
        if ($SkipConnectivity) {
            return @([pscustomobject]@{ type = 'skipped'; name = 'connectivity'; target = ''; success = $null; error = '用户指定 SkipConnectivity' })
        }
        $tests = New-Object System.Collections.Generic.List[object]
        $tests.Add((Test-PingTarget -Target '127.0.0.1' -Name '本机回环')) | Out-Null
        $gateways = @($Adapters | ForEach-Object { $_.ipv4Gateway } | Where-Object { $_ } | Select-Object -Unique)
        foreach ($gw in $gateways) {
            $tests.Add((Test-PingTarget -Target $gw -Name '默认网关')) | Out-Null
        }
        foreach ($ip in @('1.1.1.1','8.8.8.8')) {
            $tests.Add((Test-PingTarget -Target $ip -Name "公共 IP $ip")) | Out-Null
        }
        foreach ($domain in @('example.com','cloudflare.com')) {
            $tests.Add((Test-PingTarget -Target $domain -Name "域名 Ping $domain")) | Out-Null
        }
        foreach ($target in @(
            @{ h = '1.1.1.1'; p = 53; n = 'Cloudflare DNS TCP' },
            @{ h = '8.8.8.8'; p = 53; n = 'Google DNS TCP' },
            @{ h = 'cloudflare.com'; p = 443; n = 'Cloudflare HTTPS' },
            @{ h = 'openai.com'; p = 443; n = 'OpenAI HTTPS' },
            @{ h = 'steamcommunity.com'; p = 443; n = 'SteamCommunity HTTPS' }
        )) {
            $tests.Add((Test-TcpTarget -HostName $target.h -Port $target.p -Name $target.n)) | Out-Null
        }

        $failed = @($tests | Where-Object { $_.success -eq $false })
        if ($failed.Count -gt 0) {
            Add-Risk -Level 'medium' -Category 'connectivity' -Message '部分连通性测试失败，可能与本机网络、DNS、代理、运营商或防火墙策略有关。' -Evidence (($failed | ForEach-Object { "$($_.name) $($_.target)" }) -join '; ')
        }
        @($tests)
    }
}

function Get-GatewayMac {
    param([string]$Gateway)
    $arp = (& arp -a $Gateway 2>&1) -join "`n"
    $mac = $null
    if ($arp -match '([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}') {
        $mac = $Matches[0]
    }
    [pscustomobject]@{
        mac = $mac
        raw = $arp
    }
}

function Get-GatewayHttpProbe {
    param([string]$Gateway, [int[]]$Ports)
    foreach ($port in $Ports) {
        $scheme = if ($port -in @(443,8443)) { 'https' } else { 'http' }
        $url = "$scheme`://$Gateway`:$port/"
        $success = $false
        $status = $null
        $server = $null
        $title = $null
        $errorText = $null
        try {
            $response = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            $success = $true
            $status = [int]$response.StatusCode
            $server = $response.Headers['Server']
        }
        catch {
            $errorText = $_.Exception.Message
        }
        [pscustomobject]@{
            url = $url
            port = $port
            open = $success
            statusCode = $status
            server = ConvertTo-PlainText $server
            title = $title
            error = $errorText
            suggestsOpenWrt = (($server -match 'OpenWrt|uhttpd|LuCI') -or ($title -match 'OpenWrt|LuCI'))
        }
    }
}

function Get-LanGatewayCheck {
    param([array]$Adapters, $Dns)

    Invoke-Safe -Name '局域网网关' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $ipv4List = @($Adapters | ForEach-Object { $_.ipv4 } | Where-Object { $_ } | Select-Object -Unique)
        $gateways = @($Adapters | ForEach-Object { $_.ipv4Gateway } | Where-Object { $_ } | Select-Object -Unique)
        $dnsServers = @($Dns.servers | Where-Object { $_ })
        $privateIps = @($ipv4List | Where-Object { Test-PrivateIPv4 $_ })
        $privateGateways = @($gateways | Where-Object { Test-PrivateIPv4 $_ })
        $dnsIsGateway = @($dnsServers | Where-Object { $_ -in $gateways })
        $lanDnsNotGateway = @($dnsServers | Where-Object { (Test-PrivateIPv4 $_) -and ($_ -notin $gateways) })
        $gatewayDetails = @()

        foreach ($gw in $gateways) {
            $macInfo = Get-GatewayMac -Gateway $gw
            $http = @()
            if (-not $SkipConnectivity) {
                $http = @(Get-GatewayHttpProbe -Gateway $gw -Ports @(80,443,8080,8443))
            }
            $gatewayDetails += [pscustomobject]@{
                ip = $gw
                isPrivate = Test-PrivateIPv4 $gw
                mac = $macInfo.mac
                macVendorHint = Get-MacVendorHint -Mac $macInfo.mac
                arpRaw = $macInfo.raw
                httpProbe = $http
                suggestsOpenWrt = (@($http | Where-Object { $_.suggestsOpenWrt }).Count -gt 0)
            }
        }

        $suggestsBypassRouter = ($lanDnsNotGateway.Count -gt 0)
        $suggestsOpenWrt = (@($gatewayDetails | Where-Object { $_.suggestsOpenWrt }).Count -gt 0)
        $suggestsSecondRouter = ($privateIps.Count -gt 0 -and $privateGateways.Count -gt 0)

        if ($suggestsBypassRouter) {
            Add-Risk -Level 'medium' -Category 'lan' -Message 'DNS 指向非默认网关的局域网地址，疑似旁路由或独立 DNS 设备接管解析。' -Evidence ($lanDnsNotGateway -join ', ')
        }
        if ($suggestsOpenWrt) {
            Add-Risk -Level 'low' -Category 'lan' -Message '默认网关 Web 特征疑似 OpenWrt / LuCI / uhttpd。' -Evidence (($gatewayDetails | Where-Object { $_.suggestsOpenWrt } | ForEach-Object { $_.ip }) -join ', ')
        }

        [pscustomobject]@{
            isLanEnvironment = ($privateIps.Count -gt 0 -or $privateGateways.Count -gt 0)
            localPrivateIPv4 = $privateIps
            defaultGateways = $gateways
            privateGateways = $privateGateways
            dnsServers = $dnsServers
            dnsIsGateway = ($dnsIsGateway.Count -gt 0)
            lanDnsNotGateway = $lanDnsNotGateway
            suggestsSecondRouter = $suggestsSecondRouter
            suggestsBypassRouter = $suggestsBypassRouter
            suggestsOpenWrtOrSoftRouter = $suggestsOpenWrt
            gatewayDetails = $gatewayDetails
        }
    }
}

function Get-MacVendorHint {
    param([string]$Mac)
    if ([string]::IsNullOrWhiteSpace($Mac)) { return $null }
    $prefix = (($Mac -replace '[-:]', '').ToUpper())
    if ($prefix.Length -lt 6) { return $null }
    $oui = $prefix.Substring(0, 6)
    $map = @{
        '001A11' = 'Google'
        '001D0F' = 'TP-Link'
        '50C7BF' = 'TP-Link'
        'F4F26D' = 'TP-Link'
        'A42BB0' = 'TP-Link'
        'D46E0E' = 'TP-Link'
        '001E10' = 'D-Link'
        'C83A35' = 'Tenda'
        'E8DE27' = 'Tenda'
        '001E58' = 'Netgear'
        'B827EB' = 'Raspberry Pi'
        'DCA632' = 'Raspberry Pi'
        'E45F01' = 'Raspberry Pi'
        '3C7C3F' = 'Intel'
        '001B21' = 'Intel'
        'F0D5BF' = 'Intel'
        '525400' = 'QEMU/KVM virtual NIC'
        '000C29' = 'VMware'
        '005056' = 'VMware'
        '001C42' = 'Parallels'
        '080027' = 'VirtualBox'
    }
    if ($map.ContainsKey($oui)) { return $map[$oui] }
    return "Unknown OUI $oui"
}

function Get-DevToolProxyCheck {
    Invoke-Safe -Name '开发工具代理' -DefaultValue ([pscustomobject]@{}) -ScriptBlock {
        $items = New-Object System.Collections.Generic.List[object]

        function Add-DevItem {
            param([string]$Source, [string]$Key, [string]$Value, [string]$ErrorText)
            if ($Value -and $Value -notmatch '^(undefined|null|false|none|)$') {
                $items.Add([pscustomobject]@{
                    source = $Source
                    key = $Key
                    value = $Value
                    error = $null
                    mayAffectRequests = $true
                }) | Out-Null
            }
            elseif ($ErrorText) {
                $items.Add([pscustomobject]@{
                    source = $Source
                    key = $Key
                    value = $null
                    error = $ErrorText
                    mayAffectRequests = $false
                }) | Out-Null
            }
        }

        foreach ($cfg in @(
            @{ cmd = 'git'; args = @('config','--global','--get','http.proxy'); source = 'Git'; key = 'http.proxy' },
            @{ cmd = 'git'; args = @('config','--global','--get','https.proxy'); source = 'Git'; key = 'https.proxy' },
            @{ cmd = 'npm'; args = @('config','get','proxy'); source = 'npm'; key = 'proxy' },
            @{ cmd = 'npm'; args = @('config','get','https-proxy'); source = 'npm'; key = 'https-proxy' }
        )) {
            try {
                $cmdInfo = Get-Command $cfg.cmd -ErrorAction Stop
                $value = (& $cmdInfo.Source @($cfg.args) 2>$null | Select-Object -First 1)
                Add-DevItem -Source $cfg.source -Key $cfg.key -Value $value -ErrorText $null
            }
            catch {
                Add-DevItem -Source $cfg.source -Key $cfg.key -Value $null -ErrorText '工具未安装或不可访问，已跳过'
            }
        }

        foreach ($pipPath in @(
            (Join-Path $env:APPDATA 'pip\pip.ini'),
            (Join-Path $env:USERPROFILE 'pip\pip.ini')
        )) {
            if (Test-Path -LiteralPath $pipPath) {
                $content = Get-Content -LiteralPath $pipPath -ErrorAction SilentlyContinue
                $proxyLines = @($content | Where-Object { $_ -match '^\s*proxy\s*=' })
                foreach ($line in $proxyLines) {
                    Add-DevItem -Source 'pip' -Key $pipPath -Value $line.Trim() -ErrorText $null
                }
            }
        }

        $dockerSettings = Join-Path $env:APPDATA 'Docker\settings.json'
        if (Test-Path -LiteralPath $dockerSettings) {
            $dockerRaw = Get-Content -LiteralPath $dockerSettings -Raw -ErrorAction SilentlyContinue
            if ($dockerRaw -match 'proxy|Proxy|httpProxy|httpsProxy') {
                Add-DevItem -Source 'Docker Desktop' -Key $dockerSettings -Value 'settings.json 包含代理相关字段' -ErrorText $null
            }
        }

        try {
            $wslInfo = (& wsl.exe --status 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0) {
                $items.Add([pscustomobject]@{
                    source = 'WSL'
                    key = 'status'
                    value = '已安装 WSL，WSL 内可能存在独立 DNS/代理配置'
                    error = $null
                    mayAffectRequests = $false
                }) | Out-Null
            }
        }
        catch {
            # WSL is optional.
        }

        $active = @($items | Where-Object { $_.mayAffectRequests })
        if ($active.Count -gt 0) {
            Add-Risk -Level 'low' -Category 'devtool-proxy' -Message '检测到开发工具代理配置，可能影响 Git/npm/pip/Docker 等工具请求。' -Evidence (($active | ForEach-Object { "$($_.source) $($_.key)=$($_.value)" }) -join '; ')
        }

        [pscustomobject]@{
            items = $items.ToArray()
        }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "[$Title]" -ForegroundColor Cyan
}

function Format-RiskLine {
    param($Risk)
    "- $($Risk.level) / $($Risk.category): $($Risk.message) $($Risk.evidence)"
}

function Write-ConsoleReport {
    param($Report)

    Write-Host 'Windows 网络环境只读检测报告' -ForegroundColor Green
    Write-Host "采集时间: $($Report.system.collectedAt)"
    Write-Host '说明: 本工具只读取诊断信息，不修改 Hosts/DNS/代理/路由/注册表，不执行修复操作。'

    Write-Section '系统信息'
    Write-Host "Windows: $($Report.system.windowsCaption) $($Report.system.windowsVersion) Build $($Report.system.buildNumber)"
    Write-Host "当前用户: $($Report.system.domainName)\$($Report.system.userName)"
    Write-Host "管理员权限: $(if ($Report.system.isAdministrator) { '是' } else { '否' })"

    Write-Section '网络适配器'
    $active = @($Report.adapters | Where-Object { $_.isActive })
    if ($active.Count -eq 0) {
        Write-Host '未检测到启用且有 IP 的网络适配器。'
    }
    foreach ($adapter in $active) {
        Write-Host "- $($adapter.name) [$($adapter.type)] $($adapter.status)"
        Write-Host "  IPv4: $(ConvertTo-PlainText $adapter.ipv4)"
        Write-Host "  IPv6: $(ConvertTo-PlainText $adapter.ipv6)"
        Write-Host "  默认网关: $(ConvertTo-PlainText $adapter.defaultGateway)"
        Write-Host "  DNS: $(ConvertTo-PlainText $adapter.dnsServers)"
        Write-Host "  Metric: IPv4=$($adapter.ipv4Metric) IPv6=$($adapter.ipv6Metric)"
    }

    Write-Section 'Hosts 文件'
    Write-Host "路径: $($Report.hosts.path)"
    Write-Host "存在/可读取: $($Report.hosts.exists) / $($Report.hosts.readable)"
    Write-Host "有效条目: $($Report.hosts.activeEntryCount), 非 localhost 条目: $($Report.hosts.nonLocalhostEntryCount), 关键词命中: $($Report.hosts.keywordEntryCount)"
    foreach ($entry in @($Report.hosts.keywordEntries | Select-Object -First 5)) {
        Write-Host "  Line $($entry.line): $($entry.address) -> $(ConvertTo-PlainText $entry.names)"
    }

    Write-Section 'DNS'
    Write-Host "DNS 服务器: $(ConvertTo-PlainText $Report.dns.servers)"
    Write-Host "公共 DNS: $(ConvertTo-PlainText ($Report.dns.publicDns | ForEach-Object { "$($_.address) $($_.provider)" }))"
    Write-Host "局域网 DNS: $(ConvertTo-PlainText $Report.dns.privateDns)"
    Write-Host "本机 DNS: $(ConvertTo-PlainText $Report.dns.localDns)"
    foreach ($q in @($Report.dns.queryTests)) {
        Write-Host "  $($q.domain): $(if ($q.success) { '成功' } else { '失败' }) $($q.elapsedMs)ms $(ConvertTo-PlainText $q.addresses)"
    }

    Write-Section '代理'
    Write-Host "WinHTTP 代理: $(if ($Report.proxy.winHttp.hasProxy) { '存在配置' } else { '未检测到' })"
    Write-Host "Internet 代理: Enable=$($Report.proxy.internetSettings.proxyEnable) Server=$($Report.proxy.internetSettings.proxyServer) AutoConfig=$($Report.proxy.internetSettings.autoConfigUrl) AutoDetect=$($Report.proxy.internetSettings.autoDetect)"
    foreach ($envProxy in @($Report.proxy.environment)) {
        Write-Host "  $($envProxy.name)=$($envProxy.value)"
    }

    Write-Section '本地监听端口'
    if (@($Report.ports).Count -eq 0) {
        Write-Host '未检测到重点端口监听。'
    }
    foreach ($port in @($Report.ports | Sort-Object localPort, processName)) {
        Write-Host "- $($port.localAddress):$($port.localPort) PID=$($port.pid) Process=$($port.processName)"
    }

    Write-Section '默认路由'
    foreach ($route in @($Report.routes.defaultIPv4)) {
        Write-Host "- IPv4 $($route.NextHop) if=$($route.InterfaceAlias) metric=$($route.RouteMetric)/$($route.InterfaceMetric)"
    }
    foreach ($route in @($Report.routes.defaultIPv6)) {
        Write-Host "- IPv6 $($route.NextHop) if=$($route.InterfaceAlias) metric=$($route.RouteMetric)/$($route.InterfaceMetric)"
    }

    Write-Section '连通性'
    foreach ($test in @($Report.connectivity)) {
        Write-Host "- $($test.name) $($test.target): $(if ($test.success -eq $true) { '成功' } elseif ($test.success -eq $false) { '失败' } else { '跳过' }) $($test.elapsedMs)ms"
    }

    Write-Section '局域网 / 网关'
    Write-Host "局域网环境: $($Report.lanGateway.isLanEnvironment)"
    Write-Host "默认网关: $(ConvertTo-PlainText $Report.lanGateway.defaultGateways)"
    Write-Host "DNS 是否为网关: $($Report.lanGateway.dnsIsGateway)"
    Write-Host "疑似二级路由: $($Report.lanGateway.suggestsSecondRouter)"
    Write-Host "疑似旁路由: $($Report.lanGateway.suggestsBypassRouter)"
    Write-Host "疑似 OpenWrt/软路由: $($Report.lanGateway.suggestsOpenWrtOrSoftRouter)"
    foreach ($gw in @($Report.lanGateway.gatewayDetails)) {
        Write-Host "  网关 $($gw.ip) MAC=$($gw.mac) VendorHint=$($gw.macVendorHint)"
    }

    Write-Section '开发工具代理'
    if (@($Report.devToolProxy.items).Count -eq 0) {
        Write-Host '未检测到开发工具代理配置。'
    }
    foreach ($item in @($Report.devToolProxy.items)) {
        Write-Host "- $($item.source) $($item.key): $($item.value) $($item.error)"
    }

    Write-Section '风险摘要'
    if (@($Report.risks).Count -eq 0) {
        Write-Host '未发现明显高风险配置。建议仍将完整报告提交给客服分析。' -ForegroundColor Green
    }
    foreach ($risk in @($Report.risks | Sort-Object @{ Expression = {
        switch ($_.level) { 'high' { 0 } 'medium' { 1 } 'low' { 2 } default { 3 } }
    } }, category)) {
        $color = switch ($risk.level) { 'high' { 'Red' } 'medium' { 'Yellow' } 'low' { 'DarkYellow' } default { 'Gray' } }
        Write-Host (Format-RiskLine $risk) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host '请将本报告或 JSON 文件提交给客服/技术支持分析。'
}

$system = Get-SystemInfo
$adapters = @(Get-NetworkAdapters)
$hostsCheck = Get-HostsCheck
$dns = Get-DnsCheck -Adapters $adapters
$proxy = Get-ProxyCheck
$ports = @(Get-PortCheck)
$routes = Get-RouteCheck
$connectivity = @(Get-ConnectivityCheck -Adapters $adapters)
$lanGateway = Get-LanGatewayCheck -Adapters $adapters -Dns $dns
$devToolProxy = Get-DevToolProxyCheck

$report = [pscustomobject]@{
    system = $system
    adapters = $adapters
    dns = $dns
    hosts = $hostsCheck
    proxy = $proxy
    ports = $ports
    routes = $routes
    connectivity = $connectivity
    lanGateway = $lanGateway
    devToolProxy = $devToolProxy
    risks = $script:Risks.ToArray()
}

if ($OutputJson) {
    $json = $report | ConvertTo-Json -Depth 8
    if ($OutputPath) {
        $json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "JSON 报告已保存: $OutputPath"
    }
    else {
        $json
    }
}
else {
    Write-ConsoleReport -Report $report
    if ($OutputPath) {
        $text = New-Object System.Collections.Generic.List[string]
        $text.Add('Windows 网络环境只读检测报告') | Out-Null
        $text.Add("采集时间: $($report.system.collectedAt)") | Out-Null
        $text.Add('') | Out-Null
        $text.Add('[风险摘要]') | Out-Null
        if (@($report.risks).Count -eq 0) {
            $text.Add('未发现明显高风险配置。') | Out-Null
        }
        foreach ($risk in @($report.risks)) {
            $text.Add((Format-RiskLine $risk)) | Out-Null
        }
        $text.Add('') | Out-Null
        $text.Add('[JSON 原始数据]') | Out-Null
        $text.Add(($report | ConvertTo-Json -Depth 8)) | Out-Null
        $text | Set-Content -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "文本报告已保存: $OutputPath"
    }
}





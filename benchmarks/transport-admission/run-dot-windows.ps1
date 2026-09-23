[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Binary,
    [ValidateRange(1, 96)] [int]$ClientCount = 64,
    [ValidateRange(1, 8)] [int]$ListenerCount = 1,
    [ValidateRange(1, 20)] [int]$HoldSeconds = 5,
    [ValidateRange(1024, 65300)] [int]$BasePort = 34053
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not [IO.Path]::IsPathRooted($Binary)) {
    $Binary = Join-Path $repoRoot $Binary
}
$Binary = [IO.Path]::GetFullPath($Binary)
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "OnetDNS binary not found: $Binary"
}

$dotPorts = @(0..($ListenerCount - 1) | ForEach-Object { $BasePort + 100 + $_ })
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $repoRoot "target\dot-admission\$stamp"
[IO.Directory]::CreateDirectory($runDir) | Out-Null
$configPath = Join-Path $runDir "OnetDNS.toml"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$dotListen = ($dotPorts | ForEach-Object { '"127.0.0.1:{0}"' -f $_ }) -join ", "
$config = @"
backend = "forward"
listen = ["127.0.0.1:$BasePort"]
upstreams = ["1.1.1.1"]
workers = 1
cache_size = 4096
querylog = false
list_refresh_secs = 0
listen_dot = [$dotListen]
tls_self_signed_host = "localhost"
"@
[IO.File]::WriteAllText($configPath, $config, $utf8NoBom)

function Test-TcpPortFree([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        $listener.Stop()
    }
}

function Test-UdpPortFree([int]$Port) {
    $socket = [Net.Sockets.UdpClient]::new()
    try {
        $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $Port))
        return $true
    } catch {
        return $false
    } finally {
        $socket.Dispose()
    }
}

function Get-ProcessSample([Diagnostics.Process]$Target, [string]$Phase) {
    $Target.Refresh()
    [pscustomobject]@{
        Phase = $Phase
        CpuMs = $Target.TotalProcessorTime.TotalMilliseconds
        Threads = $Target.Threads.Count
        Handles = $Target.HandleCount
        WorkingSet = $Target.WorkingSet64
        Private = $Target.PrivateMemorySize64
        Virtual = $Target.VirtualMemorySize64
    }
}

if (-not (Test-TcpPortFree $BasePort) -or -not (Test-UdpPortFree $BasePort)) {
    throw "DNS benchmark port is occupied: $BasePort"
}
foreach ($dotPort in $dotPorts) {
    if (-not (Test-TcpPortFree $dotPort)) {
        throw "DoT benchmark port is occupied: $dotPort"
    }
}

$checkOutput = & $Binary --cli check --config $configPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "benchmark configuration check failed: $checkOutput"
}

$server = $null
$clients = [Collections.Generic.List[Net.Sockets.TcpClient]]::new()
try {
    $server = Start-Process -FilePath $Binary `
        -ArgumentList @("--config", $configPath, "--no-web", "--no-supervisor") `
        -WorkingDirectory $runDir -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDir "server.stdout.log") `
        -RedirectStandardError (Join-Path $runDir "server.stderr.log")

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 100
        $listening = @($dotPorts | Where-Object {
            Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue
        }).Count
    } while ($listening -ne $ListenerCount -and [DateTime]::UtcNow -lt $deadline)
    if ($listening -ne $ListenerCount) {
        throw "DoT ports did not all listen: $($dotPorts -join ', ')"
    }

    Start-Sleep -Seconds 3
    $baseline = Get-ProcessSample $server "baseline"
    foreach ($dotPort in $dotPorts) {
        foreach ($index in 1..$ClientCount) {
            $client = $null
            try {
                $client = [Net.Sockets.TcpClient]::new()
                $client.Connect("127.0.0.1", $dotPort)
                $client.GetStream().WriteByte(22)
                $clients.Add($client)
            } catch {
                if ($null -ne $client) {
                    $client.Dispose()
                }
            }
        }
    }

    Start-Sleep -Milliseconds 500
    $heldStart = Get-ProcessSample $server "held_start"
    Start-Sleep -Seconds $HoldSeconds
    $heldEnd = Get-ProcessSample $server "held_end"
    $established = @($dotPorts | ForEach-Object {
        Get-NetTCPConnection -State Established -LocalPort $_ -ErrorAction SilentlyContinue
    }).Count
    $clientsWritten = $clients.Count
    foreach ($client in $clients) {
        $client.Dispose()
    }
    $clients.Clear()
    Start-Sleep -Seconds 2
    $released = Get-ProcessSample $server "released"

    $summary = [pscustomobject]@{
        TimestampUtc = [DateTime]::UtcNow.ToString("O")
        RunDirectory = $runDir
        Binary = $Binary
        BinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash
        ClientCount = $ClientCount
        ListenerCount = $ListenerCount
        ClientAttempts = $ClientCount * $ListenerCount
        ClientWritesCompleted = $clientsWritten
        ServerEstablished = $established
        HoldSeconds = $HoldSeconds
        Baseline = $baseline
        HeldStart = $heldStart
        HeldEnd = $heldEnd
        Delta = [pscustomobject]@{
            CpuMsDuringHold = $heldEnd.CpuMs - $heldStart.CpuMs
            Threads = $heldEnd.Threads - $baseline.Threads
            Handles = $heldEnd.Handles - $baseline.Handles
            WorkingSet = $heldEnd.WorkingSet - $baseline.WorkingSet
            Private = $heldEnd.Private - $baseline.Private
            Virtual = $heldEnd.Virtual - $baseline.Virtual
        }
        Released = $released
    }
    $json = $summary | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $runDir "summary.json"), $json, $utf8NoBom)
    $json
} finally {
    foreach ($client in $clients) {
        $client.Dispose()
    }
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit(5000) | Out-Null
    }
}

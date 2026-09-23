[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Binary,
    [ValidateSet("one-byte", "large-body")] [string]$Mode = "one-byte",
    [ValidateRange(1, 300)] [int]$ClientCount = 300,
    [ValidateRange(1, 30)] [int]$HoldSeconds = 5,
    [ValidateRange(1024, 65400)] [int]$BasePort = 32053
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

$controlPort = $BasePort + 100
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $repoRoot "target\control-admission\$stamp-$Mode"
[IO.Directory]::CreateDirectory($runDir) | Out-Null
$configPath = Join-Path $runDir "OnetDNS.toml"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$config = @"
backend = "forward"
listen = ["127.0.0.1:$BasePort"]
upstreams = ["1.1.1.1"]
workers = 1
cache_size = 4096
querylog = false
list_refresh_secs = 0
control_listen = "127.0.0.1:$controlPort"
control_token = "onetdns-control-admission-benchmark-token"
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
if (-not (Test-TcpPortFree $controlPort)) {
    throw "control benchmark port is occupied: $controlPort"
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
        $listening = Get-NetTCPConnection -State Listen -LocalPort $controlPort -ErrorAction SilentlyContinue
    } while (-not $listening -and [DateTime]::UtcNow -lt $deadline)
    if (-not $listening) {
        throw "control port did not listen: $controlPort"
    }

    Start-Sleep -Seconds 3
    $baseline = Get-ProcessSample $server "baseline"
    if ($Mode -eq "large-body") {
        $requestHeader = [Text.Encoding]::ASCII.GetBytes(
            "POST /v1/config/validate HTTP/1.1`r`nHost: 127.0.0.1:$controlPort`r`nContent-Type: application/json`r`nContent-Length: 1048576`r`n`r`n"
        )
        $requestBody = [byte[]]::new(1048575)
    }

    foreach ($index in 1..$ClientCount) {
        $client = $null
        try {
            $client = [Net.Sockets.TcpClient]::new()
            $client.Connect("127.0.0.1", $controlPort)
            $stream = $client.GetStream()
            if ($Mode -eq "one-byte") {
                $stream.WriteByte([byte][char]'G')
            } else {
                $stream.Write($requestHeader, 0, $requestHeader.Length)
                $stream.Write($requestBody, 0, $requestBody.Length)
            }
            $clients.Add($client)
        } catch {
            if ($null -ne $client) {
                $client.Dispose()
            }
        }
    }

    Start-Sleep -Milliseconds 500
    $heldStart = Get-ProcessSample $server "held_start"
    Start-Sleep -Seconds $HoldSeconds
    $heldEnd = Get-ProcessSample $server "held_end"
    $established = @(Get-NetTCPConnection -State Established -LocalPort $controlPort -ErrorAction SilentlyContinue).Count
    $clientsWritten = $clients.Count
    foreach ($client in $clients) {
        $client.Dispose()
    }
    $clients.Clear()
    Start-Sleep -Seconds 2
    $released = Get-ProcessSample $server "released"

    $summary = [pscustomobject]@{
        TimestampUtc = [DateTime]::UtcNow.ToString("O")
        Mode = $Mode
        RunDirectory = $runDir
        Binary = $Binary
        BinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash
        ClientCount = $ClientCount
        ClientWritesCompleted = $clientsWritten
        ServerEstablished = $established
        BodyBytesPerClient = $(if ($Mode -eq "large-body") { 1048575 } else { 1 })
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

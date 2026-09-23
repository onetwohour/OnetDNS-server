[CmdletBinding()]
param(
    [string]$Binary = "",
    [ValidateRange(1, 100000)] [int]$ProposalCount = 32,
    [ValidateRange(1, 64)] [int]$Concurrency = 8,
    [ValidateSet("hot", "chain", "no_change")] [string]$Workload = "hot",
    [ValidateRange(1, 60)] [int]$BaselineSeconds = 5,
    [ValidateRange(1024, 65000)] [int]$BasePort = 25053,
    [ValidateRange(5, 120)] [int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($Binary)) {
    $Binary = Join-Path $repoRoot "target\raft-ha-build\release\onetdns.exe"
} elseif (-not [IO.Path]::IsPathRooted($Binary)) {
    $Binary = Join-Path $repoRoot $Binary
}
$Binary = [IO.Path]::GetFullPath($Binary)
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "OnetDNS binary not found: $Binary"
}
if ($BasePort + 202 -gt 65535) {
    throw "BasePort is too high for the reserved port range"
}

$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $repoRoot "target\raft-ha\$stamp"
[IO.Directory]::CreateDirectory($runDir) | Out-Null
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$token = "onetdns-raft-ha-benchmark-token-20260720"
$secret = "onetdns-raft-ha-benchmark-secret-not-for-production-20260720"
$identities = @(
    [pscustomobject]@{ Seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; Public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" },
    [pscustomobject]@{ Seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"; Public = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" },
    [pscustomobject]@{ Seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"; Public = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025" }
)

function Test-TcpPortFree([int]$Port) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try { $listener.Start(); return $true } catch { return $false } finally { $listener.Stop() }
}

function Test-UdpPortFree([int]$Port) {
    $socket = [Net.Sockets.UdpClient]::new()
    try {
        $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $Port))
        return $true
    } catch { return $false } finally { $socket.Dispose() }
}

$dnsPorts = 0..2 | ForEach-Object { $BasePort + $_ }
$controlPorts = 0..2 | ForEach-Object { $BasePort + 100 + $_ }
$raftPorts = 0..2 | ForEach-Object { $BasePort + 200 + $_ }
foreach ($port in $dnsPorts) {
    if (-not (Test-TcpPortFree $port) -or -not (Test-UdpPortFree $port)) {
        throw "DNS benchmark port is occupied: $port"
    }
}
foreach ($port in @($controlPorts) + @($raftPorts)) {
    if (-not (Test-TcpPortFree $port)) { throw "TCP benchmark port is occupied: $port" }
}

$nodes = @()
for ($index = 0; $index -lt 3; $index++) {
    $id = $index + 1
    $configPath = Join-Path $runDir "node-$id.toml"
    $peerValues = for ($peerIndex = 0; $peerIndex -lt 3; $peerIndex++) {
        if ($peerIndex -ne $index) {
            $peerId = $peerIndex + 1
            '"{0}@127.0.0.1:{1}#{2}"' -f $peerId, $raftPorts[$peerIndex], $identities[$peerIndex].Public
        }
    }
    $config = @"
backend = "forward"
listen = ["127.0.0.1:$($dnsPorts[$index])"]
upstreams = ["1.1.1.1"]
workers = 1
cache_size = 4096
blocked_response_ttl = 60
querylog = false
list_refresh_secs = 0
control_listen = "127.0.0.1:$($controlPorts[$index])"
control_token = "$token"
cluster_raft = true
cluster_node_id = $id
cluster_raft_listen = "127.0.0.1:$($raftPorts[$index])"
cluster_raft_peers = [$($peerValues -join ', ')]
cluster_raft_secret = "$secret"
cluster_raft_node_key = "$($identities[$index].Seed)"

[[dynamic_records]]
name = "raft-health.test"
qtype = "A"
mode = "round_robin"
values = ["192.0.2.123"]
ttl = 60
"@
    [IO.File]::WriteAllText($configPath, $config, $utf8NoBom)
    $nodes += [pscustomobject]@{
        Id = $id
        DnsPort = $dnsPorts[$index]
        ControlPort = $controlPorts[$index]
        RaftPort = $raftPorts[$index]
        Config = $configPath
        Process = $null
        Starts = 0
    }
}

foreach ($node in $nodes) {
    $checkOutput = & $Binary --cli check --config $node.Config 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "node $($node.Id) configuration check failed: $checkOutput"
    }
}

$http = [Net.Http.HttpClient]::new()
$http.Timeout = [TimeSpan]::FromSeconds(8)
$http.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $token)
$resourceSamples = New-Object Collections.Generic.List[object]
$proposalResults = New-Object Collections.Generic.List[object]
$dnsProbeResults = New-Object Collections.Generic.List[object]
$clock = [Diagnostics.Stopwatch]::StartNew()
$dnsProbeName = "raft-health.test"
$dnsProbeExpected = [byte[]](192, 0, 2, 123)
$script:dnsProbeSequence = 0
$script:dnsProbeNodeCursor = 0
$script:nextDnsProbeAtMs = 0.0

function Start-BenchmarkNode($Node) {
    $Node.Starts++
    $stdout = Join-Path $runDir "node-$($Node.Id).start-$($Node.Starts).stdout.log"
    $stderr = Join-Path $runDir "node-$($Node.Id).start-$($Node.Starts).stderr.log"
    $process = Start-Process -FilePath $Binary `
        -ArgumentList @("--config", $Node.Config, "--no-web", "--no-supervisor") `
        -WorkingDirectory $runDir -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $Node.Process = $process
}

function Stop-BenchmarkNode($Node) {
    if ($null -ne $Node.Process -and -not $Node.Process.HasExited) {
        Stop-Process -Id $Node.Process.Id -Force
        $Node.Process.WaitForExit(5000) | Out-Null
    }
}

function Get-NodeStatus($Node) {
    try {
        $url = "http://127.0.0.1:$($Node.ControlPort)/v1/cluster/nodes"
        $response = $http.GetAsync($url).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) { return $null }
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            return $body | ConvertFrom-Json
        } finally { $response.Dispose() }
    } catch { return $null }
}

function Get-ClusterSnapshot($Members) {
    $snapshot = @()
    foreach ($node in $Members) {
        $status = Get-NodeStatus $node
        if ($null -ne $status -and $null -ne $status.self) {
            $snapshot += [pscustomobject]@{ Node = $node; Status = $status.self }
        }
    }
    return $snapshot
}

function Find-Leader($Snapshot) {
    return @($Snapshot | Where-Object { $_.Status.role -eq "leader" }) | Select-Object -First 1
}

function Wait-Converged($Members, [bool]$EqualCommit, [string]$Context) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastState = "no reachable nodes"
    do {
        $snapshot = Get-ClusterSnapshot $Members
        if ($snapshot.Count -gt 0) {
            $lastState = @($snapshot | ForEach-Object {
                "node=$($_.Status.id),role=$($_.Status.role),leader=$($_.Status.leader),term=$($_.Status.term),commit=$($_.Status.commit_index),applied=$($_.Status.last_applied),last=$($_.Status.last_index),snapshot=$($_.Status.snapshot_index),retained=$($_.Status.retained_log_entries)"
            }) -join "; "
        }
        $leader = Find-Leader $snapshot
        if ($snapshot.Count -eq $Members.Count -and $null -ne $leader) {
            $leaderId = [int64]$leader.Status.id
            $leaderViews = @($snapshot | ForEach-Object { [int64]$_.Status.leader } | Select-Object -Unique)
            $healthy = @($snapshot | Where-Object { -not $_.Status.healthy }).Count -eq 0
            $commits = @($snapshot | ForEach-Object { [int64]$_.Status.commit_index } | Select-Object -Unique)
            $lastIndexes = @($snapshot | ForEach-Object { [int64]$_.Status.last_index } | Select-Object -Unique)
            $fullyApplied = @($snapshot | Where-Object {
                [int64]$_.Status.last_applied -ne [int64]$_.Status.commit_index
            }).Count -eq 0
            if ($healthy -and $leaderViews.Count -eq 1 -and $leaderViews[0] -eq $leaderId -and
                $fullyApplied -and ((-not $EqualCommit) -or
                    ($commits.Count -eq 1 -and $lastIndexes.Count -eq 1))) {
                return $snapshot
            }
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "cluster did not converge within $TimeoutSeconds seconds ($Context): $lastState"
}

function Add-ResourceSample([string]$Phase) {
    foreach ($node in $nodes) {
        if ($null -eq $node.Process -or $node.Process.HasExited) { continue }
        try {
            $process = Get-Process -Id $node.Process.Id -ErrorAction Stop
            $resourceSamples.Add([pscustomobject]@{
                TMs = [math]::Round($clock.Elapsed.TotalMilliseconds, 3)
                Phase = $Phase
                NodeId = $node.Id
                ProcessId = $process.Id
                CpuSeconds = [math]::Round($process.CPU, 6)
                WorkingSetBytes = [int64]$process.WorkingSet64
                PrivateBytes = [int64]$process.PrivateMemorySize64
                Threads = $process.Threads.Count
                Handles = $process.HandleCount
            })
        } catch { }
    }
}

function New-DnsProbePacket([uint16]$Id) {
    $packet = [Collections.Generic.List[byte]]::new()
    $packet.Add([byte]($Id -shr 8))
    $packet.Add([byte]($Id -band 0xff))
    $packet.Add(0x01); $packet.Add(0x00) # recursion desired
    $packet.Add(0x00); $packet.Add(0x01) # one question
    for ($index = 0; $index -lt 6; $index++) { $packet.Add(0x00) }
    foreach ($label in $dnsProbeName.Split('.')) {
        $wire = [Text.Encoding]::ASCII.GetBytes($label)
        $packet.Add([byte]$wire.Length)
        $packet.AddRange($wire)
    }
    $packet.Add(0x00)
    $packet.Add(0x00); $packet.Add(0x01) # A
    $packet.Add(0x00); $packet.Add(0x01) # IN
    return ,$packet.ToArray()
}

function Invoke-DnsProbe($Node, [string]$Phase) {
    $script:dnsProbeSequence++
    $id = [uint16](1 + (($script:dnsProbeSequence - 1) % 65535))
    [byte[]]$packet = New-DnsProbePacket $id
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $success = $false
    $errorText = ""
    $socket = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $socket.Client.ReceiveTimeout = 250
        $socket.Connect([Net.IPAddress]::Loopback, $Node.DnsPort)
        $null = $socket.Send($packet, $packet.Length)
        $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        [byte[]]$response = $socket.Receive([ref]$remote)
        if ($response.Length -lt 16) { throw "DNS response is shorter than 16 bytes" }
        $responseId = (([int]$response[0] -shl 8) -bor [int]$response[1])
        if ($responseId -ne $id) { throw "DNS transaction ID mismatch" }
        if (($response[2] -band 0x80) -eq 0) { throw "DNS QR bit is not set" }
        $rcode = $response[3] -band 0x0f
        if ($rcode -ne 0) { throw "DNS response rcode is $rcode" }
        $answerCount = (([int]$response[6] -shl 8) -bor [int]$response[7])
        if ($answerCount -lt 1) { throw "DNS response contains no answer" }
        $foundAddress = $false
        for ($offset = 0; $offset -le $response.Length - $dnsProbeExpected.Length; $offset++) {
            $matches = $true
            for ($byte = 0; $byte -lt $dnsProbeExpected.Length; $byte++) {
                if ($response[$offset + $byte] -ne $dnsProbeExpected[$byte]) {
                    $matches = $false
                    break
                }
            }
            if ($matches) { $foundAddress = $true; break }
        }
        if (-not $foundAddress) { throw "DNS response does not contain 192.0.2.123" }
        $success = $true
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        $timer.Stop()
        $socket.Dispose()
        [void]$dnsProbeResults.Add([pscustomobject]@{
            TMs = [math]::Round($clock.Elapsed.TotalMilliseconds, 3)
            Phase = $Phase
            NodeId = $Node.Id
            LatencyMs = [math]::Round($timer.Elapsed.TotalMilliseconds, 3)
            Success = $success
            Error = $errorText
        })
    }
    return $success
}

function Assert-DnsAvailable($Members, [string]$Phase) {
    foreach ($node in $Members) {
        if (-not (Invoke-DnsProbe $node $Phase)) {
            throw "node $($node.Id) did not serve the expected DNS answer during $Phase"
        }
    }
}

function Probe-DnsRoundRobin($Members, [string]$Phase) {
    if ($Members.Count -eq 0) { return }
    $node = $Members[$script:dnsProbeNodeCursor % $Members.Count]
    $script:dnsProbeNodeCursor++
    $null = Invoke-DnsProbe $node $Phase
}

function Assert-DnsPhaseClean([string]$Phase) {
    $failed = @($dnsProbeResults | Where-Object { $_.Phase -eq $Phase -and -not $_.Success })
    if ($failed.Count -gt 0) {
        $sample = $failed | Select-Object -First 1
        throw "DNS availability probe failed during $Phase on node $($sample.NodeId): $($sample.Error)"
    }
}

function New-Proposal([int]$Sequence) {
    if ($Workload -eq "hot") {
        return '{"patch":{"blocked_response_ttl":' + (1000 + $Sequence) + '}}'
    }
    if ($Workload -eq "chain") {
        return '{"patch":{"cache_size":' + (5000 + $Sequence) + '}}'
    }
    return '{"patch":{"blocked_response_ttl":60}}'
}

function Add-ProposalResult(
    [string]$Phase, [int]$Sequence, [int]$NodeId, [double]$StartedMs,
    [double]$LatencyMs, [int]$StatusCode, [bool]$Success, [string]$ErrorText
) {
    $proposalResults.Add([pscustomobject]@{
        Phase = $Phase
        Sequence = $Sequence
        NodeId = $NodeId
        StartedMs = [math]::Round($StartedMs, 3)
        LatencyMs = [math]::Round($LatencyMs, 3)
        StatusCode = $StatusCode
        Success = $Success
        Error = $ErrorText
    })
}

function Invoke-ProposalSync($Node, [int]$Sequence, [string]$Phase) {
    $started = $clock.Elapsed.TotalMilliseconds
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $content = [Net.Http.StringContent]::new((New-Proposal $Sequence), [Text.Encoding]::UTF8, "application/json")
    try {
        $url = "http://127.0.0.1:$($Node.ControlPort)/v1/cluster/propose"
        $response = $http.PostAsync($url, $content).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $ok = $response.IsSuccessStatusCode -and $body.Contains('"committed":true')
            Add-ProposalResult $Phase $Sequence $Node.Id $started $timer.Elapsed.TotalMilliseconds ([int]$response.StatusCode) $ok $(if ($ok) { "" } else { $body })
            return $ok
        } finally { $response.Dispose() }
    } catch {
        Add-ProposalResult $Phase $Sequence $Node.Id $started $timer.Elapsed.TotalMilliseconds 0 $false $_.Exception.Message
        return $false
    } finally { $content.Dispose(); $timer.Stop() }
}

function Invoke-ProposalBatch($LeaderNode, [int]$First, [int]$Count) {
    $pending = [Collections.Generic.List[object]]::new()
    for ($offset = 0; $offset -lt $Count; $offset++) {
        $sequence = $First + $offset
        $content = [Net.Http.StringContent]::new((New-Proposal $sequence), [Text.Encoding]::UTF8, "application/json")
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $started = $clock.Elapsed.TotalMilliseconds
        $url = "http://127.0.0.1:$($LeaderNode.ControlPort)/v1/cluster/propose"
        try {
            $task = $http.PostAsync($url, $content)
            $pending.Add([pscustomobject]@{ Sequence=$sequence; Content=$content; Timer=$timer; Started=$started; Task=$task })
        } catch {
            Add-ProposalResult "load" $sequence $LeaderNode.Id $started $timer.Elapsed.TotalMilliseconds 0 $false $_.Exception.Message
            $content.Dispose(); $timer.Stop()
        }
    }

    while ($pending.Count -gt 0) {
        # Keep resource sampling alive while idle, but wake immediately when any
        # request completes so each latency is captured at its own completion.
        $delay = [Threading.Tasks.Task]::Delay(20)
        $waiters = [Threading.Tasks.Task[]]@(@($pending | ForEach-Object { $_.Task }) + $delay)
        $null = ([Threading.Tasks.Task]::WhenAny($waiters)).GetAwaiter().GetResult()
        Add-ResourceSample "load"
        if ($clock.Elapsed.TotalMilliseconds -ge $script:nextDnsProbeAtMs) {
            Probe-DnsRoundRobin $nodes "load"
            $script:nextDnsProbeAtMs = $clock.Elapsed.TotalMilliseconds + 100.0
        }

        for ($index = $pending.Count - 1; $index -ge 0; $index--) {
            $request = $pending[$index]
            if (-not $request.Task.IsCompleted) { continue }
            $request.Timer.Stop()
            $latencyMs = $request.Timer.Elapsed.TotalMilliseconds
            try {
                $response = $request.Task.GetAwaiter().GetResult()
                try {
                    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    $ok = $response.IsSuccessStatusCode -and $body.Contains('"committed":true')
                    Add-ProposalResult "load" $request.Sequence $LeaderNode.Id $request.Started $latencyMs ([int]$response.StatusCode) $ok $(if ($ok) { "" } else { $body })
                } finally { $response.Dispose() }
            } catch {
                Add-ProposalResult "load" $request.Sequence $LeaderNode.Id $request.Started $latencyMs 0 $false $_.Exception.Message
            } finally {
                $request.Content.Dispose()
                $pending.RemoveAt($index)
            }
        }
    }
}

function Get-Percentile($Values, [double]$Percentile) {
    if ($Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $index = [math]::Max(0, [math]::Ceiling($Percentile * $sorted.Count) - 1)
    return [math]::Round([double]$sorted[$index], 3)
}

function Get-ResourceSummary([string]$Phase) {
    $rows = @($resourceSamples | Where-Object { $_.Phase -eq $Phase })
    $result = @()
    foreach ($nodeId in @($rows.NodeId | Select-Object -Unique | Sort-Object)) {
        $nodeRows = @($rows | Where-Object { $_.NodeId -eq $nodeId } | Sort-Object TMs)
        if ($nodeRows.Count -eq 0) { continue }
        $elapsed = [math]::Max(0.001, ($nodeRows[-1].TMs - $nodeRows[0].TMs) / 1000.0)
        $cpuDelta = [math]::Max(0.0, $nodeRows[-1].CpuSeconds - $nodeRows[0].CpuSeconds)
        $result += [pscustomobject]@{
            NodeId = $nodeId
            Samples = $nodeRows.Count
            CpuSeconds = [math]::Round($cpuDelta, 6)
            CpuPercentOfOneCore = [math]::Round(100.0 * $cpuDelta / $elapsed, 2)
            WorkingSetPeakBytes = [int64](($nodeRows.WorkingSetBytes | Measure-Object -Maximum).Maximum)
            PrivateBytesPeak = [int64](($nodeRows.PrivateBytes | Measure-Object -Maximum).Maximum)
            ThreadsPeak = [int](($nodeRows.Threads | Measure-Object -Maximum).Maximum)
            HandlesPeak = [int](($nodeRows.Handles | Measure-Object -Maximum).Maximum)
        }
    }
    return $result
}

function Get-DnsProbeSummary([string]$Phase) {
    $rows = @($dnsProbeResults | Where-Object { $_.Phase -eq $Phase })
    $success = @($rows | Where-Object { $_.Success })
    return [ordered]@{
        Attempts = $rows.Count
        Success = $success.Count
        Failed = $rows.Count - $success.Count
        LatencyP95Ms = Get-Percentile @($success.LatencyMs) 0.95
        LatencyMaxMs = if ($success.Count -eq 0) { $null } else {
            [math]::Round([double](($success.LatencyMs | Measure-Object -Maximum).Maximum), 3)
        }
    }
}

function Get-LogAudit([DateTime]$FailureStartedUtc) {
    $linesScanned = 0
    $expectedFailoverWarnings = 0
    $unexpected = [Collections.Generic.List[string]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $runDir -Filter "*.stderr.log" -File) {
        $lineNumber = 0
        foreach ($line in Get-Content -LiteralPath $file.FullName) {
            $lineNumber++
            $linesScanned++
            $warning = $line -cmatch '\sWARN\s'
            $severe = $line -cmatch '\s(ERROR|FATAL)\s' -or $line -match 'panic|fail[ ._-]?stop'
            if (-not $warning -and -not $severe) { continue }

            $allowed = $false
            if ($warning -and -not $severe -and $line -match '\sWARN\s+raft\.peer_unreachable\s') {
                $timestampMatch = [regex]::Match($line, '^(\S+)')
                $timestamp = [DateTime]::MinValue
                if ($timestampMatch.Success -and [DateTime]::TryParse(
                    $timestampMatch.Groups[1].Value,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
                    [ref]$timestamp
                ) -and $timestamp -ge $FailureStartedUtc) {
                    $allowed = $true
                    $expectedFailoverWarnings++
                }
            }
            if (-not $allowed) {
                [void]$unexpected.Add("$($file.Name):$($lineNumber):$line")
            }
        }
    }
    return [ordered]@{
        LinesScanned = $linesScanned
        ExpectedFailoverWarnings = $expectedFailoverWarnings
        UnexpectedCount = $unexpected.Count
        Unexpected = @($unexpected)
    }
}

$initialElectionMs = $null
$killedNode = $null
$newElectionMs = $null
$firstCommitMs = $null
$rejoinMs = $null
$rejoinDnsReadyMs = $null
$leaderFailureStartedUtc = $null
$finalSnapshot = $null
$leaderStabilityRequired = $true

try {
    $electionTimer = [Diagnostics.Stopwatch]::StartNew()
    foreach ($node in $nodes) { Start-BenchmarkNode $node }
    $initialSnapshot = Wait-Converged $nodes $true "initial election"
    $initialElectionMs = [math]::Round($electionTimer.Elapsed.TotalMilliseconds, 3)
    $initialLeader = Find-Leader $initialSnapshot
    Assert-DnsAvailable $nodes "initial"

    $baselineDeadline = [DateTime]::UtcNow.AddSeconds($BaselineSeconds)
    do { Add-ResourceSample "baseline"; Start-Sleep -Milliseconds 100 } while ([DateTime]::UtcNow -lt $baselineDeadline)

    $loadTimer = [Diagnostics.Stopwatch]::StartNew()
    for ($first = 1; $first -le $ProposalCount; $first += $Concurrency) {
        $snapshot = Wait-Converged $nodes $false "before load batch $first"
        $leader = Find-Leader $snapshot
        $count = [math]::Min($Concurrency, $ProposalCount - $first + 1)
        Invoke-ProposalBatch $leader.Node $first $count
    }
    $loadSnapshot = Wait-Converged $nodes $true "after load"
    $loadElapsedMs = $loadTimer.Elapsed.TotalMilliseconds
    Assert-DnsPhaseClean "load"
    Assert-DnsAvailable $nodes "post_load"

    $leaderBeforeFailure = Find-Leader $loadSnapshot
    $leaderStableUnderLoad =
        [int64]$leaderBeforeFailure.Status.id -eq [int64]$initialLeader.Status.id -and
        [int64]$leaderBeforeFailure.Status.term -eq [int64]$initialLeader.Status.term -and
        @($loadSnapshot | Where-Object {
            [int64]$_.Status.term -ne [int64]$initialLeader.Status.term
        }).Count -eq 0
    $killedNode = $leaderBeforeFailure.Node
    $failureTimer = [Diagnostics.Stopwatch]::StartNew()
    $leaderFailureStartedUtc = [DateTime]::UtcNow
    Stop-BenchmarkNode $killedNode
    $failSequence = $ProposalCount + 1
    $failureDeadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $survivors = @($nodes | Where-Object { $_.Id -ne $killedNode.Id })
    Assert-DnsAvailable $survivors "failover"
    do {
        Add-ResourceSample "failover"
        Probe-DnsRoundRobin $survivors "failover"
        $snapshot = Get-ClusterSnapshot $survivors
        $leader = Find-Leader $snapshot
        if ($null -ne $leader -and $leader.Node.Id -ne $killedNode.Id) {
            if ($null -eq $newElectionMs) { $newElectionMs = [math]::Round($failureTimer.Elapsed.TotalMilliseconds, 3) }
            if (Invoke-ProposalSync $leader.Node $failSequence "failover") {
                $firstCommitMs = [math]::Round($failureTimer.Elapsed.TotalMilliseconds, 3)
                break
            }
            $failSequence++
        } else {
            Add-ProposalResult "failover" $failSequence 0 $clock.Elapsed.TotalMilliseconds 0 0 $false "no leader"
            $failSequence++
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $failureDeadline)
    if ($null -eq $firstCommitMs) { throw "no proposal committed after leader termination" }
    Assert-DnsPhaseClean "failover"

    Start-Sleep -Milliseconds 50
    for ($extra = 1; $extra -le 8; $extra++) {
        $survivorSnapshot = Wait-Converged $survivors $true "before post-failover proposal $extra"
        $survivorLeader = Find-Leader $survivorSnapshot
        if ($null -eq $survivorLeader -or -not (Invoke-ProposalSync $survivorLeader.Node ($failSequence + $extra) "failover")) {
            throw "post-failover proposal $extra did not commit"
        }
        Add-ResourceSample "failover"
        Start-Sleep -Milliseconds 50
    }
    $null = Wait-Converged $survivors $true "after post-failover proposals"
    Assert-DnsAvailable $survivors "post_failover"

    $rejoinTimer = [Diagnostics.Stopwatch]::StartNew()
    Start-BenchmarkNode $killedNode
    $dnsReadyDeadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Invoke-DnsProbe $killedNode "recovery_start") {
            $rejoinDnsReadyMs = [math]::Round($rejoinTimer.Elapsed.TotalMilliseconds, 3)
            break
        }
        Start-Sleep -Milliseconds 10
    } while ([DateTime]::UtcNow -lt $dnsReadyDeadline)
    if ($null -eq $rejoinDnsReadyMs) { throw "restarted node did not resume DNS service" }
    $finalSnapshot = Wait-Converged $nodes $true "after killed leader rejoined"
    $rejoinMs = [math]::Round($rejoinTimer.Elapsed.TotalMilliseconds, 3)
    Assert-DnsAvailable $nodes "recovery"

    $configKey = if ($Workload -eq "chain") { "cache_size" } else { "blocked_response_ttl" }
    $configValues = foreach ($node in $nodes) {
        $text = [IO.File]::ReadAllText($node.Config)
        $pattern = '(?m)^' + [regex]::Escape($configKey) + '\s*=\s*(\d+)\s*$'
        $matches = [regex]::Matches($text, $pattern)
        if ($matches.Count -ne 1) { throw "node $($node.Id) $configKey is not canonical" }
        [int64]$matches[0].Groups[1].Value
    }
    $configEqual = @($configValues | Select-Object -Unique).Count -eq 1
    if (-not $configEqual) { throw "replicated configuration differs after rejoin" }

    $loadRows = @($proposalResults | Where-Object { $_.Phase -eq "load" })
    $loadSuccess = @($loadRows | Where-Object { $_.Success })
    $failRows = @($proposalResults | Where-Object { $_.Phase -eq "failover" })
    $finalCommits = @($finalSnapshot | ForEach-Object { [int64]$_.Status.commit_index })
    $finalLastIndexes = @($finalSnapshot | ForEach-Object { [int64]$_.Status.last_index })
    $finalSnapshotIndexes = @($finalSnapshot | ForEach-Object { [int64]$_.Status.snapshot_index })
    $finalRetainedEntries = @($finalSnapshot | ForEach-Object { [int64]$_.Status.retained_log_entries })
    $logAudit = Get-LogAudit $leaderFailureStartedUtc
    $summary = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString("o")
        Binary = $Binary
        BinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash
        RunDirectory = $runDir
        Host = [ordered]@{
            Os = (Get-CimInstance Win32_OperatingSystem).Caption
            Cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
            LogicalProcessors = [Environment]::ProcessorCount
            PhysicalMemoryBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        }
        Cluster = [ordered]@{
            Nodes = 3
            WorkersPerNode = 1
            InitialElectionMs = $initialElectionMs
            InitialLeader = [int64]$initialLeader.Status.id
            InitialTerm = [int64]$initialLeader.Status.term
        }
        Load = [ordered]@{
            Workload = $Workload
            ConfigKey = $configKey
            Requested = $ProposalCount
            Concurrency = $Concurrency
            Success = $loadSuccess.Count
            Failed = $loadRows.Count - $loadSuccess.Count
            ErrorRate = [math]::Round(($loadRows.Count - $loadSuccess.Count) / [math]::Max(1.0, $loadRows.Count), 6)
            ElapsedMs = [math]::Round($loadElapsedMs, 3)
            CommittedPerSecond = [math]::Round(1000.0 * $loadSuccess.Count / [math]::Max(1.0, $loadElapsedMs), 3)
            LatencyP50Ms = Get-Percentile @($loadSuccess.LatencyMs) 0.50
            LatencyP95Ms = Get-Percentile @($loadSuccess.LatencyMs) 0.95
            LatencyP99Ms = Get-Percentile @($loadSuccess.LatencyMs) 0.99
            LeaderStabilityRequired = $leaderStabilityRequired
            LeaderStable = $leaderStableUnderLoad
            LeaderAfter = [int64]$leaderBeforeFailure.Status.id
            TermAfter = [int64]$leaderBeforeFailure.Status.term
        }
        Failover = [ordered]@{
            KilledLeader = $killedNode.Id
            NewLeaderElectionMs = $newElectionMs
            FirstCommittedProposalMs = $firstCommitMs
            Attempts = $failRows.Count
            FailedAttempts = @($failRows | Where-Object { -not $_.Success }).Count
        }
        Recovery = [ordered]@{
            RejoinAndCatchUpMs = $rejoinMs
            RestartedNodeDnsReadyMs = $rejoinDnsReadyMs
            CommitIndexes = $finalCommits
            CommitIndexesEqual = @($finalCommits | Select-Object -Unique).Count -eq 1
            LastIndexes = $finalLastIndexes
            LastIndexesEqual = @($finalLastIndexes | Select-Object -Unique).Count -eq 1
            SnapshotIndexes = $finalSnapshotIndexes
            RetainedLogEntries = $finalRetainedEntries
            ConfigValues = $configValues
            ConfigEqual = $configEqual
        }
        DnsAvailability = [ordered]@{
            QueryName = $dnsProbeName
            ExpectedIpv4 = "192.0.2.123"
            ProbeIntervalMs = 100
            Initial = Get-DnsProbeSummary "initial"
            Load = Get-DnsProbeSummary "load"
            PostLoad = Get-DnsProbeSummary "post_load"
            Failover = Get-DnsProbeSummary "failover"
            PostFailover = Get-DnsProbeSummary "post_failover"
            RecoveryStart = Get-DnsProbeSummary "recovery_start"
            Recovery = Get-DnsProbeSummary "recovery"
        }
        LogAudit = $logAudit
        Resources = [ordered]@{
            Baseline = @(Get-ResourceSummary "baseline")
            Load = @(Get-ResourceSummary "load")
            Failover = @(Get-ResourceSummary "failover")
        }
    }

    $resourceSamples | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "resources.csv")
    $proposalResults | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "proposals.csv")
    $dnsProbeResults | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "dns-probes.csv")
    [IO.File]::WriteAllText(
        (Join-Path $runDir "summary.json"),
        ($summary | ConvertTo-Json -Depth 8),
        $utf8NoBom
    )
    if ($leaderStabilityRequired -and -not $leaderStableUnderLoad) {
        throw "leader or term changed during healthy load"
    }
    if ($logAudit.UnexpectedCount -ne 0) {
        throw "unexpected warning, error, panic, fatal, or fail-stop log entry detected"
    }
    $summary | ConvertTo-Json -Depth 8
} finally {
    if ($resourceSamples.Count -gt 0) {
        $resourceSamples | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "resources.csv")
    }
    if ($proposalResults.Count -gt 0) {
        $proposalResults | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "proposals.csv")
    }
    if ($dnsProbeResults.Count -gt 0) {
        $dnsProbeResults | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $runDir "dns-probes.csv")
    }
    foreach ($node in $nodes) { Stop-BenchmarkNode $node }
    $http.Dispose()
}

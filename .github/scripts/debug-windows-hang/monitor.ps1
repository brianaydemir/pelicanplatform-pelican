# Record free memory, the largest processes, and the state of every thread
# in the go command, gotestsum, and their children, for debugging test runs
# that hang on Windows. Samples once a minute until the stop file exists,
# or just once with -Once.

param(
    [string]$LogFile = 'monitor.log',
    [string]$ThreadFile = 'threads.log',
    [string]$StopFile = 'monitor.stop',
    [int]$Top = 15,
    [switch]$Once
)

function Write-Processes([string]$Now) {
    "=== $Now UTC"
    Get-CimInstance Win32_OperatingSystem |
        Format-List FreePhysicalMemory, FreeVirtualMemory
    $procs = Get-Process | Sort-Object WS -Descending
    if ($Top -gt 0) {
        $procs = $procs | Select-Object -First $Top
    }
    $procs | Format-Table -AutoSize Id, ProcessName, WS, CPU, StartTime
}

function Write-Threads([string]$Now) {
    "=== $Now UTC"
    $all = @(Get-CimInstance Win32_Process)
    $goIds = @($all | Where-Object { $_.Name -eq 'go.exe' } | ForEach-Object { $_.ProcessId })
    $watched = $all | Where-Object {
        (
            ($_.Name -in @('go.exe', 'gotestsum.exe')) -or
            ($_.Name -like '*.test.exe') -or
            ($goIds -contains $_.ParentProcessId)
        )
    }
    foreach ($p in $watched) {
        try {
            $fmt = '{0} {1} parent={2} created={3:HH:mm:ss} kernel={4:N2}s user={5:N2}s ws={6:N0}MB'
            $fmt -f @(
                $p.ProcessId, $p.Name, $p.ParentProcessId,
                $p.CreationDate.ToUniversalTime(),
                ($p.KernelModeTime / 1e7), ($p.UserModeTime / 1e7),
                ($p.WorkingSetSize / 1MB)
            )
            '  ' + $p.CommandLine
        } catch {
            "$($p.ProcessId) $($p.Name): $($_.Exception.Message)"
        }
        try {
            $threads = (Get-Process -Id $p.ProcessId -ErrorAction Stop).Threads
        } catch {
            "  threads unavailable: $($_.Exception.Message)"
            continue
        }
        foreach ($t in $threads) {
            try {
                # WaitReason throws unless the thread is waiting.
                $reason = '-'
                if ($t.ThreadState -eq 'Wait') {
                    $reason = $t.WaitReason
                }
                '  tid={0} {1}/{2} kernel={3:N2}s user={4:N2}s' -f @(
                    $t.Id, $t.ThreadState, $reason,
                    $t.PrivilegedProcessorTime.TotalSeconds,
                    $t.UserProcessorTime.TotalSeconds
                )
            } catch {
                "  tid=$($t.Id): $($_.Exception.Message)"
            }
        }
    }
}

function Write-Sample {
    $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    try {
        Write-Processes $now | Out-File -Append -Encoding utf8 -Width 200 $LogFile
    } catch {
        "=== $now UTC: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 $LogFile
    }
    try {
        Write-Threads $now | Out-File -Append -Encoding utf8 -Width 1000 $ThreadFile
    } catch {
        "=== $now UTC: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 $ThreadFile
    }
}

if ($Once) {
    Write-Sample
    return
}

# Sample in-process, rather than starting a new process each minute, so
# that the monitor keeps working if starting processes is what hangs.
while (-not (Test-Path $StopFile)) {
    Write-Sample
    for ($i = 0; $i -lt 12 -and -not (Test-Path $StopFile); $i++) {
        Start-Sleep -Seconds 5
    }
}

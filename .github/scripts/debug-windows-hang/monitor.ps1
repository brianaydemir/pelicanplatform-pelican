# Record free memory, the largest processes, and the state of every thread
# in the go command, gotestsum, their children, and the processes that run
# the step, for debugging test runs that hang on Windows. Samples once a
# minute until the stop file exists (unless a stall has been seen) or
# MaxMinutes pass, or just once with -Once.
#
# When the JSON file stops growing for StallSeconds, the monitor asks the
# go command for a goroutine dump (see debug_dump.go) and, given
# UploadName, uploads its files as an artifact, repeating every
# DumpEverySeconds while the stall lasts. A hang can keep the runner from
# ever reaching the workflow's own upload step.

param(
    [string]$LogFile = 'monitor.log',
    [string]$ThreadFile = 'threads.log',
    [string]$ErrorFile = 'monitor-errors.log',
    [string]$StopFile = 'monitor.stop',
    [string]$JsonFile = 'go-test.json',
    [string]$DumpDir = 'dumps',
    [string]$UploadName = '',
    [string]$UploaderDir = '',
    [int]$StallSeconds = 180,
    [int]$DumpEverySeconds = 240,
    [int]$MaxUploads = 8,
    [int]$MaxMinutes = 40,
    [int]$Top = 15,
    [switch]$Once
)

$watchedNames = @('go.exe', 'gotestsum.exe', 'bash.exe', 'conhost.exe', 'Runner.Worker.exe')

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
            ($_.Name -in $watchedNames) -or
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

function Get-Now {
    (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

function Write-Log([string]$Message) {
    "=== $(Get-Now) UTC: $Message" | Out-File -Append -Encoding utf8 $LogFile
}

function Write-Sample {
    $now = Get-Now
    try {
        Write-Processes $now | Out-File -Append -Encoding utf8 -Width 200 $LogFile
    } catch {
        Write-Log $_.Exception.Message
    }
    try {
        Write-Threads $now | Out-File -Append -Encoding utf8 -Width 1000 $ThreadFile
    } catch {
        "=== $now UTC: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 $ThreadFile
    }
}

function Request-Dump {
    New-Item -ItemType Directory -Force $DumpDir | Out-Null
    Set-Content -Path (Join-Path $DumpDir 'dump') -Value (Get-Now)
    Write-Log 'stalled; requested a goroutine dump from the go command'
}

function Send-Files([int]$Number) {
    if ($UploadName -eq '' -or $UploaderDir -eq '') {
        return
    }
    $name = "$UploadName-$Number"
    $files = @($JsonFile, $LogFile, $ThreadFile, $ErrorFile)
    if (Test-Path $DumpDir) {
        $files += @(Get-ChildItem $DumpDir -Filter '*.txt' | ForEach-Object { $_.FullName })
    }
    $files = @($files | Where-Object { Test-Path $_ } | ForEach-Object { (Resolve-Path $_).Path })
    $out = Join-Path $DumpDir "upload-$Number.log"
    $proc = Start-Process -FilePath 'node' -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError "$out.err" `
        -ArgumentList (@((Join-Path $UploaderDir 'upload.js'), $name, $PWD.Path) + $files)
    if ($proc.WaitForExit(180000)) {
        Write-Log "upload of $name exited with $($proc.ExitCode)"
    } else {
        $proc.Kill()
        Write-Log "upload of $name timed out"
    }
}

if ($Once) {
    Write-Sample
    return
}

$sawStall = $false

# After a stall, keep watching while the step is cancelled, which may hang.
function Test-StopRequested {
    (-not $script:sawStall) -and (Test-Path $StopFile)
}

try {
    $deadline = (Get-Date).AddMinutes($MaxMinutes)
    $lastSize = -1
    $lastGrowth = Get-Date
    $lastDump = [datetime]::MinValue
    $uploads = 0

    # Sample in-process, rather than starting a new process each minute,
    # so that the monitor keeps working if starting processes is what hangs.
    while (-not (Test-StopRequested) -and (Get-Date) -lt $deadline) {
        Write-Sample

        $size = 0
        if (Test-Path $JsonFile) {
            $size = (Get-Item $JsonFile).Length
        }
        $now = Get-Date
        if ($size -ne $lastSize) {
            $lastSize = $size
            $lastGrowth = $now
        }
        $stalled = ($size -gt 0) -and (($now - $lastGrowth).TotalSeconds -ge $StallSeconds)
        if ($stalled -and (($now - $lastDump).TotalSeconds -ge $DumpEverySeconds) -and ($uploads -lt $MaxUploads)) {
            $sawStall = $true
            $lastDump = $now
            Request-Dump
            # The go command checks for a request every 5 seconds.
            Start-Sleep -Seconds 15
            $uploads++
            Send-Files $uploads
        }

        for ($i = 0; $i -lt 12 -and -not (Test-StopRequested); $i++) {
            Start-Sleep -Seconds 5
        }
    }
    Write-Log 'monitor exiting'
} catch {
    "=== $(Get-Now) UTC: $($_ | Out-String)" | Out-File -Append -Encoding utf8 $ErrorFile
}

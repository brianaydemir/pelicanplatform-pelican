# Write kernel stacks from a live kernel dump, for debugging test runs that
# hang on Windows: those of the go command, gotestsum, the runner, and
# Defender's engine, with wait reasons, then every thread's. For each
# go.exe thread in a WrVirtualMemory wait, also describe the object it
# waits on. Needs livedump.exe (see livedump.go) and kd.exe, and symbols
# through _NT_SYMBOL_PATH.

param(
    [Parameter(Mandatory)][string]$OutFile,
    [string]$LiveDump = $env:LIVEDUMP,
    [string]$Kd = $env:KD,
    [string]$DumpFile = (Join-Path $env:RUNNER_TEMP 'live.dmp'),
    [int]$TimeoutSeconds = 900
)

function Write-Out([string]$Message) {
    "=== $((Get-Date).ToUniversalTime().ToString('HH:mm:ss')) UTC: $Message" |
        Out-File -Append -Encoding utf8 $OutFile
}

# Run a program with a time limit, appending its output to OutFile.
function Invoke-Logged([string]$Path, [string]$Arguments) {
    $log = "$OutFile.tmp"
    $proc = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    if ($proc.WaitForExit($TimeoutSeconds * 1000)) {
        Write-Out "$(Split-Path -Leaf $Path) exited with $($proc.ExitCode)"
    } else {
        $proc.Kill()
        Write-Out "$(Split-Path -Leaf $Path) timed out after $TimeoutSeconds seconds"
    }
    foreach ($f in @($log, "$log.err")) {
        if (Test-Path $f) {
            Get-Content $f | Out-File -Append -Encoding utf8 -Width 1000 $OutFile
            Remove-Item $f
        }
    }
}

# kd matches the image name stored in the kernel, which is cut at 14
# characters.
$commands = @(
    '!process 0 17 go.exe'
    '!process 0 17 gotestsum.exe'
    '!process 0 17 Runner.Worker.'
    '!process 0 17 MsMpEng.exe'
    '!locks'
    '!fltkd.filters'
    '!stacks 2'
)

try {
    Write-Out "writing a live kernel dump to $DumpFile"
    Invoke-Logged $LiveDump "`"$DumpFile`""
    if (-not (Test-Path $DumpFile) -or (Get-Item $DumpFile).Length -eq 0) {
        Write-Out 'no dump to read'
        return
    }
    Write-Out ('dump size: {0:N0} MB' -f ((Get-Item $DumpFile).Length / 1MB))

    $start = (Get-Item $OutFile).Length
    Invoke-Logged $Kd "-z `"$DumpFile`" -c `"$(($commands + 'q') -join '; ')`""

    # The wait objects follow the WAIT line of each thread, as in
    #   THREAD ffff... Cid 1b6c.04a0 ... WAIT: (WrVirtualMemory) KernelMode Non-Alertable
    #       ffff9e8c3a1f6a28  NotificationEvent
    $stream = [System.IO.File]::OpenRead((Resolve-Path $OutFile))
    try {
        $stream.Position = $start
        $text = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
    } finally {
        $stream.Close()
    }
    $goText = ($text -split 'kd> !process 0 17 gotestsum')[0]
    $pattern = 'WAIT: \(WrVirtualMemory\)[^\n]*\n\s+([0-9a-f]{8}`?[0-9a-f]{8})'
    $objects = @([regex]::Matches($goText, $pattern) |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique -First 4)
    if ($objects.Count -gt 0) {
        $more = $objects | ForEach-Object { "!pool $_ 2"; "dt nt!_KEVENT $_"; "dps $_-0x40 L20" }
        Write-Out "describing the objects of WrVirtualMemory waits: $($objects -join ' ')"
        Invoke-Logged $Kd "-z `"$DumpFile`" -c `"$(($more + 'q') -join '; ')`""
    }
} catch {
    Write-Out ($_ | Out-String)
} finally {
    Remove-Item -ErrorAction SilentlyContinue $DumpFile
    Write-Out 'done'
}

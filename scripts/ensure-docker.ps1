[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 90
)

function Test-DockerDaemonReady {
    $out = (& docker info 2>&1) -join "`n"
    $code = $LASTEXITCODE
    $failed = $out.Contains("failed to connect")
    $hasServer = $out.Contains("Server Version")
    if ($code -eq 0 -and -not $failed -and $hasServer) {
        return $true
    }
    return $false
}

Write-Host "==> Checking Docker daemon status..." -ForegroundColor Cyan

# Test if Docker daemon is already responding
if (Test-DockerDaemonReady) {
    Write-Host "[OK] Docker daemon is running and ready." -ForegroundColor Green
    exit 0
}

Write-Host "[INFO] Docker daemon is not responding. Searching for Docker Desktop..." -ForegroundColor Yellow

$candidatePaths = @(
    "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
    "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
    "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
)

$dockerDesktopPath = $null
foreach ($path in $candidatePaths) {
    if (Test-Path $path) {
        $dockerDesktopPath = $path
        break
    }
}

if (-not $dockerDesktopPath) {
    Write-Error "[FAIL] Docker daemon is not active and Docker Desktop executable could not be found."
    exit 1
}

# Check if process is already running
$runningProc = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
if (-not $runningProc) {
    Write-Host "[INFO] Launching Docker Desktop from: $dockerDesktopPath" -ForegroundColor Yellow
    Start-Process -FilePath $dockerDesktopPath
} else {
    Write-Host "[INFO] Docker Desktop process is already running, waiting for daemon engine initialization..." -ForegroundColor Yellow
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "==> Waiting for Docker daemon to become responsive (timeout: ${TimeoutSeconds}s)..." -ForegroundColor Cyan

while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    $ready = Test-DockerDaemonReady
    if ($ready) {
        $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Write-Host "`n[OK] Docker daemon successfully started and ready in ${elapsed}s." -ForegroundColor Green
        exit 0
    }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 3
}

Write-Error "`n[FAIL] Timed out waiting for Docker daemon after $TimeoutSeconds seconds."
exit 1

[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 60
)

$services = @("pentefino_postgres", "pentefino_valkey", "pentefino_seaweedfs", "pentefino_rabbitmq")
Write-Host "==> Polling health status for PenteFino infrastructure services..." -ForegroundColor Cyan

$sw = [System.Diagnostics.Stopwatch]::StartNew()

while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    $allHealthy = $true
    $statuses = @()

    foreach ($svc in $services) {
        $statusRaw = docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $svc 2>$null
        $status = if ($null -ne $statusRaw) { $statusRaw.Trim() } else { "not_found" }
        $statuses += "$svc=$status"
        if ($status -ne "healthy") {
            $allHealthy = $false
        }
    }

    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 0)
    Write-Host "[$($elapsed)s] $($statuses -join ', ')"

    if ($allHealthy) {
        Write-Host "`n[SUCCESS] All 4 PenteFino infrastructure services are HEALTHY!" -ForegroundColor Green

        # Ensure default 'evidence' bucket exists in SeaweedFS Filer
        Write-Host "==> Verifying SeaweedFS 'evidence' bucket..." -ForegroundColor Cyan
        try {
            $bucketUri = "http://127.0.0.1:8888/buckets/evidence/"
            $check = Invoke-WebRequest -Uri $bucketUri -Method Get -UseBasicParsing -ErrorAction SilentlyContinue
            if ($check.StatusCode -eq 200) {
                Write-Host "[OK] Default bucket 'evidence' verified in SeaweedFS." -ForegroundColor Green
            } else {
                $null = & curl.exe -s -X POST $bucketUri 2>&1
                Write-Host "[OK] Default bucket 'evidence' created in SeaweedFS." -ForegroundColor Green
            }
        } catch {
            $null = & curl.exe -s -X POST "http://127.0.0.1:8888/buckets/evidence/" 2>&1
            Write-Host "[OK] Default bucket 'evidence' initialized in SeaweedFS." -ForegroundColor Green
        }

        exit 0
    }

    Start-Sleep -Seconds 3
}

Write-Error "`n[FAIL] Healthcheck timeout exceeded (${TimeoutSeconds}s). Dumping container logs:"
foreach ($svc in $services) {
    Write-Host "--- Container Logs: $svc ---" -ForegroundColor Red
    docker logs --tail 25 $svc 2>&1
}
exit 1

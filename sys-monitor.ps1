Clear-Host

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

Write-Host "================================="
Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
Write-Host "================================="

# Get user credentials
$cred = Get-Credential
$username = $cred.UserName
$password = $cred.GetNetworkCredential().Password

# Extract domain and username
if ($username -like "*\*") {
    $domain, $user = $username -split "\\", 2
} elseif ($username -like "*@*") {
    $user, $domain = $username -split "@", 2
} else {
    Write-Host "Username must include domain (e.g., domain\\user or user@domain.com)" -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}

try {
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain, $user, $password)
    $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $user)

    if ($userPrincipal -eq $null) {
        Write-Host "User not found or incorrect login information." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }

    $isAdmin = $false
    foreach ($group in $userPrincipal.GetAuthorizationGroups()) {
        if ($group.Name -eq "Domain Admins") {
            $isAdmin = $true
            break
        }
    }

    if (-not $isAdmin) {
        Write-Host "User is not a member of the Domain Admins group. Access denied." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        exit
    }

    # Start server selection
    do {
        Clear-Host
        Write-Host "================================="
        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
        Write-Host "================================="
        $server = Read-Host "`nPlease enter the IP address of the target server"
        if ($server -eq "q") { break }

        if ([string]::IsNullOrEmpty($server)) {
            Write-Host "Server IP address must be provided." -ForegroundColor Red
            continue
        }

        # Check if the server and WinRM are accessible
        if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet)) {
            Write-Host "Server $server is unreachable or turned off." -ForegroundColor Red
            continue
        }

        try {
            Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Error: WinRM is not available on $server or the port is blocked." -ForegroundColor Red
            continue
        }

        # Add to TrustedHosts
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$((Get-Item WSMan:\localhost\Client\TrustedHosts).Value),$server" -Force

        # Main menu
        do {
            Write-Host ""
            Write-Host "s.  Show running services"
            Write-Host "st. Show stopped services"
            Write-Host "p.  Show CPU/RAM usage"
            Write-Host "pc. Show CPU proccess count"
            Write-Host "d.  Show disk space"
            Write-Host "u.  Show users"
            Write-Host "c.  Change server"
            Write-Host "q.  Exit completely"
            $choice = Read-Host "Please select an option (s/st/p/pc/d/u/c/q)"

            if ($choice -eq "c") { break }
            elseif ($choice -eq "q") { exit }

            Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
                param($choice)
                switch ($choice) {
                    "s" {
                        $services = Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object DisplayName | Format-Table -AutoSize
                        $services
                        $serviceName = Read-Host "Please enter the service name to control"
                        $service = Get-Service | Where-Object {$_.ServiceName -eq $serviceName}
                        if ($service) {
                            $action = Read-Host "What operation would you like to perform? (stop/restart)"
                            switch ($action) {
                                "stop"    {
                                    Stop-Service -Name $serviceName;
                                    Clear-Host
                                    Write-Host "================================="
                                    Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                    Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                    Write-Host "================================="
                                    Write-Host "$serviceName stopped." -ForegroundColor Red }
                                "restart" {
                                    Restart-Service -Name $serviceName ;
                                    Clear-Host
                                    Write-Host "================================="
                                    Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                    Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                    Write-Host "================================="
                                    Write-Host "$serviceName restarted." -ForegroundColor Yellow }
                                default   {
                                    Clear-Host
                                    Write-Host "================================="
                                    Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                    Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                    Write-Host "================================="
                                    Write-Host "Invalid operation." -ForegroundColor Red }
                            }
                        } else {
                            Clear-Host
                            Write-Host "================================="
                            Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                            Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                            Write-Host "================================="
                            Write-Host "Service not found." -ForegroundColor Red
                        }
                    }
                    "st" {
                        Get-Service | Where-Object {$_.Status -eq "Stopped"} | Sort-Object DisplayName | Format-Table -AutoSize
                        $service = Read-Host "`nEnter service name to start"
                        if ($service) {
                            Start-Service -Name $service
                            Clear-Host
                            Write-Host "================================="
                            Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                            Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                            Write-Host "================================="
                            Write-Host "Service $service started." -ForegroundColor Green
                        }

                        
                    }
                    "p" {
                        $os = Get-WmiObject Win32_OperatingSystem
                        $totalMemoryMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
                        $cpu1 = Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet
                        Start-Sleep -Seconds 1
                        $cpu2 = Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet
                        $results = foreach ($proc in $cpu2) {
                            $prev = $cpu1 | Where-Object { $_.Id -eq $proc.Id }
                            if ($prev) {
                                $cpuDelta = $proc.CPU - $prev.CPU
                                $cpuPercent = [math]::Round(($cpuDelta / 1) * 100 / (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors, 2)
                                $ramMB = [math]::Round($proc.WorkingSet / 1MB, 2)
                                $ramPercent = [math]::Round(($ramMB / $totalMemoryMB) * 100, 2)
                                [PSCustomObject]@{
                                    PID       = $proc.Id
                                    Name      = $proc.ProcessName
                                    "CPU(%)"  = $cpuPercent
                                    "RAM(MB)" = $ramMB
                                    "RAM(%)"  = $ramPercent
                                }
                            }
                        }
                        $results | Sort-Object "CPU(%)" -Descending | Format-Table -AutoSize
                        $kill = Read-Host "Do you want to close a process? (y/n)"
                        if ($kill -eq "y") {
                            $targetPid = Read-Host "Enter PID"
                            try {
                                Start-Process "taskkill.exe" -ArgumentList "/PID $targetPid /F" -NoNewWindow -Wait
                                Write-Host "Process $targetPid closed." -ForegroundColor Green

                                Clear-Host
                                Write-Host "================================="
                                Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                Write-Host "================================="

                            } catch {
                                Clear-Host
                                Write-Host "================================="
                                Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                Write-Host "================================="
                                Write-Host "Error closing process: $_" -ForegroundColor Red
                            }
                        }
                        Clear-Host
                        Write-Host "================================="
                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                        Write-Host "================================="
                    }
                    "pc" {
                        Clear-Host
                        Write-Host "================================="
                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                        Write-Host "================================="
                        # Counting the number of occurrences of each process
                        $procCounts = Get-Process | Group-Object ProcessName | Select-Object Name, @{Name="Count";Expression={($_.Count)}}
                        $procCounts | Sort-Object Count -Descending | Format-Table -AutoSize
                    }
                    "d" {
                        Clear-Host
                        Write-Host "================================="
                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                        Write-Host "================================="
                        Get-PSDrive -PSProvider 'FileSystem' | Select-Object Name,
                        @{Name="Size(GB)";Expression={[math]::Round(($_.Used + $_.Free) / 1GB,2)}},
                        @{Name="Free(GB)";Expression={[math]::Round($_.Free / 1GB,2)}} | Format-Table -AutoSize
                    }
                    "u" {
                        Clear-Host
                        Write-Host "================================="
                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                        Write-Host "================================="
                        $raw = query user
                        $raw | ForEach-Object { Write-Host $_ }

                        # Count logged-in users
                        $loggedInUsers = $raw | Where-Object { $_ -match '^\s*>?\s*(\S+)\s+(\S+)?\s+(\d+)\s' }
                        $count = $loggedInUsers.Count
                        Write-Host "`nNumber of logged-in users: $count" -ForegroundColor Cyan

                        $logoutChoice = Read-Host "`nPress L to log off all users or press Enter to go back"
                        if ($logoutChoice -eq "L") {
                            $excludedUsers = @("administrator", "otherUserName")
                            $sessions = $raw | ForEach-Object {
                                if ($_ -match '^\s*>?\s*(\S+)\s+(\S+)?\s+(\d+)\s') {
                                    $line = ($_ -replace '^\s*>?\s*', '') -replace '\s{2,}', '|' -split '\|'
                                    if ($line.Length -ge 3) {
                                        [PSCustomObject]@{
                                            User = $line[0].Trim()
                                            ID   = $line[2].Trim()
                                        }
                                    }
                                }
                            }

                            foreach ($s in $sessions) {
                                $username = $s.User -replace '^>', ''
                                $username = $username.ToLower()
                                Write-Host "Checking user: '$username'"
                                if ($username -and -not ($excludedUsers -contains $username)) {
                                    try {
                                        logoff $s.ID /V

                                        Clear-Host
                                        Write-Host "================================="
                                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                        Write-Host "================================="

                                        Write-Host "User $($s.User) logged off successfully." -ForegroundColor Green
                                    } catch {
                                        Clear-Host
                                        Write-Host "================================="
                                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                        Write-Host "================================="
                                        Write-Host "Error logging off user $($s.User): $_" -ForegroundColor Red
                                    }
                                }
                            }
                        }
                    }

                    default {
                        Clear-Host
                        Write-Host "================================="
                        Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                        Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                        Write-Host "================================="
                        Write-Host "Invalid option." -ForegroundColor Red
                    }
                }
            } -ArgumentList $choice

        } while ($true)

    } while ($true)

} catch {
    Clear-Host
    Write-Host "================================="
    Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
    Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
    Write-Host "================================="
    Write-Host "Error checking user information: $_" -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}

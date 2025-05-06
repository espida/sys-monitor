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
    Start-Sleep -Seconds 8
    exit
}

try {
    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain, $user, $password)
    $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $user)

    if ($userPrincipal -eq $null) {
        Write-Host "User not found or incorrect login information." -ForegroundColor Red
        Start-Sleep -Seconds 8
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
        Start-Sleep -Seconds 8
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
                                    Stop-Service -Name $serviceName -Force;
                                    Clear-Host
                                    Write-Host "================================="
                                    Write-Host "  Created by: " -ForegroundColor Cyan -NoNewline
                                    Write-Host "S.Mohsen Hosseini" -ForegroundColor Red
                                    Write-Host "================================="
                                    Write-Host "$serviceName stopped." -ForegroundColor Red }
                                "restart" {
                                    Restart-Service -Name $serviceName -Force ;
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

                        # نمایش تعداد هر پردازش
                        $procCounts = Get-Process | Group-Object ProcessName | Select-Object Name, @{Name="Count";Expression={($_.Count)}}
                        $procCounts | Sort-Object Count -Descending | Format-Table -AutoSize

                        # تعداد کل پردازش‌ها
                        $allProcs = Get-Process
                        Write-Host "Total process count: $($allProcs.Count)" -ForegroundColor Cyan

                        # اطلاعات RAM سیستم
                        $os = Get-CimInstance Win32_OperatingSystem
                        $totalGB = [math]::Round($os.TotalVisibleMemorySize * 1KB / 1GB, 2)
                        $freeGB = [math]::Round($os.FreePhysicalMemory * 1KB / 1GB, 2)
                        $usedGB = [math]::Round($totalGB - $freeGB, 2)
                        $percentUsedRAM = [math]::Round(($usedGB / $totalGB) * 100, 2)

                        # دریافت درصد مصرف CPU به صورت لحظه‌ای
                        $cpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
                        $cpuUsage = [math]::Round($cpuUsage, 2)

                        # نمایش اطلاعات RAM و CPU
                        Write-Host "---------------------------------" -ForegroundColor DarkGray
                        Write-Host "Total system RAM:  $totalGB GB" -ForegroundColor Green
                        Write-Host "Free system RAM:   $freeGB GB" -ForegroundColor Cyan
                        Write-Host "Used system RAM:   $usedGB GB" -ForegroundColor Yellow
                        Write-Host "RAM usage:         $percentUsedRAM %" -ForegroundColor Magenta
                        Write-Host "CPU usage:         $cpuUsage %" -ForegroundColor Red
                        Write-Host "---------------------------------" -ForegroundColor DarkGray
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
                        $users = @()
                        $index = 0

                        Write-Host "`nLogged-in Users:"
                        Write-Host "---------------------------------"
                        $raw | ForEach-Object {
                            Write-Host $_

                            if ($_ -match '^\s*>?\s*(\S+)\s+(\S+)?\s+(\d+)\s') {
                                $line = ($_ -replace '^\s*>?\s*', '') -replace '\s{2,}', '|' -split '\|'
                                if ($line.Length -ge 3) {
                                    $users += [PSCustomObject]@{
                                        Index = $index
                                        User  = $line[0].Trim()
                                        ID    = $line[2].Trim()
                                    }
                                    $index++
                                }
                            }
                        }

                        Write-Host "`nNumber of logged-in users: $($users.Count)" -ForegroundColor Cyan

                        Write-Host "`nOptions:"
                        Write-Host "L - Log off ALL users (except administrator/otherUser)"
                        Write-Host "T - Log off a single user"
                        Write-Host "Press Enter to go back"

                        $logoutChoice = Read-Host "`nChoose an option"

                        $excludedUsers = @("administrator", "otherUser")

                        if ($logoutChoice -eq "L") {
                            foreach ($s in $users) {
                                $username = $s.User.ToLower()
                                if (-not ($excludedUsers -contains $username)) {
                                    try {
                                        logoff $s.ID /V
                                        Write-Host "User $($s.User) logged off successfully." -ForegroundColor Green
                                    } catch {
                                        Write-Host "Error logging off user $($s.User): $_" -ForegroundColor Red
                                    }
                                }
                            }
                        } elseif ($logoutChoice -eq "T") {
                            Write-Host "`nSelect a user to log off:"
                            foreach ($s in $users) {
                                Write-Host "$($s.Index)) $($s.User) (Session ID: $($s.ID))"
                            }

                            $selectedIndex = Read-Host "Enter the index of the user you want to log off"
                            if ($selectedIndex -match '^\d+$' -and $selectedIndex -lt $users.Count) {
                                $targetUser = $users[$selectedIndex]
                                $username = $targetUser.User.ToLower()

                                if ($excludedUsers -contains $username) {
                                    Write-Host "Cannot log off excluded user: $($targetUser.User)" -ForegroundColor Yellow
                                } else {
                                    try {
                                        logoff $targetUser.ID /V
                                        Write-Host "User $($targetUser.User) logged off successfully." -ForegroundColor Green
                                    } catch {
                                        Write-Host "Error logging off user $($targetUser.User): $_" -ForegroundColor Red
                                    }
                                }
                            } else {
                                Write-Host "Invalid selection." -ForegroundColor Red
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
    Start-Sleep -Seconds 8
    exit
}

# Kiểm tra quyền admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Script cần được chạy với quyền Administrator. Vui lòng chạy lại với quyền admin."
    exit
}

# Cấu hình
$sshKeyType = "rsa"
$sshKeyLength = 4096
$configPath = "$PSScriptRoot\config.json"

# Hàm ghi log
function Write-Log {
    param([string]$message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    Write-Host $logMessage
    Add-Content -Path "$PSScriptRoot\setupSSH.log" -Value $logMessage
}

# Hàm đọc cấu hình
function Read-Config {
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
    } else {
        $config = @{
            remoteUser = "tanduy"
            yourEmail = "ng.duy1003@gmail.com"
            recipientEmail = "ng.duy1003@gmail.com"
            smtpServer = "smtp.gmail.com"
            smtpPort = 587
            emailPassword = "dvsp zsku uisi cszc"
            wakeUpTime = "23:00"
            shutdownTime = "03:00"
        }
        $config | ConvertTo-Json | Set-Content $configPath
    }
    return $config
}

# Hàm cập nhật script từ repository
function Update-Script {
    $repoUrl = "https://raw.githubusercontent.com/mihnmaxx/trinh_dieu_khien_may_tinh/refs/heads/main/trinh_dieu_khien_may_tinh/setupSSH.ps1"
    $tempFile = "$env:TEMP\setupSSH_new.ps1"
    
    try {
        Invoke-WebRequest -Uri $repoUrl -OutFile $tempFile
        if (Compare-Object -ReferenceObject (Get-Content $PSCommandPath) -DifferenceObject (Get-Content $tempFile)) {
            Copy-Item -Path $tempFile -Destination $PSCommandPath -Force
            Write-Log "Script đã được cập nhật. Vui lòng khởi động lại script."
            exit
        } else {
            Write-Log "Script đã là phiên bản mới nhất."
        }
    } catch {
        Write-Log "Lỗi khi cập nhật script: $_"
    } finally {
        Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
    }
}

# Hàm tạo hoặc cập nhật tác vụ lập lịch
function Set-CustomScheduledTask {
    param(
        [string]$TaskName,
        [string]$Description,
        [string]$Command,
        [string]$Arguments,
        [Microsoft.PowerShell.Scheduling.ScheduledTaskTrigger]$Trigger
    )
    
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Đã xóa tác vụ '$TaskName' cũ để cập nhật"
    }
    
    $action = New-ScheduledTaskAction -Execute $Command -Argument $Arguments
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName $TaskName -Description $Description -Action $action -Trigger $Trigger -Settings $settings -Principal $principal -Force
    Write-Log "Tác vụ '$TaskName' đã được tạo/cập nhật thành công"
}

# Hàm sao lưu cấu hình SSH
function Backup-SSHConfig {
    $backupPath = "$PSScriptRoot\ssh_backup_$(Get-Date -Format 'yyyyMMddHHmmss').zip"
    Compress-Archive -Path "$HOME\.ssh" -DestinationPath $backupPath
    Write-Log "Đã sao lưu cấu hình SSH vào $backupPath"
}

# Hàm khôi phục cấu hình SSH
function Restore-SSHConfig {
    $latestBackup = Get-ChildItem "$PSScriptRoot\ssh_backup_*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestBackup) {
        Expand-Archive -Path $latestBackup.FullName -DestinationPath "$HOME\.ssh" -Force
        Write-Log "Đã khôi phục cấu hình SSH từ $($latestBackup.FullName)"
    } else {
        Write-Log "Không tìm thấy bản sao lưu cấu hình SSH"
    }
}

# Hàm gửi báo cáo trạng thái hệ thống
function Send-SystemStatusReport {
    param($config)
    $sshStatus = Test-NetConnection -ComputerName localhost -Port 22
    if ($sshStatus.TcpTestSucceeded) {
        $statusText = "Đang chạy"
    } else {
        $statusText = "Không chạy"
    }
    $report = @"
Báo cáo trạng thái hệ thống
---------------------------
Ngày: $(Get-Date)
Tên máy: $env:COMPUTERNAME
Địa chỉ IP: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Ethernet*" }).IPAddress)
IP công cộng: $((Invoke-WebRequest -Uri "http://ifconfig.me/ip" -UseBasicParsing).Content)
Trạng thái SSH: $statusText
Dung lượng ổ đĩa: $((Get-PSDrive C).Free / 1GB) GB trống
Bộ nhớ: $((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB) GB trống
"@

    $securePassword = ConvertTo-SecureString $config.emailPassword -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential ($config.yourEmail, $securePassword)

    Send-MailMessage -From $config.yourEmail -To $config.recipientEmail -Subject "Báo cáo trạng thái hệ thống" -Body $report -SmtpServer $config.smtpServer -Port $config.smtpPort -UseSsl -Credential $credentials
    Write-Log "Đã gửi báo cáo trạng thái hệ thống"
}

# Hàm thực hiện với cơ chế retry
function Invoke-WithRetry {
    param(
        [ScriptBlock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5
    )
    
    $attempt = 1
    $success = $false
    
    while (-not $success -and $attempt -le $MaxAttempts) {
        try {
            & $ScriptBlock
            $success = $true
        } catch {
            Write-Log "Lần thử $attempt thất bại: $_"
            if ($attempt -lt $MaxAttempts) {
                Write-Log "Thử lại sau $DelaySeconds giây..."
                Start-Sleep -Seconds $DelaySeconds
            }
            $attempt++
        }
    }
    
    if (-not $success) {
        throw "Thao tác thất bại sau $MaxAttempts lần thử"
    }
}

# Hàm chính
function Main {
    try {
        Write-Log "Bắt đầu thiết lập SSH"
        
        Update-Script
        
        $config = Read-Config
        
        # Cài đặt mô-đun gửi email nếu chưa có
        if (-not (Get-Module -ListAvailable -Name PSSendMail)) {
            Install-Module -Name PSSendMail -Force -Scope CurrentUser
            Write-Log "Đã cài đặt mô-đun PSSendMail"
        }
        
        # Lấy thông tin mạng tự động
        $networkInfo = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Ethernet*" }
        $ipv4 = $networkInfo.IPAddress
        $subnetMask = $networkInfo.PrefixLength
        $defaultGateway = (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" }).NextHop
        Write-Log "Đã lấy thông tin mạng"
        
        Invoke-WithRetry -ScriptBlock {
            # Tạo cặp khóa SSH nếu chưa tồn tại
            $sshKeyPath = "$HOME\.ssh\id_$sshKeyType"
            if (-not (Test-Path -Path $sshKeyPath)) {
                ssh-keygen -t $sshKeyType -b $sshKeyLength -f $sshKeyPath -q -N ""
                Write-Log "Đã tạo cặp khóa SSH mới"
            }
            
            # Sao chép khóa công khai vào máy chủ
            $publicKeyPath = "$sshKeyPath.pub"
            $publicKey = Get-Content -Path $publicKeyPath
            $session = New-PSSession -HostName $ipv4 -UserName $config.remoteUser
            Invoke-Command -Session $session -ScriptBlock {
                param($publicKey)
                $authorizedKeysPath = "$HOME\.ssh\authorized_keys"
                if (-not (Test-Path -Path $authorizedKeysPath)) {
                    New-Item -ItemType File -Path $authorizedKeysPath -Force
                }
                Add-Content -Path $authorizedKeysPath -Value $publicKey
            } -ArgumentList $publicKey
            Remove-PSSession -Session $session
            Write-Log "Đã sao chép khóa công khai vào máy chủ"
            
            # Kiểm tra kết nối SSH
            $testConnection = ssh -o BatchMode=yes -o ConnectTimeout=5 $config.remoteUser@$ipv4 echo "Kết nối SSH thành công"
            if ($testConnection -eq "Kết nối SSH thành công") {
                Write-Log "Kiểm tra kết nối SSH thành công"
            } else {
                throw "Kiểm tra kết nối SSH thất bại"
            }
        }
        
        # Tạo nội dung email chi tiết
        $emailBody = @"
        Khóa SSH đã được thiết lập thành công trên $ipv4.

        Thông tin mạng:
        Địa chỉ IPv4: $ipv4
        Subnet Mask: $subnetMask
        Default Gateway: $defaultGateway
        IP công cộng: $((Invoke-WebRequest -Uri "http://ifconfig.me/ip" -UseBasicParsing).Content)

        Thông tin hệ thống:
        Tên máy tính: $env:COMPUTERNAME
        Người dùng hiện tại: $env:USERNAME
        Người dùng từ xa: $($config.remoteUser)

        Lệnh kết nối SSH:
        ssh $($config.remoteUser)@$((Invoke-WebRequest -Uri "http://ifconfig.me/ip" -UseBasicParsing).Content)

        Lưu ý: Đảm bảo rằng cổng 22 đã được mở trên router và được chuyển tiếp đến $ipv4 để truy cập SSH từ bên ngoài.

        Vị trí khóa SSH:
        Khóa công khai: $publicKeyPath
        Khóa riêng tư: $sshKeyPath

        Vui lòng giữ khóa riêng tư an toàn và không chia sẻ với người khác.
"@

        # Gửi email
        $securePassword = ConvertTo-SecureString $config.emailPassword -AsPlainText -Force
        $credentials = New-Object System.Management.Automation.PSCredential ($config.yourEmail, $securePassword)

        Invoke-WithRetry -ScriptBlock {
            Send-MailMessage -From $config.yourEmail -To $config.recipientEmail -Subject "Khóa SSH & Thông tin mạng chi tiết" -Body $emailBody -SmtpServer $config.smtpServer -Port $config.smtpPort -UseSsl -Credential $credentials
            Write-Log "Email đã được gửi thành công"
        }
        
        Backup-SSHConfig
        
        # Thiết lập các tác vụ lập lịch
        Set-CustomScheduledTask -TaskName "SetupSSH_AutoRun" -Description "Chạy thiết lập SSH khi khởi động" -Command "powershell.exe" -Arguments "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Trigger (New-ScheduledTaskTrigger -AtStartup)
        Set-CustomScheduledTask -TaskName "WakeUpComputer" -Description "Đánh thức máy tính lúc $($config.wakeUpTime)" -Command "powershell.exe" -Arguments "-Command &{Start-Sleep -Seconds 1}" -Trigger (New-ScheduledTaskTrigger -Daily -At $config.wakeUpTime)
        Set-CustomScheduledTask -TaskName "ShutdownComputer" -Description "Tắt máy tính lúc $($config.shutdownTime)" -Command "shutdown.exe" -Arguments "/s /f /t 0" -Trigger (New-ScheduledTaskTrigger -Daily -At $config.shutdownTime)
        Set-CustomScheduledTask -TaskName "SystemStatusReport" -Description "Gửi báo cáo trạng thái hệ thống hàng ngày" -Command "powershell.exe" -Arguments "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -ReportOnly" -Trigger (New-ScheduledTaskTrigger -Daily -At "12:00")
        
        # Tích hợp với hệ thống giám sát (ví dụ sử dụng API giả định)
        $monitoringApiUrl = "http://127.0.0.1:5000/api/update-ssh-status"
        $sshStatus = Test-NetConnection -ComputerName localhost -Port 22
        Invoke-RestMethod -Uri $monitoringApiUrl -Method Post -Body @{status = $sshStatus.TcpTestSucceeded; hostname = $env:COMPUTERNAME}
        Write-Log "Đã cập nhật trạng thái SSH trong hệ thống giám sát"
        
        Send-SystemStatusReport -config $config
        
        Write-Log "Thiết lập hoàn tất thành công"
    } catch {
        Write-Log "Đã xảy ra lỗi trong quá trình thiết lập: $_"
        Restore-SSHConfig
    }
}

# Kiểm tra xem script có được chạy với tham số -ReportOnly hay không
if ($args[0] -eq "-ReportOnly") {
    $config = Read-Config
    Send-SystemStatusReport -config $config
} else {
    Main
}
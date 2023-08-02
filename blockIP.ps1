# Configuration variables
$MaxFailedAttempts = 3    # Number of failed attempts before permanently blocking the IP
$RdpPort = 3389           # RDP port number


while ($true) {

    # Get the failed RDP login attempts from the Security event log
    $failedAttempts = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4625
        StartTime = (Get-Date).AddHours(-0.25)  # Specify the desired time range for failed login attempts
    } | ForEach-Object {
        $ip = $_.Properties[19].Value    # The IP address might be in a different property, check the event data
        if ($ip -ne $null) { $ip }
    } 

    # Group the IP addresses and count the number of failed attempts for each IP
    $failedAttemptsCount = $failedAttempts | Group-Object | ForEach-Object {
        [PSCustomObject]@{
            IP       = $_.Name
            Attempts = $_.Count
        }
    }

    # Block IP addresses with the number of failed attempts exceeding the threshold permanently
    $failedAttemptsCount | Where-Object { $_.Attempts -ge $MaxFailedAttempts } | ForEach-Object {
        $ip = $_.IP
        
            Write-Host "Permanently blocking IP: $ip"
            netsh advfirewall firewall add rule name="Block $ip" dir=in action=block enable=yes protocol=TCP localport=$RdpPort remoteip=$ip
            netsh advfirewall firewall add rule name="Block $ip" dir=in action=block enable=yes protocol=UDP localport=$RdpPort remoteip=$ip
        
    }
    #Add a delay before running the script again (adjust the delay time as needed)
    Start-Sleep -Seconds (15 * 60)
    }

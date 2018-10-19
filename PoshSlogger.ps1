# Scriptname: PowerMon
# Date: June 2018
# Author: Jeenkins - https://github.com/Jeenkins/
# Description: Monitor multiple Event Logs, and send each event via syslog using PowerShell
#
# Using Send-Syslog function from https://github.com/poshsecurity/Posh-SYSLOG
#
# This script should be configured to run as a scheduled task at boot up, or as a service.
# Must be run with admin privileges, or with an account which can access the Sysmon logs. 
# 
# Script can be utilised to send any Event log, however at the moment its configured to send the Sysmon logs.
#
# A registry key is used to store the record of the last event record ID sent.
#
# The following items can be set below in the script..
#
# Syslog server to send logs to
# $ServerName = "127.0.0.1"
# $UDPPort = 514
#
# Configure the name of the event log you want to monitor
# $LogToMonitor = "Microsoft-Windows-Sysmon/Operational"
#
# Location of last log data
# $registryPath = "HKLM:\Software\LogMonitor\LastLogData"
# The name of the string will be the name of the log file being monitorer ($LogToMonitor)
#
# Time in seconds to sleep in between log sends (somewhere between 30-120 seconds recommended). 30 seconds is the default.
# $SleepPeriod = "30"
#
# Max events to pull each time (somewhere between 500-5000 depending on time out time and system usage.) 300 is the default
# $MaxEvents = "300"


##########################
###    Script start    ###
##########################

#requires -Version 2 -Modules NetTCPIP
Add-Type -TypeDefinition @" 
 public enum Syslog_Facility 
 { 
  kern, 
  user, 
  mail, 
  daemon, 
  auth, 
  syslog, 
  lpr, 
  news, 
  uucp, 
  clock, 
  authpriv, 
  ftp, 
  ntp, 
  logaudit, 
  logalert, 
  cron, 
  local0, 
  local1, 
  local2, 
  local3, 
  local4, 
  local5, 
  local6, 
  local7, 
 } 
"@

Add-Type -TypeDefinition @" 
 public enum Syslog_Severity 
 { 
  Emergency, 
  Alert, 
  Critical, 
  Error, 
  Warning, 
  Notice, 
  Informational, 
  Debug 
 } 
"@

function Send-SyslogMsg
{

    #>
    [CMDLetBinding(DefaultParameterSetName = 'RFC5424')]
    Param
    (
        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] 
        $Server,

        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Message,

        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Syslog_Severity]
        $Severity,

        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Syslog_Facility] 
        $Facility,

        [Parameter(mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Hostname = '',

        [Parameter(mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ApplicationName = '',

        [Parameter(mandatory = $false, ParameterSetName = 'RFC5424')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProcessID = $PID,

        [Parameter(mandatory = $false, ParameterSetName = 'RFC5424')]
        [ValidateNotNullOrEmpty()]
        [String]
        $MessageID = '-',

        [Parameter(mandatory = $false, ParameterSetName = 'RFC5424')]
        [ValidateNotNullOrEmpty()]
        [String]
        $StructuredData = '-',

        [Parameter(mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [DateTime] 
        $Timestamp = (Get-Date),

        [Parameter(mandatory = $True, ParameterSetName = 'RFC3164')]
        [switch]
        $RFC3164
    )

    # Evaluate the facility and severity based on the enum types
    $Facility_Number = $Facility.value__
    $Severity_Number = $Severity.value__

    # Calculate the priority
    $Priority = ($Facility_Number * 8) + $Severity_Number

    if ($PSCmdlet.ParameterSetName -eq 'RFC3164')
    {
        #Get the timestamp
        $FormattedTimestamp = (Get-Culture).TextInfo.ToTitleCase($Timestamp.ToString('MMM dd HH:mm:ss'))
        # Assemble the full syslog formatted Message
        $FullSyslogMessage = '<{0}>{1} {2} {3} {4}' -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $Message
    }
    else
    {
        #Get the timestamp
        $FormattedTimestamp = $Timestamp.ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz')
        # Assemble the full syslog formatted Message
        $FullSyslogMessage = '<{0}>1 {1} {2} {3} {4} {5} {6} {7}' -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $ProcessID, $MessageID, $StructuredData, $Message
    }

    # create an ASCII Encoding object
    $Encoding = [System.Text.Encoding]::ASCII

    # Convert into byte array representation
    $ByteSyslogMessage = $Encoding.GetBytes($FullSyslogMessage)

    # If the message is too long, shorten it
    if ($ByteSyslogMessage.Length -gt 1024)
    {
        #$ByteSyslogMessage = $ByteSyslogMessage.SubString(0, 1024)
         $ByteSyslogMessage = $ByteSyslogMessage -replace '(.{4}).+','$1'
    }

    # Create a UDP Client Object
    $UDPCLient = New-Object -TypeName System.Net.Sockets.UdpClient
    $UDPCLient.Connect($Server, $UDPPort)

    # Send the Message
    $null = $UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length)

    #Close the connection
    $UDPCLient.Close()
}


###################################
###         Set variables       ###
###################################

#syslog server to send logs to
$ServerName = "127.0.0.1"
$UDPPort = 514

#Location of last log data
$registryPath = "HKLM:\Software\PowerMon\LastLogData"

#time in seconds to sleep in between log sends (default = 30 seconds)
$SleepPeriod = "30" 

#Max events to pull each time (default = 300)
$MaxEvents = "300"

#Hard code log file to the sysmon event log
$LogsToMonitor = "Microsoft-Windows-Sysmon/Operational","Microsoft-Windows-TaskScheduler/Operational"



###################################
###     Start pre loop check    ###
###################################

#Write message to show new loop
$Time = Get-Date -Format "yyyMMdd hh:mm:ss"
Write-Host "[+] $Time : Checking if the registry key $registryPath exists..."

#Check if registry key exists, if not, sets it up
$Exists = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
    
If (($Exists -eq $null) -and ($Exists.Length -eq 0)) {
    $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
    Write-Host "[+] $Time : Registry path $registryPath doesn't exist...Setting it up."
    New-Item -Path $registryPath -Force | Out-Null

    } else {
    $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
    Write-Host "[+] $Time : Registry path $registryPath already exists.."
}


###################################
###     Start continous loop    ###
###################################

#start loop to continue monitoring for new logs
while($true){

#loop through each log in array
foreach ($LogToMonitor in $LogsToMonitor) {

    #Write message to show new loop
    $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
    Write-Host "[+] $Time : $LogToMonitor : Checking if the registry key for $LogToMonitor last log sent is set..."

    #Check if registry key exists, if not, sets it to current latest log to start colleciton from install point onwards
    $Exists = Get-ItemProperty -Path $registryPath -Name $LogToMonitor -ErrorAction SilentlyContinue
    
    #If not exist, set for first use
    If (($Exists -eq $null) -and ($Exists.Length -eq 0)) {
        $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
        Write-Host "[+] $Time : $LogToMonitor : Registry key $LogToMonitor doesn't exist...Setting it at the latest event record."
        $PreEvents =""
        $PreEvents = Get-WinEvent -LogName $LogToMonitor -MaxEvents 1 
        New-ItemProperty -Path $registryPath -Name $LogToMonitor -Value $PreEvents.RecordID -PropertyType STRING -Force | Out-Null
    
    } else {

        #Write message to show new loop
        $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
        Write-Host "[+] $Time : $LogToMonitor : Registry key $LogToMonitor already exists. Moving on to check logs."

        }


    #get latest log record from registry
    $StartPoint = (Get-ItemProperty -Path $registryPath -Name $LogToMonitor).$LogToMonitor

    #get latest 5000 events from the last sent record
    $Events = ""
    $Events = Get-WinEvent -LogName $LogToMonitor -MaxEvents $MaxEvents | Where-Object {$_.RecordID -ge ($StartPoint)}

    #msg       
    $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
    Write-Host "[+] $Time : $LogToMonitor : Compare start point and latest event in $LogToMonitor."

    #If startpoint and the latest record match, there are no new logs.
    If ($StartPoint -eq (($Events.RecordID | Measure -Maximum).Maximum) ) {
        
        $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
        Write-Host "[+] $Time : $LogToMonitor : Start point and latest event already match. No logs to send for $LogToMonitor."

        }
        
        else {
        
        #write how many logs to send
        $Time = Get-Date -Format "yyyMMdd hh:mm:ss"
        Write-Host "[+] $Time : $LogToMonitor : Start point is behind in $LogToMonitor. Sending total logs to get up to date:" $Events.count

        #loop thru each message and send each as syslog
        foreach ($Event in $Events) {Send-SyslogMsg -Server $ServerName -Message $Event.Message -Severity "Informational" -Facility ([Syslog_Facility]::logaudit) -Hostname $env:COMPUTERNAME -ApplicationName $LogToMonitor -Timestamp $Event.TimeCreated }

     }

    #Set last record for next loop
    $LastRecord = ($Events.RecordID | Measure -Maximum).Maximum
    New-ItemProperty -Path $registryPath -Name $LogToMonitor -Value $LastRecord -PropertyType STRING -Force | Out-Null


#end for loop
}

#sleep at end of cycle
$Time = Get-Date -Format "yyyMMdd hh:mm:ss"
Write-Host "[+] $Time : Sleeping for $SleepPeriod seconds..."; Write-Host " "
Start-Sleep -Seconds $SleepPeriod

#end continuous loop
}

Clear-Host
Write-Host " "
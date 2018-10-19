PoshSlogger
Author: Jeenkins - https://github.com/Jeenkins/
Description: Monitor multiple Event Logs, and send each event via syslog using PowerShell


Using Send-Syslog function from: 
https://github.com/poshsecurity/Posh-SYSLOG - Awesome :+1:

Posh-SYSLOG is provided under the MIT license. 
https://github.com/poshsecurity/Posh-SYSLOG/blob/master/LICENSE.MD


This script should be configured to run as a scheduled task at boot up, or as a service.
Must be run with admin privileges, or with an account which can access the Sysmon logs (system) 

Script can be utilised to send any Event log, however at the moment its configured to send the Sysmon logs.

A registry key is used to store the record of the last event record ID sent.

The following items can be set below in the script..

Syslog server to send logs to
$ServerName = "127.0.0.1"
$UDPPort = 514

Configure the name of the event log you want to monitor
$LogToMonitor = "Microsoft-Windows-Sysmon/Operational"

Location of last log data
$registryPath = "HKLM:\Software\LogMonitor\LastLogData"
The name of the string will be the name of the log file being monitorer ($LogToMonitor)

Time in seconds to sleep in between log sends (somewhere between 30-120 seconds recommended). 30 seconds is the default.
$SleepPeriod = "30"

Max events to pull each time (somewhere between 500-5000 depending on time out time and system usage.) 300 is the default
$MaxEvents = "300"

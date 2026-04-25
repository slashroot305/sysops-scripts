# check defender general status
$Get_DefenderStatus = {Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode}
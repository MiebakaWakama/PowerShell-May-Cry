Get-Process | Get-Member | Out-Host -Paging
Get-Process | Get-Member -MemberType Properties
import-module activedirectory
Get-CimInstance -Class Win32_LogicalDisk | Select-Object -Property Name,FreeSpace
Get-CimInstance -Class Win32_LogicalDisk |
  Select-Object -Property Name, @{
    label='FreeSpace'
    expression={($_.FreeSpace/1GB).ToString('F2')}
  }
  1,2,3,4,5,6,7 | Where-Object {$_ -lt 4}
Get-CimInstance -Class Win32_SystemDriver | Where-Object {$_.State -eq 'Running'}
Get-CimInstance -Class Win32_SystemDriver | Where-Object {$_.State -eq "Running"} | Where-Object {$_.StartMode -eq "Auto"}
Get-CimInstance -Class Win32_SystemDriver | Where-Object {$_.State -eq "Running"} | Where-Object {$_.StartMode -eq "Manual"} | Format-Table -Property Name,DisplayName
Get-CimInstance -Class Win32_SystemDriver | Where-Object {($_.State -eq 'Running') -and ($_.StartMode -eq 'Manual')} | Format-Table -Property Name,DisplayName
Get-ChildItem |
  Sort-Object -Property LastWriteTime, Name |
  Format-Table -Property LastWriteTime, Name
Get-ChildItem |
  Sort-Object -Property LastWriteTime, Name -Descending |
  Format-Table -Property LastWriteTime, Name
Get-ChildItem |
  Sort-Object -Property @{ Expression = 'LastWriteTime'; Descending = $true },
                        @{ Expression = 'Name'; Ascending = $true } |
  Format-Table -Property LastWriteTime, Name
Get-ChildItem |
  Sort-Object -Property @{ Expression = { $_.LastWriteTime - $_.CreationTime }; Descending = $true } |
  Format-Table -Property LastWriteTime, CreationTime
New-Object -TypeName System.Diagnostics.EventLog
New-Object -TypeName System.Diagnostics.EventLog -ArgumentList Application
$AppLog = New-Object -TypeName System.Diagnostics.EventLog -ArgumentList Application  
$RemoteAppLog = New-Object -TypeName System.Diagnostics.EventLog Application,127.0.0.1
$RemoteAppLog
$RemoteAppLog | Get-Member -MemberType Method
$RemoteAppLog.Clear()
$AppLog.Clear()
$a = 1,2,"three"
Get-Member -InputObject $a
$WshShell = New-Object -ComObject WScript.Shell
$WshShell | Get-Member
[System.Console]::beep(440, 500)
$ie = New-Object -ComObject InternetExplorer.Application
$ie.Visible = $true

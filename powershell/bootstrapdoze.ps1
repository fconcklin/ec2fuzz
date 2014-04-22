# Windows AMIs don't have WinRM enabled by default -- this script will enable WinRM
# AND install 7-zip, curl and .NET 4 if its missing.
# Then use the EC2 tools to create a new AMI from the result, and you have a system 
# that will execute user-data as a PowerShell script after the instance fires up!
# This has been tested on Windows 2008 SP2 64bits AMIs provided by Amazon
# 
# Inject this as user-data of a Windows 2008 AMI, like this (edit the adminPassword to your needs):
#
# <powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://gist.github.com/masterzen/6714787/raw')) -ArgumentList "adminPassword"
# </powershell>
#
param(
	[Parameter(Mandatory=$true)]
	[string]
	$AdminPassword
)

Start-Transcript -Path 'c:\bootstrap-transcript.txt' -Force
Set-StrictMode -Version Latest
Set-ExecutionPolicy Unrestricted

$log = 'c:\Bootstrap.txt'

while (($AdminPassword -eq $null) -or ($AdminPassword -eq ''))
{
	$AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty Administrator password" -AsSecureString)))
}


$systemPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$sysNative = [IO.Path]::Combine($env:windir, "sysnative")
#http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
$Is32Bit = (($Env:PROCESSOR_ARCHITECTURE -eq 'x86') -and ($Env:PROCESSOR_ARCHITEW6432 -eq $null))
Add-Content $log -value "Is 32-bit [$Is32Bit]"

#http://msdn.microsoft.com/en-us/library/ms724358.aspx
$coreEditions = @(0x0c,0x27,0x0e,0x29,0x2a,0x0d,0x28,0x1d)
$IsCore = $coreEditions -contains (Get-WmiObject -Query "Select OperatingSystemSKU from Win32_OperatingSystem" | Select -ExpandProperty OperatingSystemSKU)
Add-Content $log -value "Is Core [$IsCore]"

# move to home, PS is incredibly complex :)
cd $Env:USERPROFILE
Set-Location -Path $Env:USERPROFILE
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

#change admin password
net user Administrator $AdminPassword
Add-Content $log -value "Changed Administrator password"

$client = new-object System.Net.WebClient

# Peach fuzzer 3.0 requires .net framework v4
if ((Test-Path "${Env:windir}\Microsoft.NET\Framework\v4.0.30319") -eq $false)
{
    $netUrl = if ($IsCore) {'http://download.microsoft.com/download/3/6/1/361DAE4E-E5B9-4824-B47F-6421A6C59227/dotNetFx40_Full_x86_x64_SC.exe' } `
    else { 'http://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe' }

    $client.DownloadFile( $netUrl, 'dotNetFx40_Full.exe')
    Start-Process -FilePath 'C:\Users\Administrator\dotNetFx40_Full.exe' -ArgumentList '/norestart /q  /ChainingPackage ADMINDEPLOYMENT' -Wait -NoNewWindow
    del dotNetFx40_Full.exe
    Add-Content $log -value "Found that .NET4 was not installed and downloaded / installed"
}

# Peach fuzzer 3.0 requires windows debugging tools
if ((Test-Path "C:\Program Files\Debugging Tools for Windows (x64)") -eq $false)
{
#    $netUrl = 'http://download.microsoft.com/download/B/0/C/B0C80BA3-8AD6-4958-810B-6882485230B5/standalonesdk/sdksetup.exe'    
	$netUrl = 'http://download.microsoft.com/download/A/6/A/A6AC035D-DA3F-4F0C-ADA4-37C8E5D34E3D/winsdk_web.exe'
    $client.DownloadFile( $netUrl, 'winsdk_web.exe')
    Start-Process -FilePath 'C:\Users\Administrator\winsdk_web.exe' -ArgumentList '/norestart /q /ChainingPackage ADMINDEPLOYMENT' -Wait -NoNewWindow
    del winsdk_web.exe
    Add-Content $log -value "Found that Windows Debugging tools were not installed and downloaded / installed"
}

# Peach farmer must be downloaded
# if ((Test-Path "C:\Users\Administrator\peachfarmer") -eq $false)
# {
#     $netUrl = 'http://path.to/peachfarmer.zip'
#     $client.DownloadFile( $netUrl, 'peachfarmer.zip')
#     Expand-ZIPFile -File "C:\Users\Administrator\peachfarmer.zip" -Destination "C:\Users\Administrator\peachfarmer"
# }

#configure powershell to use .net 4
$config = @'
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- http://msdn.microsoft.com/en-us/library/w4atty68.aspx -->
  <startup useLegacyV2RuntimeActivationPolicy="true">
    <supportedRuntime version="v4.0" />
    <supportedRuntime version="v2.0.50727" />
  </startup>
</configuration>
'@

if (Test-Path "${Env:windir}\SysWOW64\WindowsPowerShell\v1.0\powershell.exe")
{
    $config | Set-Content "${Env:windir}\SysWOW64\WindowsPowerShell\v1.0\powershell.exe.config"
    Add-Content $log -value "Configured 32-bit Powershell on x64 OS to use .NET 4"
}
if (Test-Path "${Env:windir}\system32\WindowsPowerShell\v1.0\powershell.exe")
{
    $config | Set-Content "${Env:windir}\system32\WindowsPowerShell\v1.0\powershell.exe.config"
    Add-Content $log -value "Configured host OS specific Powershell at ${Env:windir}\system32\ to use .NET 4"
}

#check winrm id, if it's not valid and LocalAccountTokenFilterPolicy isn't established, do it
$id = &winrm id
if (($id -eq $null) -and (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue) -eq $null)
{
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name LocalAccountTokenFilterPolicy -value 1 -propertyType dword
    Add-Content $log -value "Added LocalAccountTokenFilterPolicy since winrm id could not be executed"
}

#enable powershell servermanager cmdlets (only for 2008 r2 + above)
if ($IsCore)
{
    DISM /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShell /FeatureName:ServerManager-PSH-Cmdlets /FeatureName:BestPractices-PSH-Cmdlets
    Add-Content $log -value "Enabled ServerManager and BestPractices Cmdlets"

    #enable .NET flavors - on server core only -- errors on regular 2008
    DISM /Online /Enable-Feature /FeatureName:NetFx2-ServerCore /FeatureName:NetFx2-ServerCore-WOW64 /FeatureName:NetFx3-ServerCore /FeatureName:NetFx3-ServerCore-WOW64
    Add-Content $log -value "Enabled .NET frameworks 2 and 3 for x86 and x64"
}

#7zip
$7zUri = if ($Is32Bit) { 'http://sourceforge.net/projects/sevenzip/files/7-Zip/9.22/7z922.msi/download' } `
    else { 'http://sourceforge.net/projects/sevenzip/files/7-Zip/9.22/7z922-x64.msi/download' }

$client.DownloadFile( $7zUri, '7z922.msi')
Start-Process -FilePath "msiexec.exe" -ArgumentList '/i 7z922.msi /norestart /q INSTALLDIR="c:\program files\7-zip"' -Wait
SetX Path "${Env:Path};C:\Program Files\7-zip" /m
$Env:Path += ';C:\Program Files\7-Zip'
del 7z922.msi
Add-Content $log -value "Installed 7-zip from $7zUri and updated path"

#vc 2010 redstributable
$vcredist = if ($Is32Bit) { 'http://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe'} `
    else { 'http://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe' }

$client.DownloadFile( $vcredist, 'vcredist.exe')
Start-Process -FilePath 'C:\Users\Administrator\vcredist.exe' -ArgumentList '/norestart /q' -Wait
del vcredist.exe
Add-Content $log -value "Installed VC++ 2010 Redistributable from $vcredist and updated path"

#vc 2008 redstributable
$vcredist = if ($Is32Bit) { 'http://download.microsoft.com/download/d/d/9/dd9a82d0-52ef-40db-8dab-95376989c03/vcredist_x86.exe'} `
    else { 'http://download.microsoft.com/download/d/2/4/d242c3fb-da5a-4542-ad66-f9661d0a8d19/vcredist_x64.exe' }

$client.DownloadFile( $vcredist, 'vcredist.exe')
Start-Process -FilePath 'C:\Users\Administrator\vcredist.exe' -ArgumentList '/norestart /q' -Wait
del vcredist.exe
Add-Content $log -value "Installed VC++ 2008 Redistributable from $vcredist and updated path"

#curl
$curlUri = if ($Is32Bit) { 'http://www.paehl.com/open_source/?download=curl_724_0_ssl.zip' } `
    else { 'http://curl.haxx.se/download/curl-7.23.1-win64-ssl-sspi.zip' }

$client.DownloadFile( $curlUri, 'curl.zip')
&7z e curl.zip `-o`"c:\program files\curl`"
if ($Is32Bit) 
{
    $client.DownloadFile( 'http://www.paehl.com/open_source/?download=libssl.zip', 'libssl.zip')
    &7z e libssl.zip `-o`"c:\program files\curl`"
    del libssl.zip
}
SetX Path "${Env:Path};C:\Program Files\Curl" /m
$Env:Path += ';C:\Program Files\Curl'
del curl.zip
Add-Content $log -value "Installed Curl from $curlUri and updated path"

# Peach fuzzer 3.0 must be downloaded 
if ((Test-Path "C:\Users\Administrator\peach") -eq $false)
{
	$netUrl = 'http://downloads.sourceforge.net/project/peachfuzz/Peach/3.0/peach-3.0.202-win-x64-release.zip?r=1397538292&use_mirror=softlayer-dal'
	$client.DownloadFile( $netUrl, 'peachdownload.zip')
#	&7z x "C:\Users\Administrator\peachdownload.zip"
	&7z x peachdownload.zip `-o`"C:\Users\Administrator\Peach`"
	SetX Path "${Env:Path};C:\Users\Administrator\Peach\peach-3.0.202-win-x64-release" /m
	$Env:Path += ';C:\Users\Administrator\Peach\peach-3.0.202-win-x64-release'
	Add-Content $log -value "Installed Peach fuzzer and updated path"
}

# Add Peach fuzzer to path
# http://blogs.technet.com/b/heyscriptingguy/archive/2011/07/23/use-powershell-to-modify-your-environmental-path.aspx
# $oldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path 
# $newPath = $oldPath+';C:\Users\Administrator\peachdownload\'

#Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath

Add-Content $log -value "Added Peach to Path"

#Add-Content $log -value "Installed Vim text editor and updated path"

#chocolatey - standard one line installer doesn't work on Core b/c Shell.Application can't unzip
if (-not $IsCore)
{
    Invoke-Expression ((new-object net.webclient).DownloadString('http://bit.ly/psChocInstall'))
}
else
{
    #[Environment]::SetEnvironmentVariable('ChocolateyInstall', 'c:\nuget', [System.EnvironmentVariableTarget]::User)
    #if (![System.IO.Directory]::Exists('c:\nuget')) {[System.IO.Directory]::CreateDirectory('c:\nuget')}

    $tempDir = Join-Path $env:TEMP "chocInstall"
    if (![System.IO.Directory]::Exists($tempDir)) {[System.IO.Directory]::CreateDirectory($tempDir)}
    $file = Join-Path $tempDir "chocolatey.zip"
    $client.DownloadFile("http://chocolatey.org/api/v1/package/chocolatey", $file)

    &7z x $file `-o`"$tempDir`"
    Add-Content $log -value 'Extracted Chocolatey'
    $chocInstallPS1 = Join-Path (Join-Path $tempDir 'tools') 'chocolateyInstall.ps1'

    & $chocInstallPS1

    Add-Content $log -value 'Installed Chocolatey / Verifying Paths'
}

Add-Content $log -value "Installed Chocolatey"

&cinst winsshd
Add-Content $log -value 'Installed WinSSHD'

# install puppet
#https://downloads.puppetlabs.com/windows/puppet-3.2.4.msi
# curl -s -G -k -L https://downloads.puppetlabs.com/windows/puppet-3.2.4.msi -o puppet-3.2.4.msi 2>&1 > "$log"
# Start-Process -FilePath "msiexec.exe" -ArgumentList '/qn /passive /i puppet-3.2.4.msi /norestart' -Wait
# SetX Path "${Env:Path};C:\Program Files\Puppet Labs\Puppet\bin" /m
# &sc.exe config puppet start= demand
# Add-Content $log -value "Installed Puppet"

&winrm quickconfig `-q
&winrm set winrm/config/client/auth '@{Basic="true"}'
&winrm set winrm/config/service/auth '@{Basic="true"}'
&winrm set winrm/config/service '@{AllowUnencrypted="true"}'
Add-Content $log -value "Ran quickconfig for winrm"

# Enable SSH connections 
&netsh firewall set portopening tcp 22 ssh enable
Add-Content $log -value "Ran firewall config to allow incoming SSH"

# &netsh firewall set portopening tcp 445 smb enable
# Add-Content $log -value "Ran firewall config to allow incoming smb/tcp"

#run SMRemoting script to enable event log management, etc - available only on R2
$remotingScript = [IO.Path]::Combine($systemPath, 'Configure-SMRemoting.ps1')
if (-not (Test-Path $remotingScript)) { $remotingScript = [IO.Path]::Combine($sysNative, 'Configure-SMRemoting.ps1') }
Add-Content $log -value "Found Remoting Script: [$(Test-Path $remotingScript)] at $remotingScript"
if (Test-Path $remotingScript)
{
    . $remotingScript -force -enable
    Add-Content $log -value 'Ran Configure-SMRemoting.ps1'
}

#wait a bit, it's windows after all
Start-Sleep -m 10000

# Write reboot operation to log

Add-Content $log -value 'Configuration Complete'
Add-Content $log -value 'Restarting Computer'

Restart-Computer
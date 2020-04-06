  #I created this script to do two things, enable basic auth and connect to Exchange Online GCC High. 
  #If you have federation and MFA setup it is supposed to do SSO with an MFA prompt.
  #This script will check to see if basic auth is enabled before connecting to EXO (At the time of script creation, basic auth was required)
  #If basic auth is disabled, the script will prompt for elevation and modify the registry
  #
  
  $Status = New-Object -TypeName PSObject # Custom object for status information

   function check-basicauth {

   $value = get-itemproperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client

   Write-Host -ForegroundColor Cyan 'Checking if Basic Authentication is enabled for WinRM...'
   
   sleep 1
        if ($value.AllowBasic -eq 0){write-host -ForegroundColor Yellow "Basic Authentication is not enabled"; $Status | Add-Member -MemberType NoteProperty -Name 'BasicAuth' -Value '1' }
   
        else{write-host -ForegroundColor Green "Basic Auth is enabled"}
   }

   
   function enable-basicauth {
   
   write-host -ForegroundColor Red 'This is where the registry gets changed to allow Basic Auth'
   sleep 1

   start-process 'reg.exe' -ArgumentList "add HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client /v AllowBasic /t REG_DWORD /d 1 /f" -Verb runas
   sleep 1
   }

   function disable-basicauth {
   
   start-process 'reg.exe' -ArgumentList "add HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client /v AllowBasic /t REG_DWORD /d 0 /f" -Verb runas
   
   }

   #preflight check
   
   check-basicauth

   #$status.'Basic Auth'

   if ($status.BasicAuth -eq 1) {enable-basicauth; check-basicauth}


        $upn = (whoami).trimstart("NETBIOS\")+"@<fqdn>"
        $EXO = "https://outlook.office365.us/powershell-liveid"
        $AzureAD = "https://login.microsoftonline.us/common"
        $ProxyOptions = New-PSSessionOption -ProxyAccessType AutoDetect

Connect-EXOPSSession -UserPrincipalName  $upn -ConnectionURI $EXO  -AzureADAuthorizationEndPointUri $AzureAd  -PSSessionOption $ProxyOptions

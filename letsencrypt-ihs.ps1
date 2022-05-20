# IBM HTTP Server Let's Encrypt Management Script
# Version 1.0.0

param ($CertHostNames, $CertBotPath, $IHSPath, $IHSConfigPath, [switch] $Help, $Password , $CurrentPassword )

$global:InternalCertBotPath = $CertBotPath
$global:InternalIHSPath = $IHSPath
$global:InternalIHSConfigPath = $IHSConfigPath


# Print the usage for the script.
function PrintHelp {
    Write-Host " 
        -CertBot                The path to the CertBot installation ($CertBot).
        -CertHostNames          The name of the certificate host name (required).
        -CurrentPassword        The current password for the IHS keystore.
        -IHSPath                The path to the IBM HTTP Server (IHS) installation ($IHSPath).
        -IHSConfigPath          The path to the IHS configuration file ($IHSConfigPath)
        -Password               The password for new keystore.
        -Help                   Print this help message."
    exit
}

# Prints and error message and then exits the program with a 1 exit code.
function PrintErrorAndExit {
    param ($Message)
    Write-Host "    
$Message
    "
    exit
}

# Ask the user if they want to try again, exit if they enter no or n.
function AskToTryAgain {

    param($Message)
    [string]$Response = ""

    Write-Host ""

    While ($Response.Length -eq 0 -Or !(($Response -eq "n") -Or ($Response -eq "no") -Or ($Response -eq "y") -Or ($Response -eq "yes"))) {
        $Response = (Read-Host "$Message. Try again? (Y/N)" ).ToLower()
    }

    return $Response -eq "y" -Or $Response -eq "yes" 
}

# Convert the secure password string into plain text that can be used with the command line.
Function ConvertFrom-SecureString-AsPlainText {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Security.SecureString]
        $SecureString
    )
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString);
    $PlainTextString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr);
    $PlainTextString;
}

# Determine where CertBot is installed from the registry.
function GetCertBotInstallPath {
    if ([string]::IsNullOrEmpty($InternalCertBotPath)) {
        $Software = "Certbot";
        $InstallEntry = Get-ItemProperty HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $Software }
        
        If ($null -eq $InstallEntry -or $null -eq $InstallEntry.InstallLocation -or [string]::IsNullOrEmpty($InstallEntry.InstallLocation )) {
            Do {     
                $InternalCertBotPath = Read-Host 'Enter the path to the CertBot install folder'
                if ([string]::IsNullOrEmpty($InternalCertBotPath)) {
                    if (!(AskToTryAgain -Message "The path to the CertBot install folder is required.")) {
                        exit
                    }
                }
            }
            While ([string]::IsNullOrEmpty($InternalCertBotPath))
        }
        else {
            return $InstallEntry.InstallLocation
        }
    }
    else {
        return $InternalCertBotPath
    }
}

# Determine where IHS is installed from the registry.
function GetIHSInstallPath {
    if ([string]::IsNullOrEmpty($InternalIHSPath)) {
        $InstallEntry = Get-ItemProperty "HKCU:Software\IBM\HTTP Server\9.0.0.0*"
        
        If ($null -eq $InstallEntry -or $null -eq $InstallEntry.installPath -or [string]::IsNullOrEmpty($InstallEntry.installPath )) {
            $InstallEntry = Get-ItemProperty "HKCU:Software\IBM\HTTP Server\8.5.5.0*"
        }

        If ($null -eq $InstallEntry -or $null -eq $InstallEntry.installPath -or [string]::IsNullOrEmpty($InstallEntry.installPath )) {
            Do {     
                $InternalIHSPath = Read-Host 'Enter the path to the IBM HTTP Server install folder'
                if ([string]::IsNullOrEmpty($InternalIHSPath)) {
                    if (!(AskToTryAgain -Message "The path to the IBM HTTP Server install folder is required.")) {
                        exit
                    }
                }
            }
            While ([string]::IsNullOrEmpty($InternalIHSPath))
        }
        else {
            return $InstallEntry.installPath
        }
    }
    else {
        return $InternalIHSPath
    }
}

# Determine where the IHS configuration is based on the default of $IHSPath\conf\httpd.conf.
function GetIHSConfigPath {
    if ([string]::IsNullOrEmpty($InternalIHSConfigPath)) {
        $TempIHSPath = (GetIHSInstallPath)

        return "$TempIHSPath\conf\httpd.conf"
    }
    else {
        return $InternalIHSConfigPath
    }
}

# Validate the inputs and perform basic sanity checks, such as files and paths exist.
function ValidateInputs() {
    if ([string]::IsNullOrEmpty($CertHostNames) ) {
        PrintErrorAndExit -Message "Error: The certificate host name(s) is required."
    }

    if ([string]::IsNullOrEmpty($InternalCertBotPath)) {        
        Set-Variable -Name "InternalCertBotPath" -value (GetCertBotInstallPath) -scope global 
    }

    if ([string]::IsNullOrEmpty($InternalIHSPath)) {        
        Set-Variable -Name "InternalIHSPath" -value (GetIHSInstallPath) -scope global 
    }

    if ([string]::IsNullOrEmpty($InternalIHSConfigPath)) {        
        Set-Variable -Name "InternalIHSConfigPath" -value (GetIHSConfigPath) -scope global 
    }
    
    if ([string]::IsNullOrEmpty( $InternalIHSPath)) {
        PrintErrorAndExit -Message "Error: The path to the IBM HTTP Server install folder is required."
    }

    if ([string]::IsNullOrEmpty( $InternalIHSConfigPath)) {
        PrintErrorAndExit -Message "Error: The path to the IBM HTTP Server configuration file is required."
    }

    if (!(Test-Path -Path $InternalCertBotPath)) {
        PrintErrorAndExit -Message "Error: The CertBot install folder $InternalCertBotPath does not exist."
    }  

    if (!(Test-Path -Path $InternalCertBotPath\bin\certbot.exe)) {
        PrintErrorAndExit -Message "Error: The CertBot install folder $InternalCertBotPath does not contain the bin\certbot.exe."
    }  

    if (!(Test-Path -Path $InternalIHSPath)) {
        PrintErrorAndExit -Message "Error: The IBM HTTP Server install folder $InternalIHSPath does not exist."
    }  

    if (!(Test-Path -Path $InternalIHSConfigPath)) {
        PrintErrorAndExit -Message "Error: The IBM HTTP Server configuration file $InternalIHSConfigPath does not exist."
    }  
}

# Find the DocumentRoot directive in the IBM HTTP PServer configuration file.
function GetDocumentRoot() {
    $DocumentRoot = Get-Content $InternalIHSConfigPath | Where-Object { $_.Trim() -like "DocumentRoot*" }
    
    if ([string]::IsNullOrEmpty($DocumentRoot)) {
        PrintErrorAndExit "Error: The DocumentRoot directive was not found in the IBM HTTP Server configuration file $InternalIHSConfigPath"
    }

    if ($DocumentRoot.IndexOf(" ") -lt 0) {
        PrintErrorAndExit "Error: The DocumentRoot directive was found in teh IBM HTTP Server configuration file $InternalIHSConfigPath, but does not have a value."
    }

    $DocumentRoot = $DocumentRoot.Substring($DocumentRoot.IndexOf(" ")).Trim()

    # Flip the path delimiter and remove quotes
    $DocumentRoot = $DocumentRoot.Replace("/", "\").Replace("`"", "")
    if (!(Test-Path -Path $DocumentRoot )) {
        PrintErrorAndExit "Error: The DocumentRoot directive folder, $DocumentRoot does not exist."
    }
    
    return $DocumentRoot
}

# Find the KeyFile directive in the IBM HTTP Server configuration file.
function GetKeyStorePath() {
    $KeyFiles = Get-Content $InternalIHSConfigPath | Where-Object { $_.Trim() -like "*KeyFile*" }
    
    $KeyFilePath = ""

    $KeyFileConfigured = $false
    $KeyFileLine = ""
    ForEach ($KeyFile in $KeyFiles) {
        if (!($KeyFile.Trim().StartsWith("#"))) {
            $KeyFileConfigured = $true
            $KeyFilePath = $KeyFile.Substring($KeyFile.IndexOf(" ")).Trim()
        }
        if ($KeyFile.Trim().Substring(1).Trim().StartsWith("KeyFile")) {
            $KeyFileLine = $KeyFile
        }
    }

    if (!$KeyFileConfigured) {

        $KeyFilePath = Split-Path -Path $InternalIHSConfigPath
        $KeyFilePath = "$KeyFilePath\maximo.kdb"

        if ([string]::IsNullOrEmpty($KeyFileLine)) {
            (Get-Content $InternalIHSConfigPath) | 
            ForEach-Object {
                if ($_ -match "Listen 0.0.0.0:443") {
                    "KeyFile $KeyFilePath"
                }
                else {
                    $_
                }
            } | Set-Content $InternalIHSConfigPath
        }
        else {
            ((Get-Content -Path $InternalIHSConfigPath -Raw) -replace "$KeyFileLine", "KeyFile $KeyFilePath") | Set-Content -Path  $InternalIHSConfigPath
        }
    }

    $KeyFileFolder = Split-Path -Path $KeyFilePath

    if (!(Test-Path -Path $KeyFileFolder)) {
        PrintErrorAndExit "Error: The key file database folder $KeyFileFolder does not exist."
    }

    return $KeyFilePath
}

# Create the PFX (PCKS12) using certutil
function CreatePFX() {
    param ($CertificatePath, $PrivateKeyPath, $CertificateName, [SecureString] $KeyStorePassword )
    # Create the temp folder
    $TempFolder = "$PSScriptRoot\tmp"
    if (Test-Path $TempFolder) {  
        $null = Remove-Item $TempFolder -Recurse
    }

    if ([string]::IsNullOrEmpty($CertificatePath)) {
        PrintErrorAndExit "Error: A certificate path is required to create the PFX key store."
    }

    if ([string]::IsNullOrEmpty($PrivateKeyPath)) {
        PrintErrorAndExit "Error: A private key path is required to create the PFX key store."
    }

    if ([string]::IsNullOrEmpty($CertificateName)) {
        PrintErrorAndExit "Error: A certificate name is required to create the PFX key store."
    }

    if ($KeyStorePassword.Length -eq 0) {
        PrintErrorAndExit "Error: A key store passwordis required to create the PFX key store."
    }

    $InternalPassword = ConvertFrom-SecureString-AsPlainText( $KeyStorePassword)
    
    $null = New-Item $TempFolder -ItemType Directory

    $null = Copy-Item "$CertificatePath" -Destination "$TempFolder\$CertificateName.cer"
    $null = Copy-Item "$PrivateKeyPath" -Destination "$TempFolder\$CertificateName.key"
   
    $Params = "-f -p `"$InternalPassword,$InternalPassword`" -MergePFX $TempFolder\$CertificateName.cer $TempFolder\$CertificateName.pfx ".Split(" ")
    $Output = (& certutil  $Params)
   
    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not create the $CertificateName.pfx.
$Output"
    } 

    $Result = ("$TempFolder\$CertificateName.pfx")

    return $Result
}

# Create or update the IBM HTTP Server ket store (KDB)
function CreateKDB() {
    param ($PFXPath, $CertificateName, $KeyStorePath, [SecureString] $KeyStorePassword, [SecureString] $PreviousKeyStorePassword )
    $Command = "$InternalIHSPath\bin\gskcmd.bat"

    $InternalPassword = ConvertFrom-SecureString-AsPlainText( $KeyStorePassword)
    $InternalPreviousPassword = ConvertFrom-SecureString-AsPlainText( $PreviousKeyStorePassword )

    $Params = "-cert -list -db $PFXPath -pw $InternalPassword -type pkcs12".Split(" ")
    $CertificateLabels = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not list certificates in $PFXPath.
$CertificateLabels"
    }
    
    $CertificateLabel = ""
    ForEach ($CertLabel in $CertificateLabels) {
        $CertificateLabel = $CertLabel.Trim()    
    }
    
    # Create the key store if it doesn't exist
    if (!(Test-Path $KeyStorePath)) {  
        $Params = "-keydb -create -db $KeyStorePath -pw $InternalPassword".Split(" ")
        $Output = (& $Command $Params)
        if ($LASTEXITCODE -ne 0) {
            PrintErrorAndExit "Error: Could not create the key store $KeyStorePath.
$Output"
        } 
    }
    else {
        if ($InternalPassword -ne $InternalPreviousPassword) {
            $Params = "-keydb -changepw -db $KeyStorePath -pw $InternalPreviousPassword -new_pw  $InternalPassword -stash".Split(" ")
            $Output = (& $Command $Params)
        
            if ($LASTEXITCODE -ne 0) {
                PrintErrorAndExit "Error: Could not change key store password.
$Output"
            }
        }
    }

    $Params = "-cert -list -db $KeyStorePath -pw $InternalPassword".Split(" ")
    $CertificateLabels = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not list certificates in $KeyStorePath.
$CertificateLabelsutput"
    }

    $CertificateExists = $false
    ForEach ($CertLabel in $CertificateLabels) {
        if ($CertLabel.Trim() -eq "$CertificateName") {
            $CertificateExists = $true
            break
        }
    }    

    if ($CertificateExists) {
        # Remove the cert if it exists
        $Params = "-cert -delete -label $CertificateName -pw $InternalPassword -db  $KeyStorePath".Split(" ")
        $Output = (& $Command $Params)
        if ($LASTEXITCODE -ne 0) {
            PrintErrorAndExit "Error: Could not remove $CertificateName.
$Output"
        }     
    }

    $Params = "-cert -import -label $CertificateLabel -pw $InternalPassword -db $PFXPath -type pkcs12 -target  $KeyStorePath -target_pw $InternalPassword -new_label $CertificateName ".Split(" ")
    $Output = (& $Command $Params)
    
    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not import $PFXPath.
$Output"
    } 

    $Params = "-cert -setdefault -label $CertificateName -pw $InternalPassword -db $KeyStorePath".Split(" ")
    $Output = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not set the default certificate label $CertificateName.
$Output"
    }

    $Params = "-cert -add -label x1 -pw $InternalPassword -db $KeyStorePath -file $PSScriptRoot\x1.pem".Split(" ")
    $Output = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not X1 root CA.
$Output"
    }

    $Params = "-cert -add -label r3 -pw $InternalPassword -db $KeyStorePath -file $PSScriptRoot\r3.pem".Split(" ")
    $Output = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not R3 intermediate CA.
$Output"
    }

    $Params = "-keydb -stashpw -pw $InternalPassword -db $KeyStorePath".Split(" ")
    $Output = (& $Command $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not stash the key store password.
$Output"
    }
}

# Creates, expands or renews a certificate based on the inputs provided.
function CreateOrRenewCertificate() {
    param ($WebRoot, $KeyStorePath, [SecureString] $KeyStorePassword, [SecureString] $PreviousKeyStorePassword)

    if (!(Test-Path -Path "$PSScriptRoot\x1.pem")) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("https://letsencrypt.org/certs/isrgrootx1.pem", "$PSScriptRoot\x1.pem")
    }
    if (!(Test-Path -Path "$PSScriptRoot\r3.pem")) {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("https://letsencrypt.org/certs/lets-encrypt-r3.pem", "$PSScriptRoot\r3.pem")
    }
    
    $Command = "$InternalCertBotPath\bin\certbot.exe" 
    $Params = "certificates".Split(" ")

    # This command writes a message to the console that cannot be supressed.
    $CertificateDetails = (& $Command  $Params)

    if ($LASTEXITCODE -ne 0) {
        PrintErrorAndExit "Error: Could not get a list of certifiates.
$CertificateDetails"
    }

    $ProvidedHosts = $CertHostNames -split ","
    $RequestedHostCount = $ProvidedHosts.Length

    $CertIssued = $false

    $CertPartial = $false
    $CertFound = $false

    $CertName = ""
    $CertificatePath = ""
    $PrivateKeyPath = ""

    $FoundHostCount = 0

    $LocalCertName = ""
    $LocalCertificatePath = ""
    $LocalPrivateKeyPath = ""
    $LocalFoundHostCount = 0

    ForEach ($CertificateDetail in $CertificateDetails) {
        if ($CertificateDetail.Trim().StartsWith("Certificate Name:")) {

            # If the last cert found matches exactly then continue
            if ($LocalFoundHostCount -gt $FoundHostCount) {
                $CertName = $LocalCertName
                $CertificatePath = $LocalCertificatePath
                $PrivateKeyPath = $LocalPrivateKeyPath   
                $FoundHostCount = $LocalFoundHostCount    
            }
            
            if ($FoundHostCount -eq $RequestedHostCount ) {
                break
            }
            
            $LocalCertName = $CertificateDetail.Trim().Substring("Certificate Name:".Length).Trim()
            
        }

        if ($CertificateDetail.Trim().StartsWith("Certificate Path:")) {
            $LocalCertificatePath = $CertificateDetail.Trim().Substring("Certificate Path:".Length).Trim()            
        }

        if ($CertificateDetail.Trim().StartsWith("Private Key Path:")) {
            $LocalPrivateKeyPath = $CertificateDetail.Trim().Substring("Private Key Path:".Length).Trim()
        }

        if ($CertificateDetail.Trim().StartsWith("Domains:")) {

            $LocalFoundHostCount = 0
            
            $Domains = $CertificateDetail.Trim().Substring(8).Trim() -split " "

            if ($Domains.Length -le $RequestedHostCount) {

                ForEach ($ProvidedHost in $ProvidedHosts) {
                    if (($Domains -contains $ProvidedHost.Trim())) {   
                        $LocalFoundHostCount++
                    }        
                }
            }
        }
    }


    # if only one certificate was found
    if ([string]::IsNullOrEmpty($CertName)) {
        $CertName = $LocalCertName
        $CertificatePath = $LocalCertificatePath
        $PrivateKeyPath = $LocalPrivateKeyPath
        $FoundHostCount = $LocalFoundHostCount
    }    

    if ( $LocalFoundHostCount -eq $RequestedHostCount) {
        $CertFound = $true
    }
    elseif ($FoundHostCount -gt 0) {
        $CertPartial = $true
    }

    # Reset the paths if the certificate was not found.
    if (!($CertFound) -and !($CertPartial)) {
        $CertName = ""
        $CertificatePath = ""
        $PrivateKeyPath = ""
    }

    $RequestDomains = ""
    
    ForEach ($ProvidedHost in $ProvidedHosts) {
        $RequestDomains = "$RequestDomains --domain $ProvidedHost" 
    }
  
    if ($CertFound) {  
        Write-Host "Certificate has been issued, requesting a certificate renewal."  
        # If the certificate was found then call for it to be renewed.    
        $Params = "renew --quiet".Split(" ")
        $Output = (& $Command  $Params)
        if ($LASTEXITCODE -ne 0) {
            PrintErrorAndExit "Error: Could not renew the certificate.
$Output"
        }   
    }
    else {
        if ($CertPartial) {
            Write-Host "Certificate with a partial match was found requesting an expantion."
            $Params = "certonly --quiet --webroot --webroot-path  $WebRoot --no-eff-email  --register-unsafely-without-email --non-interactive --agree-tos --expand $RequestDomains".Split(" ")           
            $Output = (& $Command $Params)
            if ($LASTEXITCODE -ne 0) {
                PrintErrorAndExit "Error: Could not expand existing certificate.
$Output"
            }  
            $CertIssued = $true
        }
        else {
            Write-Host "Certificate has not yet been issued, requesting certificate."
            $Params = "certonly --quiet --webroot --webroot-path  $WebRoot --no-eff-email  --register-unsafely-without-email --non-interactive --agree-tos $RequestDomains".Split(" ")
            $Output = (& $Command $Params)
            
            if ($LASTEXITCODE -ne 0) {
                PrintErrorAndExit "Error: Could not get a certificate for $RequestDomains.
$Output"
            }  
        }

        $CertificateDetails = (&  $Command certificates)

        if ($LASTEXITCODE -ne 0) {
            PrintErrorAndExit "Error: Could not get a certificate details.
$CertificateDetails"
        }  
        $CertName = ""
        $LocalCertName = ""
        $LocalCertificatePath = ""
        $LocalPrivateKeyPath = ""
        $LocalFoundHostCount = 0    

        ForEach ($CertificateDetail in $CertificateDetails) {
            if ($CertificateDetail.Trim().StartsWith("Certificate Name:")) {

                # If the last cert found matches exactly then continue
                if ($LocalFoundHostCount -gt $FoundHostCount) {                    
                    $CertName = $LocalCertName
                    $CertificatePath = $LocalCertificatePath
                    $PrivateKeyPath = $LocalPrivateKeyPath   
                    $FoundHostCount = $LocalFoundHostCount    
                }
                
                if ($FoundHostCount -eq $RequestedHostCount ) {
                    break
                }
                
                $LocalCertName = $CertificateDetail.Trim().Substring("Certificate Name:".Length).Trim()
                
            }

            if ($CertificateDetail.Trim().StartsWith("Certificate Path:")) {
                $LocalCertificatePath = $CertificateDetail.Trim().Substring("Certificate Path:".Length).Trim()
            }

            if ($CertificateDetail.Trim().StartsWith("Private Key Path:")) {
                $LocalPrivateKeyPath = $CertificateDetail.Trim().Substring("Private Key Path:".Length).Trim()
            }

            if ($CertificateDetail.Trim().StartsWith("Domains:")) {

                $LocalFoundHostCount = 0
                
                $Domains = $CertificateDetail.Trim().Substring(8).Trim() -split " "

                if ($Domains.Length -le $RequestedHostCount) {
                    ForEach ($ProvidedHost in $ProvidedHosts) {
                        if (($Domains -contains $ProvidedHost.Trim())) {   
                            $LocalFoundHostCount++
                        }        
                    }
                }
            }
        }   

        if ($LocalFoundHostCount -gt $FoundHostCount) {  
            $FoundHostCount = $LocalFoundHostCount  
        }
        
        # if only one certificate was found
        if ([string]::IsNullOrEmpty($CertName)) {
            $CertName = $LocalCertName
            $CertificatePath = $LocalCertificatePath
            $PrivateKeyPath = $LocalPrivateKeyPath
            $FoundHostCount = $LocalFoundHostCount
        }

        if ( $FoundHostCount -eq $RequestedHostCount) {
            $CertFound = $true
        }
        elseif ($FoundHostCount -gt 0) {
            $CertPartial = $true
        }
    }

    if (!($CertFound)) {
        PrintErrorAndExit "Error: A certificate could not be found or issued for $CertHostNames"
    }
    else {        
        $null = (CreatePFX -CertificatePath $CertificatePath -PrivateKeyPath $PrivateKeyPath -CertificateName $CertName -KeyStorePassword  $KeyStorePassword)
   
        CreateKDB -PFXPath  "$PSScriptRoot\tmp\$CertName.pfx" -CertificateName $CertName -KeyStorePath $KeyStorePath -KeyStorePassword  $KeyStorePassword -PreviousKeyStorePassword $PreviousKeyStorePassword

        Write-Host "Certificate $CertName successfully import to $KeyStorePath."
    }
}

# Gets the key store password from the command line.
function GetPassword() {
    Read-Host 'Enter the keystore password' -AsSecureString
}

# Clean up the temporary files.
function Cleanup() {
    $TempFolder = "$PSScriptRoot\tmp"
    if (Test-Path $TempFolder) {  
        $null = Remove-Item $TempFolder -Recurse
    }
}

# prints the help / usage information
if ($help) {
    PrintHelp
}
else {
    ValidateInputs
    $WebRoot = GetDocumentRoot
    $KeyStorePath = GetKeyStorePath

    # Get the keystore password
    if ([string]::IsNullOrEmpty($Password)) {
        Do {
            $Password = ConvertFrom-SecureString-AsPlainText ( GetPassword )

            if ([string]::IsNullOrEmpty($Password)) {
                if (!(AskToTryAgain -Message "The keystore password is required")) {
                    exit
                }
            }
        }
        While ([string]::IsNullOrEmpty($Password))       
    }

    if ([string]::IsNullOrEmpty($CurrentPassword)) {
        $CurrentPassword = $Password
    }
    
    CreateOrRenewCertificate -WebRoot $WebRoot -KeyStorePath $KeyStorePath -KeyStorePassword ($Password  | ConvertTo-SecureString -AsPlainText -Force) -PreviousKeyStorePassword ($CurrentPassword | ConvertTo-SecureString -AsPlainText -Force)

    Cleanup

    exit
}
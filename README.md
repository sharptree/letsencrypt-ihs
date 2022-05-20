# Introduction 
This project provides scripts for both Windows and Linux to automate requesting, expanding and renewing Let's Encrypt issued certificates ([https://letsencrypt.org/](https://letsencrypt.org/)) and then import them to the CMS key store for the IBM HTTP Server.

The scripts depend on the CertBot program ([https://certbot.eff.org/](https://certbot.eff.org/)) for certificate issuing, renewal and expansion requests. Ensure that CertBot is installed on the target system before attempting to the the `letsencrypt-ihs` scripts.

# Windows
The Windows script is a PowerShell ([https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)) script that must be run from within the PowerShell environment and cannot be run from the standard command terminal.

## CertBot
The latest release of CertBot for Windows can be found here: [https://dl.eff.org/certbot-beta-installer-win32.exe](https://dl.eff.org/certbot-beta-installer-win32.exe), additional details can be found here: [https://certbot.eff.org/instructions?ws=apache&os=windows](https://certbot.eff.org/instructions?ws=apache&os=windows).  Please download and install the application before running the `letsencrypt-ihs.ps1` script.  The script will use the registry entry created by the installation wizard to determine the installation location for CertBot.

## Command 
| Parameter          | Description                                                                                                                                                      |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -CertBot           | The fully qualified path to the CertBot installation. If not provided it will be found in the Windows registry.                                                |
| -CertHostNames     | A comma delimited list of host names for the certificate.  This is a required parameter.                                                                         |
| -CurrentPassword   | If the current IBM HTTP Server key store password is different than the one provided, the `-CurrentPassword` parameter is required.                               |
| -IHSPath           | The fully qualified path to the IBM HTTP Server installation. If not provided it will be found in the Windows registry, first for version 9.0.0.0, then 8.5.5.0. |
| -IHSConfigPath     | The fully qualified path to the IBM HTTP Server configuration file.  Defaults to `-ISHPath\conf\httpd.conf`                                                      |
| -Password          | Password that will be used for the IBM HTTP Server key store. If not provided then the user will interactively for a password.                                   |
| -Help              | Flag that will print the scripts usage summary.                                                                                                                  |

# Linux
The Linux script is a Bash script that requires the following programs be installed before running:
* certbot
* openssl
* wget
* xmlstarlet

The script will check for the availability of these programs and will not run without them.

## Command
| Parameter              | Description                                                                                                                                                                                  |
|:-----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -c|--current-password  | If the current IBM HTTP Server key store password is different than the one provided, the `-c|--current-password` parameter is required.                                                     |
| -d|--domains           | A comma delimited list of host names for the certificate.  This is a required parameter.                                                                                                     |
| -i|--ihs-path          | The fully qualified path to the IBM HTTP Server installation. If not provided then it will be found in the Installation Manager registry at /var/ibm/InstallationManager/installRegistry.xml |
|    --ihs-config-path   | The fully qualified path to the IBM HTTP Server configuration file.  Defaults to `--ihs-path\conf\httpd.conf`                                                                                |
| -p|--password          | Password that will be used for the IBM HTTP Server key store. If not provided then the user will interactively for a password.                                                               |
| -h|--help              | Flag that will print the scripts usage summary.                                                                                                                                              |

# Contributing
If you have suggestions or find defects please reach out to us at [hello@sharptree.io](mailto:hello@sharptree.io).

#!/bin/bash

# IBM HTTP Server Let's Encrypt Management Script
# Version 1.0.0

set -eu -o pipefail

CERT_HOST_NAMES=""
CERTBOT_PATH=""
IHS_PATH=""
IHS_CONFIG_PATH=""
PASSWORD=""
CURRENT_PASSWORD=""
DOMAINS=""
TEMP_FOLDER="./.tmp"

IBM_REGISTRY_PATH="/var/ibm/InstallationManager/installRegistry.xml"

cmdname=${0##*/}

# Get the password from the console, keep asking until a result is provided or the user exits.
get_password() {
    while [ -z "$PASSWORD" ]; do
        read -s -p "Enter keystore password: " PASSWORD

        if [ -z "$PASSWORD" ]; then
            printf "\nA keystore password is required\n"
        fi
    done

    printf "\n"
}

# Check that the required programs are installed.
check_requirement() {
    req=$1
    if ! which $req &>/dev/null; then
        echo "$req is not installed and is required." 1>&2
        return 1
    fi
}

# Print the usage for the script.
usage()
{

    cat << EOS >&2
Usage:
    $cmdname
    -c|--current-password       The current password for the IHS keystore (if changing password).
    -d|--domains                A comma separated list of certificate host names.   
       --ihs-config-path        The path to the IHS configuration file.
    -i|--ihs-path               The path to the IBM HTTP Server (IHS) installation directory.
    -p|--password               The password for new keystore.
    -h|--help                   Print this help message.
EOS
}

# Validate the inputs and perform basic sanity checks, such as files and paths exist.
validate(){
    if [[ -z ${CERT_HOST_NAMES} ]]; then
        echo "A least one certificate host name is required."
        exit 1
    fi

    if [[ -z ${PASSWORD} ]]; then 
        get_password
    fi

    if [[ -z ${IHS_PATH} ]]; then
        if [[ -f $IBM_REGISTRY_PATH ]]; then 
            IHS_PATH=$(xmlstarlet sel -t -v '/installRegistry/profile[starts-with(@id,"IBM HTTP Server")]/property[@name="installLocation"]/@value' $IBM_REGISTRY_PATH)
        else
            echo "The IBM Installation Manager registry was not found at ${IBM_REGISTRY_PATH}, cannot auto discover the IBM HTTP Server installation directory and was not provide as a command line argument."
            exit 1
        fi

        if [[ -z ${IHS_PATH} ]]; then
            echo "The IBM HTTP Server instalaltion path was not found in the IBM Installation Manager registry and was not provide as a command line argument."
            exit 1
        fi
    fi

    if [[ ! -d $IHS_PATH ]]; then
        echo "The IBM HTTP Server installation directory ${IHS_PATH} does not exist."
        exit 1
    fi

    if [[ -z ${IHS_CONFIG_PATH} ]]; then
        IHS_CONFIG_PATH=${IHS_PATH}/conf/httpd.conf   
    fi

    if [[ ! -f $IHS_CONFIG_PATH ]]; then
        echo "The IBM HTTP Server configuration was not found at ${IHS_CONFIG_PATH}."
        exit 1
    fi     
}

# Find the DocumentRoot directive in the IBM HTTP PServer configuration file.
function getDocumentRoot(){
    local documentRoot=$(grep -i 'DocumentRoot' ${IHS_CONFIG_PATH} | grep -v '#.*' | xargs | cut -c13- | xargs)

    if [[ -z ${documentRoot} ]]; then 
        echo "The DocumentRoot directive was not found in the IBM HTTP Server configuration at ${IHS_CONFIG_PATH}."
        exit 1
    fi

    echo ${documentRoot}
}

# Find the KeyFile directive in the IBM HTTP Server configuration file.
function getKeyFilePath(){
    local keyFilePath=$(grep -i 'KeyFile' ${IHS_CONFIG_PATH} | grep -v '#.*' | xargs | cut -c8- | xargs)

    if [[ -z ${documentRoot} ]]; then 
        echo "The KeyFile directive was not found in the IBM HTTP Server configuration at ${IHS_CONFIG_PATH}."
        exit 1
    fi

    echo ${keyFilePath}
}

function cleanup(){
    rm -rf ${TEMP_FOLDER}
}

# Creates, expands or renews a certificate based on the inputs provided.
function createOrRenewCertificate(){
    webroot=$1
    keyFilePath=$2

    if [[ ! -d ${TEMP_FOLDER} ]]; then
        mkdir -p ${TEMP_FOLDER}
    fi

    if [[ ! -f ${TEMP_FOLDER}/x1.pem ]]; then 
        wget --quiet -O ${TEMP_FOLDER}/x1.pem https://letsencrypt.org/certs/isrgrootx1.pem
    fi

        if [[ ! -f ${TEMP_FOLDER}/r3.pem ]]; then 
        wget --quiet -O ${TEMP_FOLDER}/r3.pem https://letsencrypt.org/certs/lets-encrypt-r3.pem
    fi
    
    found=0
    partial=0

    certName=""
    localCertName=""

    certificatePath=""
    localCertificatePath=""
    
    privateKeyPath=""
    localPrivateKeyPath=""

    IFS=',' read -ra hosts <<< "$(echo ${CERT_HOST_NAMES} | xargs)"
    
    requestedHostCount=${#hosts[@]}
    
    foundHostCount=0
    localFoundHostCount=0
    
    while read -r line
    do
        trimmedLine=$(echo ${line} | xargs)

        if [[ $trimmedLine == "Certificate Name:"* ]]; then               
            # If the last cert found matches exactly then continue
            if [[ $localFoundHostCount -gt $foundHostCount ]]; then
                certName=$localCertName
                certificatePath=$localCertificatePath
                privateKeyPath=$localPrivateKeyPath   
                foundHostCount=$localFoundHostCount             
            fi

            if [[ $foundHostCount == $requestedHostCount ]]; then             
                break
            fi
            
            localCertName=$(echo ${trimmedLine} |  cut -c18- | xargs)         
        fi
        if [[ $trimmedLine == "Certificate Path:"* ]]; then
            localCertificatePath=$(echo ${trimmedLine} |  cut -c18- | xargs)       
        fi
        if [[ $trimmedLine == "Private Key Path:"* ]]; then
            localPrivateKeyPath=$(echo ${trimmedLine} |  cut -c19- | xargs)   
        fi  

        if [[ $trimmedLine == "Domains:"* ]]; then
            IFS=' ' read -ra domains <<< "$(echo ${trimmedLine} |  cut -c9- | xargs)"
            # reset the found host count
            localFoundHostCount=0
            if [[ ${#domains[@]} -le $requestedHostCount ]]; then
                for i in "${hosts[@]}"; do
                    if printf '%s\0' "${domains[@]}" | grep -Fxqz ${i} ; then 
                        ((localFoundHostCount=localFoundHostCount+1))                    
                    fi 
                done
            fi
        fi        
    done < <(certbot certificates)

    if [[ $localFoundHostCount -gt $foundHostCount ]]; then
        foundHostCount=$localFoundHostCount 
    fi

    # if only one certificate was found
    if [[ -z ${certName} ]]; then 
        certName=$localCertName
        certificatePath=$localCertificatePath
        privateKeyPath=$localPrivateKeyPath   
        foundHostCount=$localFoundHostCount             
    fi

    if [[ $foundHostCount == $requestedHostCount ]]; then
        found=1
    elif [[ $foundHostCount -gt 0 ]]; then 
        partial=1
    fi

    # If the cert wasn't found at all then clear everything as we are going to request a new certificate
    if [[ $found == 0 && $partial == 0 ]]; then         
        certName=""
        certificatePath=""
        privateKeyPath=""
    fi


    domainArgs=$(printf " --domain %s" "${hosts[@]}")

    if [[ $found == 1 ]]; then
        # If the certificate was found then call for it to be renewed.    
        echo "Certificate has been issued, requesting a certificate renewal."
        output=$(certbot  renew --quiet)
    else 
        if [[ ${partial} == 1 ]]; then
            echo "Certificate with a partial match was found requesting an expantion."
            output=$(certbot certonly --quiet --webroot --webroot-path $webroot --no-eff-email --register-unsafely-without-email --non-interactive --agree-tos --expand $domainArgs)                    
        else 
            echo "Certificate has not yet been issued, requesting certificate."

            output=$(certbot certonly --quiet --webroot --webroot-path  $webroot --no-eff-email  --register-unsafely-without-email --non-interactive --agree-tos $domainArgs)
        fi

        certName=""
        localCertName=""
        localCertificatePath=""
        localPrivateKeyPath=""
        localFoundHostCount=0            
        while read -r line
        do
            trimmedLine=$(echo ${line} | xargs)

            if [[ $trimmedLine == "Certificate Name:"* ]]; then               
                # If the last cert found matches exactly then continue
                if [[ $localFoundHostCount -gt $foundHostCount ]]; then
                    certName=$localCertName
                    certificatePath=$localCertificatePath
                    privateKeyPath=$localPrivateKeyPath   
                    foundHostCount=$localFoundHostCount             
                fi

                if [[ $foundHostCount == $requestedHostCount ]]; then 
                    found=1
                    break
                fi
                
                localCertName=$(echo ${trimmedLine} |  cut -c18- | xargs)         
            fi
            if [[ $trimmedLine == "Certificate Path:"* ]]; then
                localCertificatePath=$(echo ${trimmedLine} |  cut -c18- | xargs)       
            fi
            if [[ $trimmedLine == "Private Key Path:"* ]]; then
                localPrivateKeyPath=$(echo ${trimmedLine} |  cut -c19- | xargs)   
            fi  

            if [[ $trimmedLine == "Domains:"* ]]; then
                IFS=' ' read -ra domains <<< "$(echo ${trimmedLine} |  cut -c9- | xargs)"
                # reset the found host count
                localFoundHostCount=0
                if [[ ${#domains[@]} -le $requestedHostCount ]]; then
                    for i in "${hosts[@]}"; do
                        if printf '%s\0' "${domains[@]}" | grep -Fxqz ${i} ; then 
                            ((localFoundHostCount=localFoundHostCount+1))
                        fi 
                    done
                fi
            fi        
        done < <(certbot certificates)

        # if only one certificate was found then set the values
        if [[ -z ${certName} ]]; then 
            certName=$localCertName
            certificatePath=$localCertificatePath
            privateKeyPath=$localPrivateKeyPath   
            foundHostCount=$localFoundHostCount             
        fi

        if [[ $localFoundHostCount -gt $foundHostCount ]]; then
            foundHostCount=$localFoundHostCount 
        fi

        if [[ $foundHostCount == $requestedHostCount ]]; then
            found=1
        elif [[ $foundHostCount -gt 0 ]]; then 
            partial=1
        fi

    fi

    if [[ found == 0 ]]; then
        # show an error
        echo "Error: The certificate was not found, renewed or issued."
        exit 1
    else
        # Create the p12 keystore
        output=$(openssl pkcs12 -export -out ${TEMP_FOLDER}/${certName}.p12 -inkey ${privateKeyPath} -in ${certificatePath} -passout pass:${PASSWORD} -name ${certName} )

        if [[ -z ${CURRENT_PASSWORD} ]]; then
            CURRENT_PASSWORD=${PASSWORD}
        fi

        gskCommand="$IHS_PATH/bin/gskcmd"
        
        certificateLabels=$($gskCommand -cert -list -db ${TEMP_FOLDER}/${certName}.p12 -pw $PASSWORD -type pkcs12)
        
        if [[ ! -f ${keyFilePath} ]]; then
            output=$($gskCommand -keydb -create -db ${keyFilePath} -pw ${PASSWORD})
            
            if [[ $? != 0 ]]; then
                echo "Error: ${output}"
                exit 1
            fi 
        else
            if [[ ${PASSWORD} != ${CURRENT_PASSWORD} ]]; then 
                echo "password's don't match"
                $gskCommand -keydb -changepw -db ${keyFilePath} -pw ${CURRENT_PASSWORD} -new_pw  ${PASSWORD} -stash

                echo "result was $? and output is ${output}" 
                if [[ $? != 0 ]]; then
                    echo "Error: ${output}"
                    exit 1
                fi 
            fi
        fi

        # Get the installed certificates and then check if a certificate with the same name already exists, if it does then delete it and add the new one
        installedCertificates=$($gskCommand -cert -list -db  ${keyFilePath} -pw  ${PASSWORD})

        SAVEIFS=$IFS   # Save current IFS (Internal Field Separator)
        IFS=$'\n'      # Change IFS to newline char
        names=($installedCertificates) # split the `names` string into an array by the same name
        IFS=$SAVEIFS   # Restore original IFS 

        for (( i=0; i<${#names[@]}; i++ ))
        do
            name=$(echo ${names[$i]}|xargs)            
            if [[ ${name} == ${certName} ]]; then
                $gskCommand -cert -delete -label ${certName} -pw ${PASSWORD} -db ${keyFilePath}
            fi
        done
        
        $gskCommand -cert -import -label ${certName} -pw ${PASSWORD} -db ${TEMP_FOLDER}/${certName}.p12 -type pkcs12 -target ${keyFilePath} -target_pw ${PASSWORD} -new_label ${certName} 
        
        $gskCommand -cert -setdefault -label ${certName} -pw ${PASSWORD} -db ${keyFilePath} 

        $gskCommand -cert -add -label x1 -pw ${PASSWORD} -db  ${keyFilePath} -file ${TEMP_FOLDER}/x1.pem

        $gskCommand -cert -add  -label r3 -pw ${PASSWORD} -db  ${keyFilePath} -file ${TEMP_FOLDER}/r3.pem 

        $gskCommand -keydb  -stashpw -pw ${PASSWORD} -db  ${keyFilePath} 

        echo "Certificate ${certName} successfully import to ${keyFilePath}."
    fi
}

# The main entry point for the script.
main() {

    # Check for required software
    reqs=(
        xmlstarlet
        certbot
        openssl
        wget
    )

    # Check the require programs
    for req in ${reqs[@]}; do
        check_requirement $req
    done

    # Ge the command line arguments.
    while (( "$#" )); do
        case "$1" in
            -c|--current-password) 
              if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                  CURRENT_PASSWORD=$2
                  shift 2
              else
                  echo "Error: Argument for $1 is missing a current password value." >&2
                  exit 1
              fi
            ;; 
            -d|--domains) 
              if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                  CERT_HOST_NAMES=$2
                  shift 2
              else
                  echo "Error: Argument for $1 is missing one or more comma separated certificate names." >&2
                  exit 1
              fi
            ;;               
            --ihs-config-path) 
              if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                  IHS_CONFIG_PATH=$2
                  shift 2
              else
                  echo "Error: Argument for $1 is missing a path to the IBM HTTP Server (IHS) configuration file path." >&2
                  exit 1
              fi
            ;;                         

            -i|--ihs-path) 
              if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                  IHS_PATH=$2
                  shift 2
              else
                  echo "Error: Argument for $1 is missing a path to the IBM HTTP Server (IHS) install directory." >&2
                  exit 1
              fi
            ;;                         

            -p|--password) 
              if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
                  PASSWORD=$2
                  shift 2
              else
                  echo "Error: Argument for $1 is missing a keystore password." >&2
                  exit 1
              fi
            ;;                                      
            -h|--help) 
                usage               
                exit 0
            ;;     
            -*|--*=) # unsupported flags
                printf "\nError: Unsupported flag $1.\n" >&2
                exit 1
            ;;
            *) # preserve positional arguments
                PARAMS="$PARAMS $1"
                shift
            ;;
        esac
    done

    # Validate the inputs
    validate

    # Get the web document root.
    documentRoot=$(getDocumentRoot)

    # Get the key file.
    keyFilePath=$(getKeyFilePath)

    # Create or renew the certificaes
    createOrRenewCertificate $documentRoot $keyFilePath

    cleanup
}

main $@
if [ $? -ne 0 ]; then
    exit 1
else
    exit 0
fi
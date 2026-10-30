$ip = "VOTRE_IP"
Invoke-RestMethod "https://$ip/redfish/v1/" -SkipCertificateCheck      # erreur exacte PowerShell
curl.exe -skv https://$ip/redfish/v1/                                  # -k ignore le cert, -v montre le TLS
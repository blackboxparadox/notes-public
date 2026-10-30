# ============================================================
#  Decouverte de serveurs HP sur sous-reseaux  (v8)
#  v7 : detection HP via /xmldata?item=all (sans login) au lieu de la
#       racine Redfish, souvent videe quand l'iLO est gere par OneView.
#  v8 : menu (3) Utilisateurs iLO a provisionner ; Phase 3 cree/MAJ ces
#       comptes (ex. AdminCompute) sur chaque iLO puis utilise le compte
#       marque "OneView" pour l'ajout.
#  Chaque action est ENREGISTREE sur le disque immediatement
#  -> si ca casse, on relance et ca reprend ou c'etait.
#
#  Nouveautes v5 :
#   - Phase 1 detecte un hote par PING *ou* TCP 443 (ICMP souvent bloque)
#   - Phase 2 lit la RACINE Redfish /redfish/v1/ (accessible SANS login)
#     -> fini le faux "non-HP" quand /Managers/1 renvoie 401
#   - Colonne Vendor : HPE / Dell / Lenovo-IBM / Cisco / Supermicro / Fujitsu / Autre
#   - Rapport : detail des non-HP par vendor
#
#  Menu :
#   (1) Identifiants iLO/SSH   (2) Appliances (OneView / IAP)
#   (3) Phase 1 : Scan reseau  (4) Phase 2 : Identification
#   (5) Phase 3 : Ajout        (6) Rapport    (7) Tester 1 IP (diagnostic)
#
#  Status : dead | alive | not-hp | no-access | ready | sent
#  Fonctionne sous Windows PowerShell 5.1 ET PowerShell 7
#  (certificat auto-signe + TLS geres selon la version)
# ============================================================

# ---------- Config ----------
$base_dir       = 'D:\_Oneview_assets_export'
$subnet_file    = "$base_dir\subnets.txt"
$keys_dir       = "$base_dir\ov_keys"
$appliances_dir = "$base_dir\ov_appliances"
$users_dir      = "$base_dir\ov_users"          # utilisateurs iLO a creer/MAJ (chiffre)
$out_file       = "$base_dir\discovered_servers.csv"
$log_file       = "$base_dir\scan.log"
$delay_ms       = 1000     # pause entre chaque IP
$ping_ms        = 500      # attente max ping (ICMP)
$tcp_ms         = 400      # attente max test TCP 443

foreach ($d in @($base_dir, $keys_dir, $appliances_dir, $users_dir)) {
 if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

Import-Module Posh-SSH
Import-Module HPEOneView.1000

# ============================================================
#  COMPATIBILITE PowerShell 5.1 / 7  (certificat auto-signe + TLS)
#  C'est ICI que se jouait le faux "non-HP" : en 5.1, le parametre
#  -SkipCertificateCheck n'existe pas -> chaque appel plantait.
# ============================================================
$script:PS7 = $PSVersionTable.PSVersion.Major -ge 6
if (-not $script:PS7) {
 # Windows PowerShell 5.1 : accepter le certificat auto-signe + forcer TLS moderne
 try {
  Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
}
"@
 } catch {}   # deja defini si on relance dans la meme fenetre
 [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
 [System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]'Tls12,Tls11,Tls'
}
Write-Host ("PowerShell {0} detecte." -f $PSVersionTable.PSVersion) -ForegroundColor DarkCyan

# GET Redfish compatible 5.1 / 7 (le -SkipCertificateCheck seulement si dispo)
function Get-Redfish([string]$url, [pscredential]$cred) {
 $p = @{ Uri=$url; TimeoutSec=6; ErrorAction='Stop' }
 if ($script:PS7) { $p.SkipCertificateCheck = $true }   # 5.1 : gere par CertificatePolicy ci-dessus
 if ($cred)       { $p.Credential = $cred }
 Invoke-RestMethod @p
}

# HP/iLO : /xmldata?item=all  -> XML SANS login (PN=version iLO, SPN=modele, FWRI=firmware)
#  C'est LA bonne source : la racine Redfish est souvent vide quand l'iLO est gere par OneView.
function Get-HpXmlData([string]$ip) {
 try {
  $p = @{ Uri="https://$ip/xmldata?item=all"; TimeoutSec=6; ErrorAction='Stop' }
  if ($script:PS7) { $p.SkipCertificateCheck = $true }
  [xml]$x = (Invoke-WebRequest @p).Content
  if ($x.RIMP) { return $x.RIMP }
 } catch {}
 return $null
}

# Racine Redfish + entete HTTP "Server" (utile pour deviner le vendor des non-HP)
function Get-RedfishRoot([string]$ip) {
 $p = @{ Uri="https://$ip/redfish/v1/"; TimeoutSec=6; ErrorAction='Stop' }
 if ($script:PS7) { $p.SkipCertificateCheck = $true }
 $resp = Invoke-WebRequest @p
 $obj = $null; try { $obj = $resp.Content | ConvertFrom-Json } catch {}
 [PSCustomObject]@{ Server=[string]$resp.Headers['Server']; Body=$obj }
}

# ============================================================
#  JOURNAL + ETAT (sauvegarde immediate)
# ============================================================
function Log([string]$msg, [string]$color = 'Gray') {
 $line = "{0}  {1}" -f (Get-Date -f 'HH:mm:ss'), $msg
 Write-Host $line -ForegroundColor $color
 Add-Content -Path $log_file -Value $line -Encoding UTF8
}

function New-Row([string]$ip) {
 [PSCustomObject]@{
  IP=$ip; Alive=''; Vendor=''; iLO=''; Model=''; Firmware=''; Generation=''
  Target=''; PasswordFound=''; KeyFile=''; Status=''; Appliance=''; LastUpdate=''
 }
}
function Normalize-Row($r) {
 $n = New-Row $r.IP
 foreach ($p in $n.PSObject.Properties.Name) {
  if (($r.PSObject.Properties.Name -contains $p) -and ($null -ne $r.$p)) { $n.$p = $r.$p }
 }
 $n
}
function Load-State {
 $script:State = [ordered]@{}
 if (Test-Path $out_file) {
  foreach ($r in Import-Csv $out_file -Delimiter ';') { $script:State[$r.IP] = Normalize-Row $r }
 }
}
function Save-State {
 $tmp = "$out_file.tmp"
 $script:State.Values | Sort-Object IP | Export-Csv $tmp -Delimiter ';' -NoType -Encoding UTF8
 Move-Item $tmp $out_file -Force
}
function Save-Server($row) {
 $row.LastUpdate = (Get-Date -f 'yyyy-MM-dd HH:mm:ss')
 $script:State[$row.IP] = $row
 Save-State
}

# ============================================================
#  Sous-reseaux + identifiants + appliances
# ============================================================
function Get-SubnetIPs([string]$cidr) {
 $parts = ($cidr.Trim()) -split '/'
 $ip = $parts[0]; $bits = [int]$parts[1]
 $base = ([ipaddress]$ip).GetAddressBytes(); [array]::Reverse($base)
 $base = [BitConverter]::ToUInt32($base,0)
 $mask = [uint32]([math]::Pow(2,32) - [math]::Pow(2,32-$bits))
 $net  = $base -band $mask
 $size = [uint32]([math]::Pow(2,32-$bits))
 for ($i=1; $i -lt $size-1; $i++) {
  $b = [BitConverter]::GetBytes($net+$i); [array]::Reverse($b)
  ([ipaddress]$b).IPAddressToString
 }
}
function Read-SubnetFile {
 if (-not (Test-Path $subnet_file)) { Log "[WARN] $subnet_file introuvable" Yellow; return @() }
 @(Get-Content $subnet_file) | ForEach-Object { [string]$_ } |
  Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') } | ForEach-Object { $_.Trim() }
}
function Get-KnownCreds {
 $list = @()
 foreach ($f in Get-ChildItem $keys_dir -Filter *.xml -EA SilentlyContinue) {
  try { $list += [PSCustomObject]@{ File=$f.Name; Cred=Import-Clixml $f.FullName } } catch { Log "[WARN] illisible: $($f.Name)" Yellow }
 }
 foreach ($f in Get-ChildItem $keys_dir -Filter *.key -EA SilentlyContinue) {
  try { $sec = Get-Content $f.FullName | ConvertTo-SecureString
        $list += [PSCustomObject]@{ File=$f.Name; Cred=New-Object PSCredential('Administrator',$sec) } } catch { Log "[WARN] illisible: $($f.Name)" Yellow }
 }
 $list
}
function Manage-Creds {
 while ($true) {
  Write-Host "`n--- Identifiants iLO/SSH ---"
  $files = @(Get-ChildItem $keys_dir -File -EA SilentlyContinue | Where-Object { $_.Extension -in '.xml','.key' } | Sort-Object Name)
  for ($i=0; $i -lt $files.Count; $i++) { Write-Host "  [$i] $($files[$i].Name)" }
  Write-Host "`n (A)jouter  (S)upprimer  (R)etour"
  switch ((Read-Host "Choix").ToUpper()) {
   'A' { $name = Read-Host "Nom du fichier (ex: admin-prod)"; Get-Credential -Message $name | Export-Clixml "$keys_dir\$name.xml"; Write-Host "[OK] $name.xml cree" }
   'S' { $n = Read-Host "Numero a supprimer"; if ($n -match '^\d+$' -and [int]$n -lt $files.Count) { Remove-Item $files[[int]$n].FullName; Write-Host "[OK] supprime" } else { Write-Host "[WARN] numero invalide" } }
   'R' { return }
  }
 }
}
function Get-Appliances {
 $list = @()
 foreach ($f in Get-ChildItem $appliances_dir -Filter *.xml -EA SilentlyContinue) {
  try { $a = Import-Clixml $f.FullName; $type = if ($a.Type) { $a.Type } else { 'OneView' }
        $list += [PSCustomObject]@{ Name=$f.BaseName; Path=$f.FullName; Type=$type; IP=$a.IP; Cred=$a.Cred } } catch { Log "[WARN] appliance illisible: $($f.Name)" Yellow }
 }
 $list
}
function Manage-Appliances {
 while ($true) {
  Write-Host "`n--- Appliances (OneView / iLO Amplifier Pack) ---"
  $apps = @(Get-Appliances)
  for ($i=0; $i -lt $apps.Count; $i++) { Write-Host "  [$i] $($apps[$i].Name)  [$($apps[$i].Type)]  ->  $($apps[$i].IP)  (compte: $($apps[$i].Cred.UserName))" }
  Write-Host "`n (A)jouter  (S)upprimer  (R)etour"
  switch ((Read-Host "Choix").ToUpper()) {
   'A' { $name = Read-Host "Nom court (ex: oneview-prod)"
         $t = (Read-Host "Type : (O)neView [defaut]  ou  (I)AP").ToUpper(); $type = if ($t -eq 'I') { 'IAP' } else { 'OneView' }
         $ip = Read-Host "IP ou nom DNS de l'appliance"; $cred = Get-Credential -Message "Compte admin $type pour $name"
         [PSCustomObject]@{ Type=$type; IP=$ip.Trim(); Cred=$cred } | Export-Clixml "$appliances_dir\$name.xml"; Write-Host "[OK] appliance '$name' ($type) enregistree" }
   'S' { $n = Read-Host "Numero a supprimer"; if ($n -match '^\d+$' -and [int]$n -lt $apps.Count) { Remove-Item $apps[[int]$n].Path; Write-Host "[OK] supprime" } else { Write-Host "[WARN] numero invalide" } }
   'R' { return }
  }
 }
}

# ============================================================
#  Utilisateurs iLO a provisionner (creer / MAJ sur les serveurs)
#  Chaque .xml : UserName + mot de passe (chiffre) + ForOneView
# ============================================================
function Get-ProvUsers {
 $list = @()
 foreach ($f in Get-ChildItem $users_dir -Filter *.xml -EA SilentlyContinue) {
  try { $u = Import-Clixml $f.FullName
        $list += [PSCustomObject]@{ Name=$f.BaseName; Path=$f.FullName; Cred=$u.Cred; ForOneView=[bool]$u.ForOneView } }
  catch { Log "[WARN] user illisible: $($f.Name)" Yellow }
 }
 $list
}
function Manage-Users {
 while ($true) {
  Write-Host "`n--- Utilisateurs iLO a provisionner (creer/MAJ) ---"
  $us = @(Get-ProvUsers)
  for ($i=0; $i -lt $us.Count; $i++) {
   $flag = if ($us[$i].ForOneView) { '[compte OneView]' } else { '' }
   Write-Host "  [$i] $($us[$i].Cred.UserName)  $flag"
  }
  Write-Host "`n (A)jouter/MAJ  (S)upprimer  (R)etour"
  switch ((Read-Host "Choix").ToUpper()) {
   'A' {
    $name = Read-Host "Nom d'utilisateur iLO (ex: AdminCompute)"
    $cred = Get-Credential -UserName $name -Message "Mot de passe pour '$name'"
    $fo   = (Read-Host "Compte utilise pour la connexion OneView ? (O)ui [defaut] / (N)on").ToUpper() -ne 'N'
    [PSCustomObject]@{ Cred=$cred; ForOneView=$fo } | Export-Clixml "$users_dir\$name.xml"
    Write-Host "[OK] utilisateur '$name' enregistre (OneView=$fo)"
   }
   'S' {
    $n = Read-Host "Numero a supprimer"
    if ($n -match '^\d+$' -and [int]$n -lt $us.Count) { Remove-Item $us[[int]$n].Path; Write-Host "[OK] supprime" } else { Write-Host "[WARN] numero invalide" }
   }
   'R' { return }
  }
 }
}
#  Pour MODIFIER un utilisateur : le re-ajouter avec le meme nom (il ecrase).

# ============================================================
#  Detection
# ============================================================
# Test TCP d'un port (ex: 443) avec timeout
function Test-Tcp([string]$ip, [int]$port, [int]$ms) {
 $c = New-Object Net.Sockets.TcpClient
 try { $a = $c.BeginConnect($ip,$port,$null,$null)
       if ($a.AsyncWaitHandle.WaitOne($ms)) { $c.EndConnect($a); return $true } } catch {} finally { $c.Close() }
 return $false
}
# Deduit le vendor depuis les cles Oem + Vendor + Product/Model
function Detect-Vendor([string]$s) {
 switch -Regex ($s) {
  'Hpe|Hewlett|iLO'                 { 'HPE'; break }
  'Dell|iDRAC'                      { 'Dell'; break }
  'Lenovo|IBM|XClarity|XCC|IMM'     { 'Lenovo-IBM'; break }
  'Cisco|CIMC|UCS'                  { 'Cisco'; break }
  'Supermicro'                      { 'Supermicro'; break }
  'Fujitsu|iRMC'                    { 'Fujitsu'; break }
  default                           { 'Autre' }
 }
}

# ============================================================
#  PHASE 1 : SCAN RESEAU (ping OU tcp443)
# ============================================================
function Phase1-Scan([string[]]$subnets) {
 $ips = @(foreach ($s in $subnets) { Get-SubnetIPs $s })
 Log "===== PHASE 1 : SCAN =====" Cyan
 Log "[INFO] $($ips.Count) IP a tester, delai ${delay_ms}ms" Cyan

 $m = (Read-Host "Detection : (B) ping+TCP443 [defaut]  (P) ping seul  (T) TCP443 seul").ToUpper()
 $all = (Read-Host "Portee : (N)ouvelles IP seulement [defaut]  ou  (T)out re-scanner").ToUpper() -eq 'T'

 foreach ($ip in $ips) {
  if (-not $all -and $script:State.Contains($ip)) { continue }
  Start-Sleep -Milliseconds $delay_ms

  $via = $null
  if ($m -ne 'T') { try { if ((New-Object Net.NetworkInformation.Ping).Send($ip,$ping_ms).Status -eq 'Success') { $via='icmp' } } catch {} }
  if (-not $via -and $m -ne 'P') { if (Test-Tcp $ip 443 $tcp_ms) { $via='tcp443' } }

  $row = if ($script:State.Contains($ip)) { $script:State[$ip] } else { New-Row $ip }
  if ($via) {
   $row.Alive='True'; if ($row.Status -in @('','dead')) { $row.Status='alive' }
   Log "[SCAN] $ip  -> VIVANT ($via)" Green
  } else {
   $row.Alive='False'; if ($row.Status -in @('','alive')) { $row.Status='dead' }
   Log "[SCAN] $ip  -> pas de reponse" DarkGray
  }
  Save-Server $row
 }
 Log "[FINI] Phase 1 terminee." Cyan
}

# ============================================================
#  PHASE 2 : IDENTIFICATION (xmldata HP, puis Redfish pour les autres)
# ============================================================
# Renseigne la ligne et renvoie : 'hp' | 'other' | 'none'
function Identify-Host($row) {
 $ip = $row.IP

 # 1) HP/iLO via /xmldata?item=all (XML, sans login) -> marche meme si l'iLO est gere par OneView
 Log "   GET https://$ip/xmldata?item=all  (HP, sans login)..." Gray
 $xml = Get-HpXmlData $ip
 if ($xml -and ($xml.MP.PN -match 'Lights-Out|iLO')) {
  $pn = [string]$xml.MP.PN
  $row.Vendor='HPE'; $row.iLO=$pn; $row.Firmware=[string]$xml.MP.FWRI; $row.Model=[string]$xml.HSI.SPN
  Log "   -> SERVEUR HP : $pn (fw $($row.Firmware))  modele '$($row.Model)'" Green
  switch -Regex ($pn) {
   '(Lights-Out|iLO)\s*6' { $row.Generation='Gen11';  $row.Target='OneView'; Log "   -> iLO 6 (Gen11) => cible : OneView" Green }
   '(Lights-Out|iLO)\s*5' { $row.Generation='Gen10';  $row.Target='OneView'; Log "   -> iLO 5 (Gen10) => cible : OneView" Green }
   '(Lights-Out|iLO)\s*4' { $row.Generation='Gen8/9'; $row.Target='IAP';     Log "   -> iLO 4 (Gen8/9) => cible : iLO Amplifier Pack" Green }
   default                { $row.Generation='?';      $row.Target='?';       Log "   -> version iLO inconnue => cible a definir" Yellow }
  }
  return 'hp'
 }

 # 2) Sinon : racine Redfish + entete Server pour deviner le vendor (Dell, Lenovo, Cisco...)
 Log "   curl https://$ip/redfish/v1/  (racine Redfish)..." Gray
 try { $rr = Get-RedfishRoot $ip }
 catch { $row.Vendor='?'; $row.iLO='non-redfish'; Log "   -> echec Redfish : $_" DarkYellow; return 'none' }

 $oem = @(); if ($rr.Body -and $rr.Body.Oem) { $oem = $rr.Body.Oem.PSObject.Properties.Name }
 $row.Vendor = Detect-Vendor ("{0} {1} {2} {3}" -f ($oem -join ' '), $rr.Server, $rr.Body.Vendor, $rr.Body.Product)
 $row.iLO    = [string]$rr.Body.Product
 Log "   -> Vendor=$($row.Vendor)  Server='$($rr.Server)'  Oem='$($oem -join ',')'" Green
 return 'other'
}

function Phase2-Identify {
 Log "===== PHASE 2 : IDENTIFICATION =====" Cyan
 $creds = @(Get-KnownCreds)
 Log "[INFO] $($creds.Count) identifiants charges" Cyan

 $mode = (Read-Host "(C)ontinuer hotes vivants [defaut]  (R)etester acces refuses  (T)out refaire").ToUpper()
 $todo = switch ($mode) { 'R' { @('alive','no-access') } 'T' { @('alive','no-access','not-hp','ready','sent') } default { @('alive') } }
 $targets = @($script:State.Values | Where-Object { $_.Alive -eq 'True' -and $_.Status -in $todo })
 Log "[INFO] $($targets.Count) hote(s) a identifier" Cyan

 foreach ($row in $targets) {
  $ip = $row.IP
  Log "[IDENT] $ip" White

  $cat = Identify-Host $row
  if ($cat -eq 'none') {
   $row.Target=''; $row.Status='not-hp'
   Log "   -> aucune reponse (port 443 ferme ou non-BMC)" Yellow
   Save-Server $row; continue
  }
  if ($cat -eq 'other') {
   $row.Target=''; $row.Status='not-hp'
   Log "   -> $($row.Vendor) : PAS un serveur HP (pas d'ajout OneView/IAP)" Yellow
   Save-Server $row; continue
  }
  # cat = 'hp' : Vendor / iLO / modele / cible deja renseignes par Identify-Host

  # Test des mots de passe via SSH (pour confirmer l'acces avant ajout)
  Log "   [SSH] test des identifiants connus..." Gray
  $row.PasswordFound='False'; $row.KeyFile=''
  foreach ($k in $creds) {
   Log "      essai '$($k.File)'..." DarkGray
   try { $s = New-SSHSession -ComputerName $ip -Credential $k.Cred -AcceptKey -ConnectionTimeout 8 -EA Stop
         $row.PasswordFound='True'; $row.KeyFile=$k.File; Remove-SSHSession $s | Out-Null
         Log "   -> ACCES OK avec la cle '$($k.File)'" Green
         break
   } catch { Start-Sleep -Milliseconds 500 }
  }
  if ($row.PasswordFound -eq 'True') { $row.Status='ready' }
  else { $row.Status='no-access'; Log "   -> AUCUN identifiant ne fonctionne : ACCES REFUSE" Red }

  Save-Server $row
 }
 Log "[FINI] Phase 2 terminee." Cyan
}

# ---------- Diagnostic : tester 1 IP a la main ----------
function Test-OneIP {
 $ip = Read-Host "IP iLO/BMC a tester"

 Write-Host "`n--- 1) HP  https://$ip/xmldata?item=all  (sans login) ---" -ForegroundColor Cyan
 $xml = Get-HpXmlData $ip
 if ($xml -and ($xml.MP.PN -match 'Lights-Out|iLO')) {
  Write-Host ("  PN (iLO)  : {0}" -f $xml.MP.PN)   -ForegroundColor Green
  Write-Host ("  Firmware  : {0}" -f $xml.MP.FWRI)
  Write-Host ("  Modele    : {0}" -f $xml.HSI.SPN)
  Write-Host ("  Serial    : {0}" -f $xml.HSI.SBSN)
  Write-Host "  => SERVEUR HP detecte" -ForegroundColor Green
 } else {
  Write-Host "  (pas de xmldata HP : non-HP, ou xmldata desactive sur l'iLO)" -ForegroundColor Yellow
 }

 Write-Host "`n--- 2) Racine Redfish  https://$ip/redfish/v1/ ---" -ForegroundColor Cyan
 try { $rr = Get-RedfishRoot $ip }
 catch { Write-Host "  [ERREUR] pas de racine Redfish : $_" -ForegroundColor Red; return }
 $oem = @(); if ($rr.Body -and $rr.Body.Oem) { $oem = $rr.Body.Oem.PSObject.Properties.Name }
 Write-Host "  Server hdr: $($rr.Server)"
 Write-Host "  Product   : $($rr.Body.Product)"
 Write-Host "  Vendor    : $($rr.Body.Vendor)"
 Write-Host "  Oem       : $($oem -join ', ')"
 Write-Host ("  => Vendor deduit : {0}" -f (Detect-Vendor ("{0} {1} {2} {3}" -f ($oem -join ' '), $rr.Server, $rr.Body.Vendor, $rr.Body.Product))) -ForegroundColor Cyan
 Write-Host "`n--- JSON racine brut ---"
 $rr.Body | ConvertTo-Json -Depth 8
}

# ============================================================
#  iLO Amplifier Pack (REST)  >>> A CONFIRMER <<<
# ============================================================
function Connect-IAP([string]$ip, [pscredential]$cred) {
 $body = @{ UserName=$cred.UserName; Password=$cred.GetNetworkCredential().Password } | ConvertTo-Json
 $r = Invoke-WebRequest "https://$ip/redfish/v1/SessionService/Sessions" -Method Post -Body $body -ContentType 'application/json' -SkipCertificateCheck -SkipHeaderValidation -EA Stop
 $token = $r.Headers['X-Auth-Token']; if ($token -is [array]) { $token = $token[0] }
 [PSCustomObject]@{ IP=$ip; Token=$token }
}
function Get-IAPSystems($iap) {
 $h = @{ 'X-Auth-Token' = $iap.Token }
 $col = Invoke-RestMethod "https://$($iap.IP)/redfish/v1/AggregatorService/ManagedSystems" -Headers $h -SkipCertificateCheck
 foreach ($x in $col.Members) { try { (Invoke-RestMethod "https://$($iap.IP)$($x.'@odata.id')" -Headers $h -SkipCertificateCheck).ManagerAddress } catch {} }
}
function Add-IAPSystem($iap, [string]$iloIP, [pscredential]$cred) {
 $h = @{ 'X-Auth-Token' = $iap.Token }
 $body = @{ ManagerAddress=$iloIP; UserName=$cred.UserName; Password=$cred.GetNetworkCredential().Password } | ConvertTo-Json
 Invoke-RestMethod "https://$($iap.IP)/redfish/v1/AggregatorService/ManagedSystems" -Method Post -Headers $h -Body $body -ContentType 'application/json' -SkipCertificateCheck -EA Stop | Out-Null
}

# ============================================================
#  Gestion des comptes iLO via Redfish (authentifie, Basic Auth)
# ============================================================
function Basic-Header([pscredential]$cred) {
 $pair = "{0}:{1}" -f $cred.UserName, $cred.GetNetworkCredential().Password
 @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)) }
}
function ILO-Get([string]$ip, [string]$path, [pscredential]$cred) {
 $p = @{ Uri="https://$ip$path"; Headers=(Basic-Header $cred); TimeoutSec=10; ErrorAction='Stop' }
 if ($script:PS7) { $p.SkipCertificateCheck=$true }
 Invoke-RestMethod @p
}
function ILO-Send([string]$ip, [string]$path, [string]$method, $body, [pscredential]$cred) {
 $p = @{ Uri="https://$ip$path"; Method=$method; Headers=(Basic-Header $cred); ContentType='application/json'; TimeoutSec=15; ErrorAction='Stop' }
 if ($body) { $p.Body = ($body | ConvertTo-Json -Depth 6) }
 if ($script:PS7) { $p.SkipCertificateCheck=$true }
 Invoke-RestMethod @p
}
# Privileges Administrator, adaptes a la generation (iLO 4 = moins de droits)
function ILO-Privileges([string]$gen) {
 $p = [ordered]@{ LoginPriv=$true; RemoteConsolePriv=$true; UserConfigPriv=$true; VirtualMediaPriv=$true; VirtualPowerAndResetPriv=$true; iLOConfigPriv=$true }
 if ($gen -ne 'Gen8/9') { $p.HostBIOSConfigPriv=$true; $p.HostNICConfigPriv=$true; $p.HostStorageConfigPriv=$true; $p.SystemRecoveryConfigPriv=$true }
 $p
}
# Liste les comptes iLO : [{ UserName; Url }]
function Get-ILOAccounts([string]$ip, [pscredential]$cred) {
 $col = ILO-Get $ip "/redfish/v1/AccountService/Accounts/" $cred
 foreach ($m in $col.Members) {
  try { $a = ILO-Get $ip $m.'@odata.id' $cred; [PSCustomObject]@{ UserName=[string]$a.UserName; Url=[string]$m.'@odata.id' } } catch {}
 }
}
# Cree ou met a jour un compte iLO (mot de passe + privileges). Retourne 'cree'|'maj'|'inchange'
function Set-ILOUser([string]$ip, [pscredential]$admin, $userDef, [string]$gen, [bool]$updateExisting) {
 $name = $userDef.Cred.UserName
 $pwd  = $userDef.Cred.GetNetworkCredential().Password
 $priv = ILO-Privileges $gen
 $existing = @(Get-ILOAccounts $ip $admin) | Where-Object { $_.UserName -eq $name } | Select-Object -First 1
 if ($existing) {
  if (-not $updateExisting) { return 'inchange' }
  ILO-Send $ip $existing.Url 'PATCH' @{ Password=$pwd; Oem=@{ Hpe=@{ Privileges=$priv } } } $admin | Out-Null
  return 'maj'
 } else {
  ILO-Send $ip "/redfish/v1/AccountService/Accounts/" 'POST' @{ UserName=$name; Password=$pwd; Oem=@{ Hpe=@{ LoginName=$name; Privileges=$priv } } } $admin | Out-Null
  return 'cree'
 }
}

# ============================================================
#  PHASE 3 : AJOUT a une appliance (pick) + provisioning des comptes iLO
# ============================================================
function Phase3-Add {
 Log "===== PHASE 3 : AJOUT =====" Cyan
 $apps = @(Get-Appliances)
 if ($apps.Count -eq 0) {
  Write-Host "[INFO] Aucune appliance enregistree (menu 2). Saisie unique:"
  $t = (Read-Host "Type : (O)neView [defaut]  ou  (I)AP").ToUpper(); $type = if ($t -eq 'I') { 'IAP' } else { 'OneView' }
  $ip = Read-Host "IP de l'appliance"; $cred = Get-Credential -Message "Compte admin $type ($ip)"
  $app = [PSCustomObject]@{ Name='(saisie)'; Type=$type; IP=$ip.Trim(); Cred=$cred }
 } else {
  Write-Host "`nAppliances enregistrees:"
  for ($i=0; $i -lt $apps.Count; $i++) { Write-Host "  [$i] $($apps[$i].Name) [$($apps[$i].Type)] -> $($apps[$i].IP)" }
  $n = Read-Host "Numero de l'appliance"
  if (-not ($n -match '^\d+$') -or [int]$n -ge $apps.Count) { Write-Host "[WARN] choix invalide"; return }
  $app = $apps[[int]$n]
 }
 Log "[INFO] appliance : $($app.Name) [$($app.Type)] -> $($app.IP)" Cyan

 $candidates = @($script:State.Values | Where-Object { $_.Target -eq $app.Type -and $_.PasswordFound -eq 'True' })
 $noacc = @($script:State.Values | Where-Object { $_.Target -eq $app.Type -and $_.Status -eq 'no-access' }).Count
 if ($noacc -gt 0) { Log "[NOTE] $noacc serveur(s) '$($app.Type)' sans acces (voir rapport)" Yellow }
 if ($candidates.Count -eq 0) { Log "[INFO] Aucun serveur '$($app.Type)' pret." Yellow; return }

 $iap = $null
 if ($app.Type -eq 'OneView') {
  Log "[CONNEXION] OneView $($app.IP) ..." Gray
  try { Connect-OVMgmt -Appliance $app.IP -Credential $app.Cred -ErrorAction Stop | Out-Null } catch { Log "[ERREUR] Connexion OneView: $_" Red; return }
  $existingIPs = @(Get-OVServer | ForEach-Object { $_.mpHostInfo.mpIpAddresses.address })
 } else {
  Log "[CONNEXION] iLO Amplifier Pack $($app.IP) ..." Gray
  try { $iap = Connect-IAP $app.IP $app.Cred } catch { Log "[ERREUR] Connexion IAP: $_" Red; return }
  $existingIPs = @(Get-IAPSystems $iap)
 }
 Log "[INFO] $($existingIPs.Count) serveur(s) deja dans l'appliance" Cyan

 $present = @($candidates | Where-Object { $existingIPs -contains $_.IP })
 $new     = @($candidates | Where-Object { $existingIPs -notcontains $_.IP })

 Write-Host "`nDeja dans '$($app.Name)' ($($present.Count)):"
 foreach ($r in $present) { Write-Host "  - $($r.IP)  $($r.Model)"; if ($r.Status -ne 'sent' -or $r.Appliance -ne $app.Name) { $r.Status='sent'; $r.Appliance=$app.Name; Save-Server $r } }
 if ($present.Count -eq 0) { Write-Host "  (aucun)" }

 Write-Host "`nNouveaux a ajouter ($($new.Count)):"
 if ($new.Count -eq 0) { Write-Host "  (aucun) -- rien a faire."; if ($app.Type -eq 'OneView') { Disconnect-OVMgmt }; return }
 for ($i=0; $i -lt $new.Count; $i++) { Write-Host "  [$i] $($new[$i].IP)  $($new[$i].Model)  (cle: $($new[$i].KeyFile))" }

 $pick = Read-Host "Numeros separes par virgule, * pour tous, ou R pour annuler"
 if ($pick.ToUpper() -eq 'R') { if ($app.Type -eq 'OneView') { Disconnect-OVMgmt }; Log "[INFO] annule." Yellow; return }
 $chosen = if ($pick -eq '*') { $new } else { @($pick -split ',' | ForEach-Object { $new[[int]$_.Trim()] }) }

 # --- Provisioning des comptes iLO (optionnel) ---
 $provUsers = @(Get-ProvUsers)
 $doProv = $false
 if ($provUsers.Count -gt 0) {
  Write-Host "`nUtilisateurs iLO definis : $(($provUsers | ForEach-Object { $_.Cred.UserName }) -join ', ')"
  $doProv = (Read-Host "Creer/MAJ ces comptes sur les serveurs choisis avant l'ajout ? (O)ui [defaut] / (N)on").ToUpper() -ne 'N'
 }
 $ovUser = $provUsers | Where-Object ForOneView | Select-Object -First 1

 $creds = @(Get-KnownCreds)
 foreach ($r in $chosen) {
  $k = $creds | Where-Object File -eq $r.KeyFile | Select-Object -First 1
  if (-not $k) { Log "[WARN] $($r.IP): cle $($r.KeyFile) introuvable" Yellow; continue }

  $addCred = $k.Cred     # par defaut : le credential decouvert au scan

  # 1) Provisioning des comptes iLO (lecture -> creation/MAJ)
  if ($doProv) {
   Log "[USERS] $($r.IP) : lecture des comptes iLO..." Gray
   try {
    $before = @(Get-ILOAccounts $r.IP $k.Cred)
    Log "   comptes actuels : $(($before | ForEach-Object { $_.UserName }) -join ', ')" Gray
    foreach ($u in $provUsers) {
     try { $res = Set-ILOUser $r.IP $k.Cred $u $r.Generation $true
           Log "   -> $($u.Cred.UserName) : $res" Green }
     catch { Log "   -> $($u.Cred.UserName) : ERREUR $_" Red }
    }
    if ($ovUser) { $addCred = $ovUser.Cred }   # OneView se connectera avec ce compte
   } catch { Log "[USERS] $($r.IP) : ERREUR lecture comptes : $_" Red }
  }

  # 2) Ajout a l'appliance
  Log "[ADD] $($r.IP) -> $($app.Type) '$($app.Name)' (compte: $($addCred.UserName)) : ajout..." White
  try {
   if ($app.Type -eq 'OneView') { Add-OVServer -Hostname $r.IP -Credential $addCred -Monitored -ErrorAction Stop | Out-Null } else { Add-IAPSystem $iap $r.IP $addCred }
   $r.Status='sent'; $r.Appliance=$app.Name; Save-Server $r
   Log "[ADD] $($r.IP) -> OK, ajoute a '$($app.Name)'" Green
  } catch { Log "[ADD] $($r.IP) -> ERREUR: $_" Red }
 }
 if ($app.Type -eq 'OneView') { Disconnect-OVMgmt }
 Log "[FINI] Phase 3 terminee." Cyan
}

# ============================================================
#  RAPPORT / STATISTIQUES
# ============================================================
function Show-Report {
 $rows = @($script:State.Values)
 Write-Host "`n================ RAPPORT ================" -ForegroundColor Cyan
 if ($rows.Count -eq 0) { Write-Host "  (etat vide - lance d'abord un scan)"; return }

 $alive = @($rows | ? { $_.Alive -eq 'True' }); $dead = @($rows | ? { $_.Alive -eq 'False' })
 Write-Host ("  IP enregistrees      : {0}" -f $rows.Count)
 Write-Host ("  Vivants              : {0}" -f $alive.Count) -ForegroundColor Green
 Write-Host ("  Morts / sans reponse : {0}" -f $dead.Count)  -ForegroundColor DarkGray

 Write-Host "`n  --- Par statut ---"
 foreach ($g in ($rows | Group-Object Status | Sort-Object Name)) { Write-Host ("    {0,-10} : {1}" -f ($(if($g.Name){$g.Name}else{'(vide)'}), $g.Count)) }

 Write-Host "`n  --- Par vendor (BMC detecte) ---"
 foreach ($g in ($alive | Where-Object Vendor | Group-Object Vendor | Sort-Object Count -Descending)) {
  $c = if ($g.Name -eq 'HPE') { 'Green' } else { 'White' }
  Write-Host ("    {0,-12} : {1}" -f $g.Name, $g.Count) -ForegroundColor $c
 }

 $hp = @($rows | ? { $_.Vendor -eq 'HPE' })
 Write-Host "`n  --- HP par cible ---"
 foreach ($g in ($hp | Group-Object Target | Sort-Object Name)) { Write-Host ("    {0,-18} : {1}" -f ($(if($g.Name){$g.Name}else{'?'}), $g.Count)) }
 Write-Host "  --- HP par generation ---"
 foreach ($g in ($hp | Group-Object Generation | Sort-Object Name)) { Write-Host ("    {0,-8} : {1}" -f ($(if($g.Name){$g.Name}else{'?'}), $g.Count)) }

 Write-Host "`n  --- Avancement ---"
 Write-Host ("    PRETS (ready) : {0}" -f @($rows | ? { $_.Status -eq 'ready' }).Count) -ForegroundColor Green
 $sent = @($rows | ? { $_.Status -eq 'sent' })
 Write-Host ("    ENVOYES (sent): {0}" -f $sent.Count) -ForegroundColor Green
 foreach ($g in ($sent | Group-Object Appliance | Sort-Object Name)) { Write-Host ("        -> {0,-18} : {1}" -f ($(if($g.Name){$g.Name}else{'?'}), $g.Count)) }

 $noacc = @($rows | ? { $_.Status -eq 'no-access' })
 Write-Host ("`n  --- SANS ACCES (mot de passe introuvable) : {0} ---" -f $noacc.Count) -ForegroundColor Red
 foreach ($r in ($noacc | Sort-Object IP)) { Write-Host ("    {0,-16} {1,-10} {2}" -f $r.IP, $r.Target, $r.Model) -ForegroundColor Red }

 Write-Host "`n  Etat : $out_file    Journal : $log_file"
 Write-Host "=========================================" -ForegroundColor Cyan
}

# ============================================================
#  MENU PRINCIPAL
# ============================================================
Load-State
while ($true) {
 Write-Host "`n===== DECOUVERTE SERVEURS HP (v8) ====="
 Write-Host " (1) Identifiants iLO/SSH      (2) Appliances (OneView / IAP)"
 Write-Host " (3) Utilisateurs iLO (creer/MAJ)"
 Write-Host " (4) Phase 1 : Scan reseau     (5) Phase 2 : Identification"
 Write-Host " (6) Phase 3 : Ajout (+ users)  (7) Rapport / statistiques"
 Write-Host " (8) Tester 1 IP (diagnostic)  (Q) Quitter"
 switch ((Read-Host "Choix").ToUpper()) {
  '1' { Manage-Creds }
  '2' { Manage-Appliances }
  '3' { Manage-Users }
  '4' { $subs = @(Read-SubnetFile); if ($subs.Count -eq 0) { Write-Host "[WARN] aucun sous-reseau"; break }
        Write-Host "`nSous-reseaux disponibles:"; for ($i=0; $i -lt $subs.Count; $i++) { Write-Host "  [$i] $($subs[$i])" }
        $pick = Read-Host "Numeros separes par virgule, ou * pour tous"
        if ($pick -eq '*') { Phase1-Scan $subs } else { Phase1-Scan @($pick -split ',' | ForEach-Object { $subs[[int]$_.Trim()] }) } }
  '5' { Phase2-Identify }
  '6' { Phase3-Add }
  '7' { Show-Report }
  '8' { Test-OneIP }
  'Q' { return }
 }
}

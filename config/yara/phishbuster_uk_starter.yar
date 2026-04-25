/*
   PhishBuster UK — starter YARA ruleset
   Drop additional .yar files into this directory; they are auto-compiled
   on engine startup. severity meta drives the score weight (low / medium / high).
*/

rule HTML_Credential_Harvester_UK
{
    meta:
        author    = "PhishBuster UK"
        severity  = "high"
        description = "HTML attachment with login form posting to non-UK-bank host"
    strings:
        $form  = "<form" nocase
        $pw    = "type=\"password\"" nocase
        $login = "login" nocase
        $bank  = /\b(natwest|barclays|lloyds|hsbc|halifax|santander)\b/ nocase
    condition:
        all of them and filesize < 1MB
}

rule Phish_HTML_Auto_Submit
{
    meta:
        severity = "high"
        description = "HTML auto-submits a form to an external host on load"
    strings:
        $a = "onload" nocase
        $b = "submit()" nocase
        $c = "<form" nocase
    condition:
        all of them and filesize < 500KB
}

rule HMRC_Lure_HTML
{
    meta:
        severity = "high"
        description = "HMRC-themed HTML lure"
    strings:
        $hmrc1 = "HM Revenue" nocase
        $hmrc2 = /tax\s*refund/ nocase
        $form  = "<form" nocase
        $cred  = /password|sort\s*code|account\s*number|national\s*insurance/ nocase
    condition:
        2 of ($hmrc1, $hmrc2) and $form and $cred
}

rule Royal_Mail_Lure_HTML
{
    meta:
        severity = "high"
        description = "Royal Mail redelivery / parcel fee lure"
    strings:
        $rm1   = "Royal Mail" nocase
        $rm2   = /redeliver(y)?/ nocase
        $rm3   = /parcel|delivery\s*fee|small\s*shipping/ nocase
        $form  = "<form" nocase
    condition:
        2 of ($rm1, $rm2, $rm3) and $form
}

rule Suspicious_ISO_Container
{
    meta:
        severity = "medium"
        description = "ISO9660 image — often used to bypass MOTW"
    strings:
        $iso = "CD001"
    condition:
        $iso at 0x8001 or $iso at 0x8801
}

rule Suspicious_LNK_Loader
{
    meta:
        severity = "high"
        description = "Windows shortcut with PowerShell or cmd execution"
    strings:
        $magic = { 4C 00 00 00 01 14 02 00 }
        $ps    = "powershell" nocase
        $cmd   = "cmd.exe" nocase
        $iex   = "IEX" nocase
    condition:
        $magic at 0 and any of ($ps, $cmd, $iex)
}

rule Office_VBA_With_Shell_Exec
{
    meta:
        severity = "high"
        description = "Office VBA macro invoking shell/CreateObject/Wscript"
    strings:
        $vba   = "vbaProject"
        $shell = "Shell" nocase
        $crobj = "CreateObject" nocase
        $wsh   = /Wscript\.Shell/ nocase
    condition:
        $vba and 2 of ($shell, $crobj, $wsh)
}

rule Encoded_Powershell_Payload
{
    meta:
        severity = "high"
        description = "PowerShell with -enc / -EncodedCommand / FromBase64String"
    strings:
        $a = /powershell.{0,40}-(e|en|enc|encoded(c|command))/ nocase
        $b = "FromBase64String" nocase
        $c = "::DownloadString" nocase
    condition:
        any of them
}

rule Double_Extension_Hint
{
    meta:
        severity = "low"
        description = "File with double extension suggestive of disguise"
    strings:
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".doc.exe" nocase
        $ext3 = ".invoice.html" nocase
        $ext4 = ".zip.exe" nocase
        $ext5 = ".jpg.scr" nocase
    condition:
        any of them
}

rule PS_AMSI_Bypass_Compact {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Detects a compact AMSI bypass attempt (or something obscure at the very least)"
		reference = "https://twitter.com/cyb3rops/status/1588574518057979905/photo/1"
	strings:
		$k1 = "|%{[char][" ascii nocase
		$k2 = "+($" ascii
		$s1 = ".Assembly.GetType([" ascii nocase
		$s2 = "SetValue(" ascii nocase
		$s3 = "GetField([" ascii nocase
		$s4 = "-replace" ascii nocase
	condition:
		filesize < 100KB and all of ($k*) and 2 of ($s*)
}

/*
PS_AMSI_Bypass_Compact florian_roth_20221104.bin
0x99:$k1: |%{[char][
0xf2:$k1: |%{[char][
0xaa:$k2: +($
0x103:$k2: +($
0x79:$s1: .Assembly.GetType([
0x14a:$s2: SetValue(
0xda:$s3: GetField([
0xca:$s4: -replace
0x123:$s4: -replace

===============

$A="5492868772801748688168747280728187173688878280688776828"
$B="1173680867656877679866880867644817687416876797271"
[Ref].Assembly.GetType([string](0..37|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " " ).
GetField([string](38..51|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " ",'Non' + 'Public,Static').
SetValue($null,$true)
*/

rule PS_Char_Concat {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Common PowerShell char concatenation pattern"
		category = "hunting"
	strings:
		$s1 = "+[Char]" nocase
		$s2 = /\[Char\][0-9]{1,3}\s*\+\s*\[Char\][0-9]{1,3}/ nocase
	condition:
		all of ($s*)	
}

rule PS_Casing_StringChar_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Weird casing on '[String][Char]' with a negation for this exact casing"
		category = "hunting"
	strings:
		$s1 = "[String][Char]" nocase
		$n1 = "[String][Char]"
	condition:
		$s1 and not $n1
}

rule PS_Casing_Replace_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Weird casing on the 'replace' PowerShell operation"
		category = "hunting"
	strings:
		$s1 = ".replace(" nocase
		$n1 = ".replace("
		$n2 = ".Replace("
	condition:
		$s1 and not any of ($n*)
}

rule PS_Casing_Replace_2 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Weird casing on the 'replace' PowerShell operation"
		category = "hunting"
	strings:
		$s1 = "-replace(" nocase
		$n1 = "-replace("
		$n2 = "-Replace("
	condition:
		$s1 and not any of ($n*)
}

rule PS_ArrayOrdering_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Obfuscated PowerShell grabbing elements from an array, typically when concatenating payloads or strings"
		category = "hunting"
	strings:
		$s1 = "(\"{0}{1}{2}"
	condition:
		$s1
}

rule PS_reverse_strings_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Basic left-to-right or left-to-right obfuscation use - includes network comms"
		category = "hunting"
	strings:
		$ps = "powershell" ascii wide nocase
		$r_env = ":vne$" ascii wide
		$r_new_obj = "jbO-weN(" ascii wide
		$r_download = "olnwoD." ascii wide
		$direction_l2r = "LeftToRight"
		$direction_r2l = "RightToLeft"
	condition:
		$ps in (0..100) and 1 of ($r_*) and 1 of ($direction_*) and filesize < 10KB
}

rule PS_Char_Byte {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Common PowerShell obfuscation pattern"
		category = "hunting"
	strings:
		$obfus = "[char]([byte]0x" ascii nocase
	condition:
		filesize < 800KB and #obfus > 30
}

rule PS_AMSI_Bypass_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "AMSI Bypass PowerShell script"
		category = "hunting"
	strings:
		$dll_imp = "[DllImport(\"kernel32\")]" ascii
		$api = "LoadLibrary" ascii
		$obfus_1 = ".normalize(" ascii nocase
		$obfus_2 = "[char]([byte]0x" ascii nocase
	condition:
		filesize < 800KB and $dll_imp and $api and $obfus_1 and #obfus_2 > 5
}

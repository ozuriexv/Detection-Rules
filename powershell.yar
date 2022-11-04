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

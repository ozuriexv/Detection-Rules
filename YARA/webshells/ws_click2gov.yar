rule jsp_webshell_click2gov : Windows {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		reference = "https://www.fireeye.com/blog/threat-research/2018/09/click-it-up-targeting-local-government-payment-portals.html"
		hash = "CC155B8CD261A6ED33F264E710CE300E"
		date = "20-09-2018"
		category = "malware"
		malfamily = "click2gov"
	strings:
		$jsp = { 3c 25 40 }
		$p1 = "String PASS = \"098f6bcd4621d373cade4e832627b4f6\""
		$p2 = "String PASS = \"09a0aa1091460d23e5a68550826b359b\""
		$cmd1 = { 69 66 20 28 4F 53 2E 73 74 61 72 74 73 57 69 74 68 28 22 57 69 6E 64 6F 77 73 22 29 29 20 7B 0A 09 09 09 [1-10] 5B 30 5D 3D 22 63 6D 64 22 3B 0A 09 09 09 [1-10] 5B 31 5D 3D 22 2F 63 22 3B }
		$cmd2 = { 5B 30 5D 3D 22 2F 62 69 6E 2F 73 68 22 3B 0A 09 09 09 [1-10] 5B 31 5D 3D 22 2D 63 22 }
	condition:
		($jsp at 0) and ((1 of ($cmd*)) or 1 of ($p*))
}

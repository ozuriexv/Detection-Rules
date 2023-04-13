rule cve_2020_1300 : Windows Exploit {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "CVE-2020-1300 - .cab directory traversal"
		reference = "https://www.thezdi.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files"
		category = "exploit"
		date = "10-07-2020"
	strings:
		$exp_str = "../../"
		$exp_re = /(\.\.\/){2}[A-Za-z0-9_\-\/\.]+\x00/
	condition:
		uint32be(0) == 0x4d534346 and all of ($exp_*)
}

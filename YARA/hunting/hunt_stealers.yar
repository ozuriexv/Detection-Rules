rule gen_stealer_paths_appdata_moz {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Roaming\\Mozilla\\Firefox\\logins.json" ascii nocase
		$s2 = /\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\[a-z0-9.-\s]+\\(cookies\.sqlite|logins\.json|formhistory\.sqlite)/ nocase
		$s3 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\formhistory.sqlite" ascii nocase
		$s4 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\logins.json" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_wallets {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = /\\AppData\\Roaming\\[a-z0-9\s]+\\(wallets\\)?wallets\.dat/ ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_comodo {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Local\\Comodo\\Dragon\\User Data\\Web Data" ascii nocase
		$s2 = "\\AppData\\Local\\Comodo\\Dragon\\User Data\\Cookies" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_opera {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Roaming\\Opera Software\\Web Data" ascii nocase
		$s2 = "\\AppData\\Roaming\\Opera Software\\Cookies" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_chrome {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data" ascii nocase
		$s2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_chromium {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Local\\Chromium\\User Data\\Web Data" ascii nocase
		$s2 = "\\AppData\\Local\\Chromium\\User Data\\Cookies" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

rule gen_stealer_paths_appdata_windows {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Generic paths often used by stealers"
		category = "hunting"
		date = "12-05-2020"
	strings:
		$s1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\" ascii nocase
	condition:
		uint16be(0) == 0x4d5a and filesize < 3MB and any of ($s*)
}

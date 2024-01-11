rule PS_Github_Integration {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@ozuriexv"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Searching for the use of Github in a PowerShell script, somewhere near the '-Uri' parameter"
		category = "hunting"
	strings:
		$host = "github" nocase
		$uri = "-Uri" nocase
		$var = /\$uri\s*=\s*\x22[^\x22]{4,30}github/  nocase
	condition:
		for all i in (1..#uri) : ($host in (@uri[i]..@uri[i]+150)) or $var
}

rule PS_Telegram_Integration {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@ozuriexv"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Searching for the use of Telegram in a PowerShell script, somewhere near the '-Uri' parameter"
		category = "hunting"
	strings:
		$host = "telegram" nocase
		$uri = "-Uri" nocase
		$var = /\$uri\s*=\s*\x22[^\x22]{4,30}telegram/ nocase
	condition:
		for all i in (1..#uri) : ($host in (@uri[i]..@uri[i]+150)) or $var
}

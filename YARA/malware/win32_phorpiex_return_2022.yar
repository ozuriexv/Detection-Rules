rule phorpiex_return {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
    		description = "Detects new Phorpiex, barebones, downloader component."
    		reference = "b22b92d3736d46ec635e39270782ba3b2407e465212d222723e3b709df0e95ee"
	strings:
		$nomnom_str = { 56 57 be ?? ?? ?? ?? 8d 7d ?? a5 66 a5 a4 8b 7d ?? 57 33 f6 e8 }
		$user_agent = "Mozilla/5.0 (Windows NT 10.0;" ascii wide
		$filename_format = "%s\\%d%d.scr" ascii wide
		$jpg_format = /%s\\[0-9]{4,8}\.jpg/ ascii wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 200KB and ($nomnom_str or ($user_agent and $filename_format and $jpg_format))
}

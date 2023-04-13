rule js_obfus_0x_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Detects common method of JS obfuscation"
	strings:
		$c_1 = "+parseInt(_0x" ascii
		$c_2 = "var _0x" ascii
		$c_3 = "(0x" ascii

		$js_1 = "function(_0x" ascii
		$js_2 = "return _0x" ascii
		$js_3 = "function _0x"

	condition:
		filesize < 500KB and #c_1 > 3 and #c_2 > 5 and #c_3 > 10 and all of ($js_*)
}

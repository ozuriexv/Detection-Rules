rule xor_dos_header_fake_magic : Windows XOR Obf {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Looks for XORed DOS header with file magic of another file"
		category = "hunting"
		date = "02-07-2020"
	strings:
		$magic = {(42 5a 68 | 47 49 46 38 ?? 61 | 49 49 2a 00 | 4d 4d 00 2a | ff d8 ff (db | e0 | ee | e1) | 50 4b 0? 0? | 52 61 72 21 1a 07 | 7f 45 4c 46 | 89 50 4e 47 | ca fe ba be | 25 50 44 46 2d | d0 cf 11 e0 a1 b1 1a e1 | 75 73 74 61 72 (00 30 30|20 20 00) | 37 7a bc af 27 1c | 1f 8b | fd 37 7a 58 5a 00 | (43 | 46) 57 53 | 7b 5c 72 74 66 31)}
		$xor = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii
	condition:
		$magic at 0 and $xor
}

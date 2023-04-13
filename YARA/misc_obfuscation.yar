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

rule obf_vbs_26062020 : Windows VBS Obf {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Obfuscated VBS stuff"
		reference = "https://blog.morphisec.com/obfuscated-vbscript-drops-zloader-ursnif-qakbot-dridex"
		category = "hunting"
		date = "26-06-2020"
	strings:
		$execg = "ExecuteGlobal(determinate(" ascii
		$obf1 = /=\sArray\(([A-Za-z0-9]{2,8},\s?){20,400}[A-Za-z0-9]{2,8}\)/
	condition:
		#execg > 10 and #obf1 > 4
}

/*
filesizes on *_api_xor rules limited to 1MB for performance reasons
*/

rule win_registry_api_xor {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "XOR on various common Windows APIs"
		category = "hunting"
	strings:
		$s1 = "RegCreateKey" xor(0x01-0xff) ascii wide
		$s2 = "RegDeleteKey" xor(0x01-0xff) ascii wide
		$s3 = "RegEnumKey" xor(0x01-0xff) ascii wide
		$s4 = "RegGetValue" xor(0x01-0xff) ascii wide
		$s5 = "RegOpenKey" xor(0x01-0xff) ascii wide
		$s6 = "RegQueryValue" xor(0x01-0xff) ascii wide
		$s7 = "RegSetValue" xor(0x01-0xff) ascii wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 1MB and 1 of them
}

rule win_wmi_api_xor {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "XOR on various common Windows APIs"
		category = "hunting"
	strings:
		$s1 = "WmiEnumerateGuids" xor(0x01-0xff) ascii wide
		$s2 = "WmiExecuteMethod" xor(0x01-0xff) ascii wide
		$s3 = "WmiNotificationRegistration" xor(0x01-0xff) ascii wide
		$s4 = "WmiQueryAllData" xor(0x01-0xff) ascii wide
		$s5 = "WmiSetSingle" xor(0x01-0xff) ascii wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 1MB and 1 of them
}

rule win_k32_api_xor {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "XOR on various common Windows APIs"
		category = "hunting"
	strings:
		$s1 = "IsDebuggerPresent" xor(0x01-0xff) ascii wide
		$s2 = "LoadLibrary" xor(0x01-0xff) ascii wide
		$s3 = "LoadResource" xor(0x01-0xff) ascii wide
		$s4 = "MapViewOfFile" xor(0x01-0xff) ascii wide
		$s5 = "Module32First" xor(0x01-0xff) ascii wide
		$s6 = "Module32Next" xor(0x01-0xff) ascii wide
		$s7 = "Process32First" xor(0x01-0xff) ascii wide
		$s8 = "Process32Next" xor(0x01-0xff) ascii wide
		$s9 = "ReadProcessMemory" xor(0x01-0xff) ascii wide
		$s10 = "ResumeThread" xor(0x01-0xff) ascii wide
		$s11 = "VirtualAlloc" xor(0x01-0xff) ascii wide
		$s12 = "WriteProcessMemory" xor(0x01-0xff) ascii wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 1MB and 1 of them
}

rule win_winsock_wininet_api_xor {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "XOR on various common Windows APIs"
		category = "hunting"
	strings:
		$s1 = "HttpAddRequestHeaders" xor(0x01-0xff) ascii wide
		$s2 = "HttpOpenRequest" xor(0x01-0xff) ascii wide
		$s3 = "HttpQuery" xor(0x01-0xff) ascii wide
		$s4 = "HttpSendRequest" xor(0x01-0xff) ascii wide
		$s5 = "HttpWebSocket" xor(0x01-0xff) ascii wide
		$s6 = "InternetCheckConnection" xor(0x01-0xff) ascii wide
		$s7 = "InternetCombineUrl" xor(0x01-0xff) ascii wide
		$s8 = "InternetConnect" xor(0x01-0xff) ascii wide
		$s9 = "InternetCrackUrl" xor(0x01-0xff) ascii wide
		$s10 = "InternetCreateUrl" xor(0x01-0xff) ascii wide
		$s11 = "InternetOpen" xor(0x01-0xff) ascii wide
		$s12 = "InternetRead" xor(0x01-0xff) ascii wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 1MB and 1 of them
}

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

rule T1038_Lateral_Movement_SCM_DLL_Hijack : Windows LateralMovement T1038 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Detects possible lateral movement via copying specially crafted DLLs to specific paths."
		date = "20-04-2019"
		reference = "https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992"
		reference = "https://github.com/djhohnstein/wlbsctrl_poc"
		reference = "https://github.com/djhohnstein/TSMSISrv_poc"
		malfamily = "DLLHijack"
		category = "LateralMovement"
		mitre = "T1038"
	strings:
		$re_poc1 = /\\\\(([0-9]{1,3}\.){3}[0-9]{1,3}|([a-z0-9\-]{1,30}\.){1,8}[a-z]{1,8})\s*(stop|start)\s*(IKEEXT|SessionEnv)/i
		$re_poc2 = /copy\s*(wlbsctrl|TSMSISrv)\.dll\s*\\\\(([0-9]{1,3}\.){3}[0-9]{1,3}|([a-z0-9\-]{1,30}\.){1,8}[a-z]{1,8})\\\w\$\\Windows\\System32\\(wlbsctrl|TSMSISrv)\.dll/i

		$poc1_str1 = "stop IKEEXT" ascii wide
		$poc1_str2 = "copy wlbsctrl.dll \\\\" ascii wide
		$poc1_str3 = "\\Windows\\System32\\wlbsctrl.dll" ascii wide
		$poc1_str4 = "start IKEEXT" ascii wide

		$poc2_str1 = "stop SessionEnv" ascii wide
		$poc2_str2 = "copy TSMSISrv.dll \\\\" ascii wide
		$poc2_str3 = "\\Windows\\System32\\TSMSISrv.dll" ascii wide
		$poc2_str4 = "start SessionEnv" ascii wide
	condition:
		1 of ($re_poc*) or 3 of ($poc1_*) or 3 of ($poc2_*)
}

rule mz_spam_pdb_hunting : Windows PE Hunting {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
        	description = "PDB containing 'spam' string inspired by FireEye research."
        	category = "hunting"
        	date = "30-08-2019"
	strings:
		$pdb_str = "spam" ascii nocase
		$pdb_re = /RSDS[\x00-\xFF]{1,300}:\\[\x00-\xFF]{1,300}spam[^\.]+\.pdb\x00/ nocase
	condition:
		uint16be(0) == 0x4d5a and $pdb_str and $pdb_re
}

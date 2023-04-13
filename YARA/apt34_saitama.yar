rule apt34_saitama_agent_alphabet : Windows DNS {
	meta:
		author = "James E.C."
		description = "Custom alphabet used by APT34's Saitama Agent"
		hash = "E0872958B8D3824089E5E1CFAB03D9D98D22B9BCB294463818D721380075A52D"
	strings:
		$a = "razupgnv2w01eos4t38h7yqidxmkljc6b9f5" wide fullword
	condition:
		uint16be(0) == 0x4d5a and $a and filesize < 200KB
}

rule apt34_saitama_agent_pdb : Windows DNS {
	meta:
		author = "James E.C."
		description = "Snippets of APT34's Saitama Agent PDB"
		hash = "E0872958B8D3824089E5E1CFAB03D9D98D22B9BCB294463818D721380075A52D"
	strings:
		$pdb1 = "E:\\Saitama\\" ascii
		$pdb2 = "\\Saitama.Agent\\obj"
	condition:
		uint16be(0) == 0x4d5a and 1 of ($pdb*) and filesize < 200KB
}

rule apt34_saitama_agent_base_ps : Windows DNS {
	meta:
		author = "James E.C."
		description = "Snippets of base64 PowerShell commands used in APT34's Saitama Agent"
		hash = "E0872958B8D3824089E5E1CFAB03D9D98D22B9BCB294463818D721380075A52D"
	strings:
		$ja_ps = "JAAoAHAAaQBuAGcA" wide
		$rw_ps = "RwBlAHQALQB" wide
	condition:
		uint16be(0) == 0x4d5a and filesize < 200KB and #ja_ps > 4 and #rw_ps > 4
}

rule apt34_saitama_agent_main : Windows DNS {
	meta:
		author = "James E.C."
		description = "Various function names from APT34's Saitama Agent"
		hash = "E0872958B8D3824089E5E1CFAB03D9D98D22B9BCB294463818D721380075A52D"
	strings:
		$f1 = "DataSendedAndHasData" ascii fullword
		$f2 = "DataSendedAndReceived" ascii fullword
		$f3 = "MachineCommand" ascii fullword
		$f4 = "CompressedCmd" ascii fullword
		
		$k1 = "SleepAlive : Start" wide fullword
		$k2 = "Saitama.Agent" wide fullword
	condition:
		uint16be(0) == 0x4d5a and filesize < 200KB and (3 of ($f*) or 1 of ($k*))
}

rule xml_encoded_2021_40444 : Windows CVE {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
		notes = "According to @DissectMalware, 'External' is case sensitive so parts of the $targetmode PCRE may never hit."
		hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E" // document.xml
		hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69" // original .docx
	strings:
		$xml = "<?xml" ascii wide
		$mhtml = /Target\s*=\s*\"([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/ ascii wide
		$targetmode = /TargetMode\s*=\s*\"([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/ ascii wide
	condition:
		filesize < 500KB and $xml in (0..50) and $mhtml and $targetmode
}

/*
xml_encoded_2021_40444 .\document.xml.rels
0x442:$xml_e: Target="&#109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#116;&#112;
0x442:$xml_r: Target="&#109;&#104;&#116;&#109;&#108;&#58;
0x62d:$t_mode_e: TargetMode="&#x45;&#x78;&#x74;&#x65;&#x72;&#x6e;&#x61;&#x6c;"
0x62d:$t_mode_r: TargetMode="&#x45;&#x78;&#x74;
*/

rule xml_obfus_hunting_1 {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "Suspicious leading 0's in XML entity encoding"
		credit = "@DissectMalware, @cyb3rops"
	strings:
		$xml = "<?xml" ascii wide
		$leading_1 = "&#00" ascii wide
		$leading_2 = "&#x00" ascii wide
	condition:
		filesize < 500KB and $xml in (0..50) and 1 of ($leading_*)
}

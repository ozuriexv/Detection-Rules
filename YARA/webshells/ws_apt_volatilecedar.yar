rule apt_volatilecedar_aspwebshell : APT WebShell {
	meta:
		author = "James E.C, Emerging Threats - Proofpoint"
		twitter = "@EcOzurie"
		mastodon = "https://infosec.exchange/@ozurie"
		description = "ASP WebShell used by Volatile Cedar"
		hashes = "1dc13fe7f576f5c5ccac4230bdf2122d8351dd50266d0b712291ce59d1c788ae"
	strings:
		$jsp = { 3c 25 40 }
	
		$s1 = "exec master..xp_regwrite" ascii nocase
		$s2 = "%execute(request(chr(35)))%" ascii nocase
		$s3 = "Text=\"Exploit\"" ascii nocase
		$s4 = "Exec Cmd.................\\r\\n" ascii nocase
		$s5 = "xp_cmdshell" ascii nocase
		$s6 = "xplog70.dll" ascii nocase
		$s7 = "odsole70.dll" ascii nocase
		$s8 = "SandBoxMode" ascii nocase

		$header1 = "<%--CloneTime--%>"
		$header2 = "<%--UserInfo--%>"
		$header3 = "<%--Reg--%>"
		$header4 = "<%--SuExp--%>"
		$header5 = "<%--FileEdit--%>"
		$header6 = "<%--FileList--%>"

		$pass1 = "string Password=\"8b1a9953c4611296a827abf8c47804d7\""
		$pass2 = "value=\"#l@$ak#.lk;0@P\""
	condition:
		($jsp at 0) and (6 of ($s*) and 4 of ($header*) or $pass1 or $pass2)
}

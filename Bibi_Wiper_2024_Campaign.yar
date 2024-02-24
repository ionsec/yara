rule BiBi_2024_detector { 
	meta: 
		description = "Detects bibi wiper fresh 2024 campaign" 
		author = "IONsec.io"
		date = "2024-02-23"
		
	strings: 
		$str1 = {47 65 74 44 72 69 76 65 54 79 70 65 41}
		$str2 = {47 65 74 4C 6F 67 69 63 61 6C 44 72 69 76 65 73}
		$str3 = "Deleting Disk" ascii wide nocase
		$str4 = {65 74 65 6C 65 64 20 6E 69 6D 64 61 73 73 76}
		$str5 = "bibi" ascii wide nocase
		
	condition: 
		all of them
}
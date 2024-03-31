rule Pizdaosla_detector { 
	meta: 
		description = "Detects Pizdaosla ransomware" 
		author = "IONSec.io"
		
	strings: 
		$str1 = {46 72 6F 6D 53 69 62 65 72 69 61 57 69 74 68 4C 6F 76 65}
		$str2 = {45 76 65 72 79 74 68 69 6E 67 33 32 2E 64 6C 6C}
		$str3 = {43 72 65 61 74 65 4D 75 74 65 78 57}
		$str4 = {75 6E 6C 6F 63 6B 65 72}
		
	condition: 
		all of them
}






rule RunningRAT : AAAAAA {
    meta:
        author = "AAAAAA"
        thanks_to1 = "AAAAAA"
        thanks_to2 = "AAAAA"
        description = "AAAAAA"
        date = "2021.05.10"
    strings:
        /* Executables */
        $s01 = "exe.tsohcvs" fullword ascii
        $s02 = "exe.erolpxei" fullword ascii
        $s03 = "rundll32.exe" fullword ascii

        /* Imports */
        $s04 = "paeHssecorPteG" fullword ascii
        $s05 = "sserddAcorPteG" fullword ascii
        $s06 = "AyrarbiLdaoL" fullword ascii
        $s07 = "teSlortnoCtnerruC" fullword ascii
        
        /* Folders */
        $s08 = "\\23metsyS\\" ascii
        $s09 = "\\23metsys\\" ascii
        $s10 = "%tooRmetsyS%" fullword ascii

        /* Libraries */
        $s11 = "%s%d.dll" ascii

        /* More strings and commands */
        $s12 = "del /f/q \"%s\"" ascii
        $s13 = "GUpdate" fullword ascii
        $s14 = "\"%s\",MainThread" ascii
        $s16 = "emankcosteg" fullword ascii
        $s15 = "%s\\%d.bak" fullword ascii
        $s17 = "ini.revreS\\" fullword ascii
        $s18 = "daerhTniaM,\"s%\" s%" ascii
        $s19 = "s% etadpUllD,\"s%\" 23lldnuR" ascii
        $s20 = "---DNE yromeMmorFdaoL" fullword ascii
        $s21 = "eMnigulP" fullword ascii
        $s22 = "/c ping 127.0.0.1 -n" ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
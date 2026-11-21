pub struct Dictionary {
    pub id: &'static str,
    pub description: &'static str,
    pub url: &'static str,
}

pub const CATALOG: &[Dictionary] = &[
    Dictionary {
        id: "common-1k",
        description: "SecLists / Xato: 1,000 common passwords (small first pass)",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt",
    },
    Dictionary {
        id: "common-10k",
        description: "SecLists: 10,000 common passwords",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    },
    Dictionary {
        id: "ncsc-100k",
        description: "SecLists / NCSC: 100,000 frequently used passwords",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    },
    Dictionary {
        id: "xato-1m",
        description: "SecLists / Xato: 1 million passwords (larger search)",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
    },
    Dictionary {
        id: "rockyou",
        description: "RockYou via naive-hashcat: about 134 MB; raw password bytes",
        url: "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    },
];

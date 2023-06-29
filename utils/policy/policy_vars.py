header_keys = [
    'action',
    'protocol',
    'source_ip',
    'source_port',
    'direction',
    'dest_ip',
    'dest_port'
]

general_keys = []

actions = ["alert", "log", "pass", "activate", "dynamic"]
protocols = ["tcp", "udp", "icmp", "ip"]

ipaddrs = [
    "any",
    "$HOME_NET",
    "$EXTERNAL_NET",
    "$DNS_SERVERS", 
    "$SMTP_SERVERS",
    "$HTTP_SERVERS",
    "$SQL_SERVERS"
    "$TELNET_SERVERS",
    "$SSH_SERVERS",
    "$FTP_SERVERS",
    "$SIP_SERVER"
]

ports = [
    "any",
    "$HTTP_PORTS",
    "$SHELLCODE_PORTS",
    "$ORACLE_PORTS",
    "$SSH_PORTS",
    "$FTP_PORTS",
    "$SIP_PORTS",
    "$FILE_DATA_PORTS",
    "$GTP_PORTS",
    "$AIM_PORTS"
]

directions = ["->" , "<>"] # -> : directional | <> : bidirectional

priority = {
    "maximum": 4,
    "minimum": 0
}

reference_systems = [
    "bugtraq",
    "cve",
    "nessus",
    "arachnids",
    "mcafee",
    "osvdb",
    "msb",
    "url"
]

classtypes = [
    "attempted-admin",
    "attempted-user",
    "inappropriate-content",
    "policy-violation",
    "shellcode-detect",
    "successful-admin",
    "successful-user",
    "trojan-activity",
    "unsuccessful-user",
    "web-application-attack",
    "attempted-dos",
    "attempted-recon",
    "bad-unknown",
    "default-login-attempt",
    "denial-of-service",
    "misc-attack",
    "non-standard-protocol",
    "rpc-portmap-decode",
    "successful-dos",
    "successful-recon-largescale",
    "successful-recon-limited",
    "suspicious-filename-detect",
    "suspicious-login",
    "system-call-detect",
    "unusual-client-port-connection",
    "web-application-activity",
    "icmp-event",
    "misc-activity",
    "network-scan",
    "not-suspicious",
    "protocol-command-decode",
    "string-detect",
    "unknown",
    "tcp-connection"
]

metadata_keys = ["engine", "soid", "service"]
metadata_engine_values = ["shared"]
metadata_service_values = [
    "http",
    "dcerpc",
    "dns",
    "imap",
    "ftp",
    "netbios-dgm",
    "isakmp",
    "pop2",
    "ftp-data",
    "netbios-ssn",
    "oracle",
    "snmp",
    "smtp",
    "nmtp",
    "cvs",
    "ssh",
    "finger",
    "shell",
    "tftp",
    "sunrpc",
    "x11"
]

# -------------------------------------- Detection ---------------------------------------------

http_encode_options = ["uri", "header", "cookie"]
http_encoding_types = ["utf8", "double_encode", "non_ascii", "uencode", "bare_type", "ascii", "iis_encode"]

# -------------------------------------- Non-Detection -----------------------------------------

ipopts_options = ["rr", "eol", "nop", "ts", "sec", "esec", "lsrr", "lsrre", "ssrr", "satid", "any"]

flag_bits = ["F", "S", "R", "P", "A", "U", "C", "E", "0"]

flow_options = [
    "established",
    "not_established",
    "stateless",

    "to_client",
    "to_server",
    "from_client",
    "from_server",

    "no_stream",
    "only_stream",

    "no_frag",
    "only_frag"
]

flowbits_options = ["set", "setx", "unset", "toggle", "isset", "isnotset", "noalert", "reset"]

ip_protos = ["tcp", "udp", "icmp", "ip", "igmp"]

# -------------------------------------- Post-Detection ----------------------------------------

hash_algorithms = ["md5", "sha256", "sha512"]


bool_options = [
    "nocase",
    "rawbytes",
    "http_header",
    "http_raw_header",
    "http_cookie",
    "http_uri",
    "http_raw_uri",
    "fast_pattern"
]

have_modifiers = [
    "content",
    "protected_content",
    "uricontent",
]

modifiers = {
    "content":[
        "nocase",
        "rawbytes",
        "depth",
        "offset",
        "distance",
        "within",
        "http_client_body",
        "http_cookie",
        "http_raw_cookie",
        "http_header",
        "http_raw_header",
        "http_method",
        "http_uri",
        "http_raw_uri",
        "http_stat_code",
        "http_stat_msg",
        "fast_pattern"
    ],
    "protected_content": [
        "hash",
        "length",
        "offset",
        "distance",
        "http_client_body",
        "http_cookie",
        "http_raw_cookie",
        "http_header",
        "http_raw_header",
        "http_method",
        "http_uri",
        "http_raw_uri",
        "http_stat_code",
        "http_stat_msg",
    ],
    "uricontent": [
        "nocase",
        "depth",
        "offset",
        "distance",
        "within",
        "fast_pattern"
    ]
}


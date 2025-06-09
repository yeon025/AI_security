# fmt: off


# 띄어쓰기 구분해야 하는 문자열들
target_strings = [
    # OS Commanding
    "bin", "tftp", "exe", "uftp", "/cdir", "dir", "/c ", "echo",
    "systeminfo", "/etc", "ping", "Wget", "nc", "rm",

    # Path Traversal
    "etc",

    # SQL Injection
    "or", "union", "and", "INJECTED_PARAM", "select", "drop",
    "delete", "sqlmap", "else", "then", "from", "case", "when",

    # SSI
    "set", "email",
]


target_strings_2 = [
    # Ldap Injection
    ")(", "(&(", "(|(", "(||(", "*)", "*))",

    # OS Commanding
    "&&", ";", ">", "system",

    # Path Traversal
    "./", ".\\", "../", "~/", "/../",

    # SQL Injection
    "/**/", "‘’=’", "=(", ";--", "1=1",

    # SSI
    "<!--", "-->", "<!--#", "include", "cmd",

    # XPath Injection
    "//*", "]|//", "]|", "substring", "extractvalue",
    "user", "name", "|[", "1=1",

    # XSS
    "window", "open", "document", "cookie", "iframe",
    "link", "rel", "object", "meta", "http-equiv",
    "<script", "onerror", "<img", "<input", "style",
    "<embed", "video", "eval", "alert",

    # Shellshock
    "{:;};", "(){", "bash", ";}",
]



# Ldap Injection
Ldap_strings = [
    ")(", "(&(", "(|(", "(||(", "*)", "*))"
]

# OS Commanding
OC_strings = [
    "bin", "tftp", "exe", "uftp", "/cdir", "dir", "/c ", "echo",
    "systeminfo", "/etc", "ping", "Wget", "nc", "rm",
    "&&", ";", ">", "system",
]

# Path Traversal
PT_strings = [
    "etc", "./", ".\\", "../", "~/", "/../",
]

# SQL Injection
Sqli_strings = [
    "or", "union", "and", "INJECTED_PARAM", "select", "drop",
    "delete", "sqlmap", "else", "then", "from", "case", "when",
]

# Server Side Includes (SSI)
SSI_strings = [
    "set", "email",
    "<!--", "-->", "<!--#", "include", "cmd",
]

# XPath Injection
Xpath_strings = [
    "//*", "or", "and", "]|//", "]|",
    "substring", "extractvalue", "user", "name", "|[",
]

# Cross-Site Scripting (XSS)
XSS_strings = [
    "window", "open", "document", "cookie", "iframe",
    "link", "rel", "object", "meta", "http-equiv",
    "<script", "onerror", "<img", "<input", "style",
    "<embed", "video", "eval", "alert",
]

# Shellshock
SSH_strings = [
    "{:;};", "(){", "bash", ";}",
]

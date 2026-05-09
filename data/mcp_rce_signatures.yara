/*
 * MCP RCE Detection YARA Rules
 * 
 * Detects Model Context Protocol (MCP) server attack patterns based on
 * the OX Security April 2026 disclosure.
 * 
 * Categories:
 * - UI injection payloads (unauthenticated code execution)
 * - Marketplace poisoning (registry/supply chain attacks)
 * - JSON config-based RCE (LiteLLM CVE-2026-30623 style)
 * - Command execution patterns (shell metacharacters, reverse shells)
 * 
 * Usage:
 *     yara mcp_rce_signatures.yara /path/to/strace.log
 *     yara mcp_rce_signatures.yara /path/to/package/
 */

/* ========================================================================= */
/* UI INJECTION PAYLOADS                                                     */
/* ========================================================================= */

rule MCP_UI_HTML_Injection {
    meta:
        description = "Detects HTML injection payloads in MCP tool responses"
        severity = "high"
        attack_family = "ui_injection"
        cve = "CVE-2026-30624"
        mitre = "T1189"
    strings:
        $html_img_onerror = /<img\s+[^>]*onerror\s*=\s*["'][^"']*["']/ nocase
        $html_script_tag = /<script[^>]*>[\s\S]*?<\/script>/ nocase
        $html_iframe_srcdoc = /<iframe[^>]*srcdoc\s*=\s*["']/ nocase
        $fetch_document_cookie = /fetch\s*\(\s*["'][^"']*["'].*document\.cookie/ nocase
    condition:
        any of them
}

rule MCP_UI_Markdown_XSS {
    meta:
        description = "Detects Markdown-based XSS payloads with javascript: URIs"
        severity = "critical"
        attack_family = "ui_injection"
        cve = "CVE-2026-30624"
        mitre = "T1059.007"
    strings:
        $md_js_uri = /\[.*\]\s*\(\s*javascript\s*:/ nocase
        $md_eval_atob = /eval\s*\(\s*atob\s*\(\s*["'][A-Za-z0-9+/=]+["']\s*\)/ nocase
        $md_data_uri = /data\s*:\s*text\/html.*base64/ nocase
    condition:
        any of them
}

rule MCP_UI_SVG_Injection {
    meta:
        description = "Detects SVG-based injection with event handlers"
        severity = "critical"
        attack_family = "ui_injection"
        cve = "CVE-2026-30624"
        mitre = "T1059.004"
    strings:
        $svg_onload = /<svg[^>]*onload\s*=\s*["']/ nocase
        $svg_eval_chr = /eval\s*\(\s*String\.fromCharCode\s*\(/ nocase
        $svg_child_process = /require\s*\(\s*["']child_process["']\s*\)/ nocase
    condition:
        any of them
}

rule MCP_UI_CSS_Exfiltration {
    meta:
        description = "Detects CSS-based data exfiltration via @import"
        severity = "high"
        attack_family = "ui_injection"
        cve = "CVE-2026-30624"
        mitre = "T1005"
    strings:
        $css_import_url = /@import\s+url\s*\(\s*["']https?:\/\// nocase
        $css_attribute_selector = /\[class\s*[\^$*]?=\s*["'][^"']*["']\s*\]/ nocase
    condition:
        $css_import_url
}

/* ========================================================================= */
/* MARKETPLACE POISONING                                                     */
/* ========================================================================= */

rule MCP_Marketplace_Typosquatting {
    meta:
        description = "Detects typosquatting patterns in MCP server package names"
        severity = "critical"
        attack_family = "marketplace_poisoning"
        cve = "CVE-2026-30625"
        mitre = "T1195.001"
    strings:
        $typosquat_fs = /mcp-server-files{1,2}system/ nocase
        $typosquat_gh = /mcp-server-gi{1,2}thub/ nocase
        $typosquat_fetch = /mcp-{1,2}fetch/ nocase
        $postinstall_curl = /"postinstall"\s*:\s*".*curl.*\|\s*(bash|sh)"/ nocase
        $postinstall_wget = /"postinstall"\s*:\s*".*wget.*\|\s*(bash|sh)"/ nocase
    condition:
        ($typosquat_fs or $typosquat_gh or $typosquat_fetch) and ($postinstall_curl or $postinstall_wget)
}

rule MCP_Marketplace_DependencyConfusion {
    meta:
        description = "Detects dependency confusion attacks with high version numbers"
        severity = "critical"
        attack_family = "marketplace_poisoning"
        cve = "CVE-2026-30625"
        mitre = "T1195.001"
    strings:
        $high_version = /"version"\s*:\s*"[89]\d{2}\.\d+\.\d+"/ nocase
        $internal_scope = /"@internal\/[^"]+"/ nocase
        $exec_child_process = /require\s*\(\s*['"]child_process['"]\s*\)\s*\.exec/ nocase
        $reverse_shell = /bash\s+-i\s+>&\s+\/dev\/tcp\// nocase
    condition:
        $high_version and ($internal_scope or $exec_child_process or $reverse_shell)
}

rule MCP_Marketplace_SupplyChainBackdoor {
    meta:
        description = "Detects supply chain backdoors via malicious dependencies"
        severity = "critical"
        attack_family = "marketplace_poisoning"
        cve = "CVE-2026-30625"
        mitre = "T1195.001"
    strings:
        $malicious_dep_url = /"https?:\/\/[^\/]+\/.*\.tar\.gz"/ nocase
        $nc_reverse_shell = /nc\s+-e\s+\/bin\/(sh|bash)/ nocase
        $netcat_reverse_shell = /ncat\s+[^\/]+\/bin\/(sh|bash)/ nocase
        $exec_reverse = /exec\s*\(\s*['"]nc\s+/ nocase
    condition:
        $malicious_dep_url and ($nc_reverse_shell or $netcat_reverse_shell or $exec_reverse)
}

/* ========================================================================= */
/* JSON CONFIG-BASED RCE                                                     */
/* ========================================================================= */

rule MCP_Config_LiteLLM_Injection {
    meta:
        description = "Detects LiteLLM config injection via custom_llm_provider"
        severity = "critical"
        attack_family = "json_config_rce"
        cve = "CVE-2026-30623"
        mitre = "T1059.006"
    strings:
        $litellm_custom_provider = /"custom_llm_provider"\s*:\s*"/ nocase
        $import_os_system = /__import__\s*\(\s*['"]os['"]\s*\)\.system/ nocase
        $curl_pipe_bash = /curl\s+https?:\/\/[^\/]+\/[^\/]*\.sh\s*\|\s*bash/ nocase
        $litellm_params = /"litellm_params"\s*:/ nocase
    condition:
        ($litellm_custom_provider or $litellm_params) and ($import_os_system or $curl_pipe_bash)
}

rule MCP_Config_YAML_Deserialization {
    meta:
        description = "Detects YAML deserialization attacks executing arbitrary code"
        severity = "critical"
        attack_family = "json_config_rce"
        cve = "CVE-2026-30629"
        mitre = "T1059.006"
    strings:
        $yaml_python_object = /!!python\/object\/apply\s*:\s*os\.system/ nocase
        $yaml_python_module = /!!python\/module\s+os/ nocase
        $yaml_reduce = /__reduce__\s*:/ nocase
        $yaml_reverse_shell = /bash\s+-i\s+.*\/dev\/tcp\// nocase
    condition:
        ($yaml_python_object or $yaml_python_module or $yaml_reduce) and $yaml_reverse_shell
}

rule MCP_Config_EnvVariableInjection {
    meta:
        description = "Detects environment variable injection for code execution"
        severity = "critical"
        attack_family = "json_config_rce"
        cve = "CVE-2026-30628"
        mitre = "T1574.007"
    strings:
        $node_options_require = /"NODE_OPTIONS"\s*:\s*["']--require\s+/ nocase
        $pythonpath_injection = /"PYTHONPATH"\s*:\s*["']\/tmp\// nocase
        $ld_preload_injection = /"LD_PRELOAD"\s*:\s*["']\/tmp\/.*\.so["']/ nocase
        $env_config_block = /"environment"\s*:\s*\{/ nocase
    condition:
        $env_config_block and ($node_options_require or $pythonpath_injection or $ld_preload_injection)
}

rule MCP_Config_TemplateInjection {
    meta:
        description = "Detects server-side template injection in MCP configs"
        severity = "high"
        attack_family = "json_config_rce"
        cve = "CVE-2026-30630"
        mitre = "T1059.007"
    strings:
        $handlebars_constructor = /\{\{constructor\.constructor/ nocase
        $jinja_os_popen = /\{\{.*os\.popen\s*\(/ nocase
        $jinja_config_from_string = /config\.from_string\s*\(/ nocase
        $template_process_exec = /process\.mainModule\.require/ nocase
    condition:
        any of them
}

rule MCP_Config_ProtocolHandlerAbuse {
    meta:
        description = "Detects MCP server configuration abuse to spawn malicious processes"
        severity = "critical"
        attack_family = "json_config_rce"
        cve = "CVE-2026-30623"
        mitre = "T1059.006"
    strings:
        $mcp_servers_config = /"mcp_servers"\s*:\s*\{/ nocase
        $python_c_exec = /"python"\s*,\s*"-c"/ nocase
        $os_system_import = /import\s+os\s*;\s*os\.system/ nocase
        $backdoor_download = /curl\s+https?:\/\/[^\/]+\/backdoor/ nocase
    condition:
        $mcp_servers_config and ($python_c_exec or $os_system_import) and $backdoor_download
}

/* ========================================================================= */
/* COMMAND EXECUTION PATTERNS                                                */
/* ========================================================================= */

rule MCP_Cmd_ShellMetacharacterInjection {
    meta:
        description = "Detects shell metacharacter injection in MCP tool arguments"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.004"
    strings:
        $semicolon_injection = /;\s*curl\s+https?:\/\/[^\/]+\/.*\|\s*(bash|sh)/ nocase
        $pipe_injection = /\|\s*(bash|sh|zsh|dash)/ nocase
        $ampersand_injection = /&&\s*(wget|curl)\s+https?:\/\// nocase
        $download_execute = /(curl|wget)\s+[^|]+\|\s*(bash|sh)/ nocase
    condition:
        any of them
}

rule MCP_Cmd_CommandSubstitution {
    meta:
        description = "Detects command substitution patterns ($() and backticks)"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.004"
    strings:
        $dollar_paren = /\$\(\s*(curl|wget|bash|sh)\s+/ nocase
        $backtick_exec = /`[^`]*(curl|wget|bash|sh)[^`]*`/ nocase
        $curl_silent = /curl\s+-s\s+https?:\/\// nocase
        $wget_quiet = /wget\s+-q\s+https?:\/\// nocase
    condition:
        ($dollar_paren or $backtick_exec) and ($curl_silent or $wget_quiet)
}

rule MCP_Cmd_BashReverseShell {
    meta:
        description = "Detects Bash reverse shell patterns"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.004"
    strings:
        $bash_tcp = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+/ nocase
        $bash_udp = /bash\s+-i\s+>&\s+\/dev\/udp\/\d+\.\d+\.\d+\.\d+\/\d+/ nocase
        $bash_exec = /bash\s+-c\s+["']bash\s+-i/ nocase
    condition:
        any of them
}

rule MCP_Cmd_PythonReverseShell {
    meta:
        description = "Detects Python-based reverse shell implementations"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.006"
    strings:
        $python_socket_shell = /python[3]?\s+-c\s+['"]import\s+socket.*subprocess.*os/ nocase
        $python_dup2 = /os\.dup2\s*\(.*fileno/ nocase
        $python_subprocess_call = /subprocess\.call\s*\(\s*\[.*\/bin\/sh/ nocase
        $python_socket_connect = /socket\.socket.*\.connect\s*\(/ nocase
    condition:
        $python_socket_shell and ($python_dup2 or $python_subprocess_call or $python_socket_connect)
}

rule MCP_Cmd_NodeJSReverseShell {
    meta:
        description = "Detects Node.js-based reverse shell implementations"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.007"
    strings:
        $node_child_process = /node\s+-e\s+['"]require\(["']child_process['"]\)\.spawn/ nocase
        $node_net_socket = /net\.Socket\s*\(\).*\.connect\s*\(/ nocase
        $node_exec_bash = /exec\s*\(\s*["']\/bin\/bash/ nocase
    condition:
        any of them
}

rule MCP_Cmd_EncodedExecution {
    meta:
        description = "Detects base64-encoded command execution to evade detection"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1140"
    strings:
        $base64_decode_exec = /echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d\s*\|\s*(bash|sh)/ nocase
        $eval_base64 = /eval\s*\(\s*base64\s*\.decode\s*\(/ nocase
        $atob_exec = /atob\s*\(\s*["'][A-Za-z0-9+/=]+["']\s*\)/ nocase
    condition:
        any of them
}

rule MCP_Cmd_FileRedirection {
    meta:
        description = "Detects download-and-execute patterns via file redirection"
        severity = "critical"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.004"
    strings:
        $curl_to_hidden = /curl\s+.*>\s+\/tmp\/\.[^\/]+\s*&&\s*chmod\s+\+x/ nocase
        $wget_to_hidden = /wget\s+.*-O\s+\/tmp\/\.[^\/]+\s*&&\s*chmod\s+\+x/ nocase
        $execute_hidden = /\/tmp\/\.[a-z]+\s*$/ nocase
        $chmod_then_exec = /chmod\s+\+x\s+[^&]+\s*&&\s*[^&]+\.sh/ nocase
    condition:
        ($curl_to_hidden or $wget_to_hidden) and ($execute_hidden or $chmod_then_exec)
}

rule MCP_Cmd_DNSExfiltration {
    meta:
        description = "Detects DNS-based data exfiltration patterns"
        severity = "high"
        attack_family = "command_execution"
        cve = "CVE-2026-30631"
        mitre = "T1048.001"
    strings:
        $nslookup_loop = /for\s+.*in\s+\$\(ls\s+.*\);\s*do\s*nslookup/ nocase
        $dig_exfil = /dig\s+.*@.*\.[a-z]+\.[a-z]{2,}/ nocase
        $dns_encoded_data = /\.[a-zA-Z0-9]{20,}\.[a-z]+\.[a-z]{2,}/ nocase
    condition:
        any of them
}

/* ========================================================================= */
/* MCP-SPECIFIC INDICATORS                                                   */
/* ========================================================================= */

rule MCP_Protocol_JSONRPC_Adversarial {
    meta:
        description = "Detects adversarial JSON-RPC 2.0 patterns targeting MCP servers"
        severity = "high"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059"
    strings:
        $tools_call_injection = /"method"\s*:\s*"tools\/call".*"arguments"\s*:\s*\{[^}]*[;|&$`]/ nocase
        $malicious_tool_name = /"name"\s*:\s*"[^"]*(?:exec|eval|system|shell|run)[^"]*"/ nocase
        $jsonrpc_with_payload = /"jsonrpc"\s*:\s*"2\.0".*"payload"\s*:/ nocase
    condition:
        any of them
}

rule MCP_Transport_ScriptInjection {
    meta:
        description = "Detects injection in MCP transport layer scripts"
        severity = "high"
        attack_family = "command_execution"
        cve = "CVE-2026-30626"
        mitre = "T1059.004"
    strings:
        $transport_http_inject = /MCP_TRANSPORT=.*["'];.*\$/ nocase
        $port_injection = /MCP_SERVER_PORT=.*[;|&]/ nocase
        $command_inject = /strace.*-o.*&&\s*(curl|wget|bash)/ nocase
    condition:
        any of them
}

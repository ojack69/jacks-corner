/* Global variables */
var appId = null;
var appId_iOS = null;

var BURP_PROXY_IP = null;
var BURP_PROXY_PORT = null;

/*
 * Two lists control which connections are redirected to the proxy. Both use the
 * same entry format:
 *   "api.cliente.com"     -> exact hostname, any port
 *   "*.cliente.com"       -> any subdomain (and the apex cliente.com), any port
 *   "api.cliente.com:443" -> hostname on a specific port only
 *   "203.0.113.10"        -> literal IPv4 on any port (hosts reached without DNS)
 *   "203.0.113.10:443"    -> literal IPv4 on a specific port
 *
 * Decision order for every outbound connection:
 *   1. If it matches PROXY_DENYLIST         -> connect DIRECTLY (deny-list wins).
 *   2. Else if PROXY_ALLOWLIST is non-empty -> redirect only if it matches.
 *   3. Else (allow-list empty)              -> redirect everything.
 *
 * Typical setups:
 *   - Narrow scope: put the target host(s) in PROXY_ALLOWLIST, leave denylist empty.
 *   - Broad scope:  leave PROXY_ALLOWLIST empty and drop the noisy hosts
 *                   (connectivity checks, telemetry, CDNs) into PROXY_DENYLIST.
 * Hostname matching relies on the getaddrinfo hook to map IP -> hostname.
 */
var PROXY_ALLOWLIST = null;
var PROXY_DENYLIST = null;

// Master switch for the SSL/TLS pinning bypass.
//   true  -> disable Flutter's TLS certificate verification (needed to read HTTPS
//            in the proxy when the proxy CA is NOT trusted by the app/device).
//   false -> leave TLS verification intact (proxy-only mode; use this when the proxy
//            CA certificate is already installed and trusted on the device).
var BYPASS_SSL_PINNING = true;

// Set to true to log every redirect/direct decision and every DNS mapping (debug).
var ALLOWLIST_DEBUG = false;

// Shared guard: flips to true once the pinning bypass is in place, so the primary
// (string-scan) method and the pattern-based fallback never hook the same function twice.
var TLSValidationDisabled = false;

// Resolved IPv4 address -> hostname (lowercased), populated by the getaddrinfo hook.
var IP_TO_HOST = {};

var flutter_base = null;
var flutter_size = null;

var PT_LOAD_rodata_p_memsz = null;
var PT_LOAD_text_p_vaddr = null;
var PT_LOAD_text_p_memsz = null;
var PT_GNU_RELRO_p_vaddr = null;
var PT_GNU_RELRO_p_memsz = null;

var TEXT_segment_text_section_offset = null;
var TEXT_segment_text_section_size = null;
var TEXT_segment_cstring_section_offset = null;
var TEXT_segment_cstring_section_size = null;
var DATA_segment_const_section_offset = null;
var DATA_segment_const_section_size = null;

var ssl_client_string_pattern_found_addr = null;
var verify_cert_chain_func_addr = null;
var handshake_string_pattern_found_addr = null;
var verify_peer_cert_func_addr = null;

var Socket_CreateConnect_string_pattern_found_addr = null;
var Socket_CreateConnect_func_addr = null;

var GetSockAddr_func_addr = null;
var sockaddr = null;
/* Global variables */

/* Util functions */
// Find application package name
function findAppId() {
    if (Process.platform === "linux") {
        var pm = Java.use('android.app.ActivityThread').currentApplication();
        return pm.getApplicationContext().getPackageName();
    } else {
        return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
    }
}

// Convert hex to byte string
function convertHexToByteString(hexString) {
    // Remove the '0x' prefix
    let cleanHexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;

    // Pad with a leading zero if the length is odd
    if (cleanHexString.length % 2 !== 0) {
        cleanHexString = '0' + cleanHexString;
    }

    // Split the string into pairs of two characters
    let byteArray = cleanHexString.match(/.{1,2}/g);

    // Reverse the order of the byte pairs
    byteArray.reverse();

    // Join the byte pairs with spaces
    let byteString = byteArray.join(' ');

    return byteString;
}

// Convert ip string (e.g, "192.168.0.12") to byte array
function convertIpToByteArray(ipString) {
    // Split the IP address into its components
    let octets = ipString.split('.');

    // Convert each octet to a hexadecimal number and then to a byte
    let byteArray = octets.map(octet => parseInt(octet, 10));

    return byteArray;
}

// Read the original IPv4 address and port from a sockaddr_in structure.
// Layout is the same on Linux and Darwin for the fields we need:
//   +0x2 : sin_port  (network byte order, 16-bit)
//   +0x4 : sin_addr  (4 bytes, network byte order)
function readSockaddrInEndpoint(sa) {
    sa = ptr(sa);
    let ip = [0, 1, 2, 3].map(i => sa.add(0x4 + i).readU8()).join('.');
    let port = byteFlip(sa.add(0x2).readU16());
    return { ip: ip, port: port };
}

// Does a hostname match an allow-list pattern? Supports exact ("api.example.com")
// and wildcard ("*.example.com", which also matches the apex "example.com").
function hostMatchesPattern(host, pattern) {
    host = host.toLowerCase();
    pattern = pattern.toLowerCase();
    if (pattern.indexOf('*.') === 0) {
        let bare = pattern.slice(2);            // "example.com"
        return host === bare || host.endsWith('.' + bare);
    }
    return host === pattern;
}

function looksLikeIpv4(s) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

// Does a single allow/deny entry match this endpoint?
// `host` may be null when the destination IP could not be mapped back to a hostname.
function entryMatches(entry, ip, port, host) {
    let e = entry.trim();
    if (e === '') return false;

    // Optional ":port" suffix. Only split on it when the part after the last
    // colon is purely numeric, so hostnames without a port stay intact.
    let target = e;
    let entryPort = null;
    let sep = e.lastIndexOf(':');
    if (sep !== -1 && /^\d+$/.test(e.slice(sep + 1))) {
        target = e.slice(0, sep);
        entryPort = parseInt(e.slice(sep + 1), 10);
    }
    if (entryPort !== null && entryPort !== port) return false;

    if (looksLikeIpv4(target)) {
        return target === ip;                                   // IP / IP:port entry
    }
    return host != null && hostMatchesPattern(host, target);   // hostname / wildcard
}

// Does any entry in a list match this endpoint?
function listMatches(list, ip, port, host) {
    if (list == null) return false;
    for (const entry of list) {
        if (entryMatches(entry, ip, port, host)) return true;
    }
    return false;
}

// Decide whether an endpoint must be redirected to the proxy.
// Deny-list wins; then a non-empty allow-list restricts; empty allow-list = all.
function isProxyTarget(ip, port, host) {
    if (listMatches(PROXY_DENYLIST, ip, port, host)) return false;
    if (PROXY_ALLOWLIST == null || PROXY_ALLOWLIST.length === 0) return true;
    return listMatches(PROXY_ALLOWLIST, ip, port, host);
}

// Read the resolved IPv4 out of a struct addrinfo, coping with both the BSD/bionic/
// Darwin field order (ai_addr at 0x20) and the glibc order (ai_addr at 0x18).
function readAiAddrIp(ai) {
    for (const off of [0x20, 0x18]) {
        let ai_addr = ai.add(off).readPointer();
        if (ai_addr.isNull()) continue;
        // sockaddr_in family: Linux u16@0x0, Darwin u8@0x1. AF_INET == 2 on both.
        let famLinux = ai_addr.readU16();
        let famDarwin = ai_addr.add(0x1).readU8();
        if (famLinux === 2 || famDarwin === 2) {
            return [0, 1, 2, 3].map(i => ai_addr.add(0x4 + i).readU8()).join('.');
        }
    }
    return null;
}

// Hook the resolver so we can remember which hostname each IPv4 came from.
// dart:io / dio resolve names through getaddrinfo, so this captures dio traffic too.
function hookResolver() {
    var getaddrinfo = Module.getGlobalExportByName('getaddrinfo');
    if (getaddrinfo == null) {
        console.log('[!] getaddrinfo not found; hostname allow-list will not resolve names');
        return;
    }
    Interceptor.attach(getaddrinfo, {
        onEnter: function (args) {
            // int getaddrinfo(const char *node, const char *service,
            //                 const struct addrinfo *hints, struct addrinfo **res)
            this.node = args[0].isNull() ? null : args[0].readCString();
            this.res = args[3];
        },
        onLeave: function (retval) {
            try {
                if (retval.toInt32() !== 0 || this.node == null || this.res.isNull()) return;
                let host = this.node.toLowerCase();
                let ai = this.res.readPointer();
                let guard = 0;
                while (!ai.isNull() && guard++ < 64) {
                    let ip = readAiAddrIp(ai);
                    if (ip != null) {
                        IP_TO_HOST[ip] = host;
                        if (ALLOWLIST_DEBUG) console.log(`[dns] ${host} -> ${ip}`);
                    }
                    ai = ai.add(0x28).readPointer();  // ai_next
                }
            } catch (e) {
                if (ALLOWLIST_DEBUG) console.log('[!] getaddrinfo parse error: ' + e);
            }
        }
    });
    console.log('[*] Hook getaddrinfo (hostname allow-list enabled)');
}

// Convert ArrayBuffer to hex string
function convertArrayBufferToHex(buffer) {
    let hexArray = [];
    let uint8Array = new Uint8Array(buffer);
    for (let byte of uint8Array) {
        hexArray.push(byte.toString(16).padStart(2, '0'));
    }
    return hexArray.join(' ');
}

// Byte flip
function byteFlip(number) {
    // Extract the high and low bytes
    let highByte = (number >> 8) & 0xFF;
    let lowByte = number & 0xFF;

    // Swap the high and low bytes
    let flippedNumber = (lowByte << 8) | highByte;

    return flippedNumber;
}

// Memory scan
function scanMemory(scan_start_addr, scan_size, pattern, for_what) {
    Memory.scan(scan_start_addr, scan_size, pattern, {
        onMatch: function(address, size){
            if (for_what == "ssl_client") {
                ssl_client_string_pattern_found_addr = address;
                console.log(`[*] ssl_client string pattern found at: ${address}`);
            } 
            else if (for_what == "ssl_client_adrp_add") {
                var adrp, add;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "adrp") {
                    adrp = disasm.operands.find(op => op.type === 'imm')?.value;
                    
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic != "add") {
                        disasm = Instruction.parse(disasm.next);
                    }
                    add = disasm.operands.find(op => op.type === 'imm')?.value;

                    if (adrp != undefined && add != undefined && ptr(adrp).add(add).toString() == ssl_client_string_pattern_found_addr.toString()) {
                        console.log(`[*] Found adrp add address: ${address}`);
                        // As we trace back, disassemble to find the address of the verify_cert_chain function (https://blog.weghos.com/flutter/engine/third_party/boringssl/src/ssl/ssl_x509.cc.html#_ZN4bsslL41ssl_crypto_x509_session_verify_cert_chainEP14ssl_session_stPNS_13SSL_HANDSHAKEEPh)
                        for (let off = 0;; off += 4) {
                            disasm = Instruction.parse(address.sub(off));
                            if (disasm.mnemonic == "sub") {
                                disasm = Instruction.parse(disasm.next);
                                if (disasm.mnemonic == "stp" || disasm.mnemonic == "str") {
                                    verify_cert_chain_func_addr = address.sub(off);
                                    console.log(`[*] Found verify_cert_chain function address: ${verify_cert_chain_func_addr}`);
                                    break;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
            else if (for_what == "ssl_client_lea_rdi_rip") {
                /* opcode
                    lea rdi, [rip - 0xabcd]
                */
                var rdi, rip, disp;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "lea") {
                    rip = disasm.next;
                    disp = disasm.operands.find(op => op.type === 'mem')?.value.disp;
                    rdi = rip.add(disp);

                    if (rip != undefined && rdi != undefined && ptr(rdi).toString() == ssl_client_string_pattern_found_addr.toString()) {
                        console.log(`[*] Found lea rdi rip address: ${address}`);
                        // As we trace back, disassemble to find the address of the verify_cert_chain function (https://blog.weghos.com/flutter/engine/third_party/boringssl/src/ssl/ssl_x509.cc.html#_ZN4bsslL41ssl_crypto_x509_session_verify_cert_chainEP14ssl_session_stPNS_13SSL_HANDSHAKEEPh)
                        for (let off = 0;; off += 1) {
                            try {
                                disasm = Instruction.parse(address.sub(off));
                                if (disasm.mnemonic == "push" && disasm.opStr == "rbp") {
                                    if (Instruction.parse(disasm.next) != 'push r15') {
                                        continue;
                                    }
                                    verify_cert_chain_func_addr = address.sub(off);
                                    console.log(`[*] Found verify_cert_chain function address: ${verify_cert_chain_func_addr}`);
                                    break; 
                                } else {
                                    continue;
                                } 
                            } catch (error) {
                                continue;
                            }
                        }
                    }
                }
            }
            else if (for_what == "handshake") {
                for (let off = 0;; off += 1) {
                    var arrayBuff = new Uint8Array(ptr(address).sub(0x6).sub(off).readByteArray(6));
                    var hexarray = convertArrayBufferToHex(arrayBuff);
                    if (hexarray == "2e 2e 2f 2e 2e 2f") {  // "../../"
                        handshake_string_pattern_found_addr = ptr(address).sub(0x6).sub(off);
                        console.log(`[*] handshake string pattern found at: ${address}`);
                        break;
                    }
                    else {
                        continue;
                    }
                }
                // Get the iOS app id. if it's too early app crashes when spawning the iOS flutter app. this location is safe.
                appId_iOS = findAppId();
            }
            else if (for_what == "handshake_adrp_add") {
                var adrp, add;
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic == "adrp") {
                    adrp = disasm.operands.find(op => op.type === 'imm')?.value;
                    
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic != "add") {
                        disasm = Instruction.parse(disasm.next);
                    }
                    add = disasm.operands.find(op => op.type === 'imm')?.value;

                    if (adrp != undefined && add != undefined && ptr(adrp).add(add).toString() == handshake_string_pattern_found_addr.toString()) {
                        console.log(`[*] Found adrp add address: ${address}`);
                        // As we trace back, disassemble to find the address of the ssl_verify_peer_cert function (https://blog.weghos.com/flutter/engine/third_party/boringssl/src/ssl/handshake.cc.html#_ZN4bssl20ssl_verify_peer_certEPNS_13SSL_HANDSHAKEE)
                        for (let off = 0;; off += 4) {
                            disasm = Instruction.parse(address.sub(off));
                            if (disasm.mnemonic == "sub") {
                                disasm = Instruction.parse(disasm.next);
                                if (disasm.mnemonic == "stp" || disasm.mnemonic == "str") {
                                    verify_peer_cert_func_addr = address.sub(off);
                                    console.log(`[*] Found verify_peer_cert function address: ${verify_peer_cert_func_addr}`);
                                    break;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
            else if (for_what == "Socket_CreateConnect") {
                Socket_CreateConnect_string_pattern_found_addr = address;
                console.log(`[*] Socket_CreateConnect string pattern found at: ${address}`);
            }
            else if (for_what == "Socket_CreateConnect_func_addr") {
                Socket_CreateConnect_func_addr = address.sub(0x10).readPointer();
                console.log(`[*] Found Socket_CreateConnect function address: ${Socket_CreateConnect_func_addr}`);
                /* arm64
                    Socket_CreateConnect function looks like this.
                    SUB             SP, SP, #0xD0
                    STR             X30, [SP,#0xD0+var_30]
                    STP             X22, X21, [SP,#0xD0+var_20]
                    STP             X20, X19, [SP,#0xD0+var_10]
                    MOV             W1, #1
                    MOV             X19, X0
                    BL              sub_89E20C
                    ADD             X1, SP, #0xD0+var_B0
                    BL              loc_67C15C   <---------------- branch to GetSockAddr function
                    MOV             W1, #2
                    MOV             X0, X19
                    BL              sub_89E20C
                */

                /* x64
                    push            rbp
                    push            r15
                    push            r14
                    push            r13
                    push            r12
                    push            rbx
                    sub             rsp, 498h
                    mov             rbx, rdi
                    mov             esi, 1
                    call            sub_AB2790
                    lea             rsi, [rsp+4C8h+addr]
                    mov             rdi, rax
                    call            sub_8EEB50  <---------------- branch to GetSockAddr function
                    mov             rdi, rbx
                    mov             esi, 2
                    call            sub_AB2790
                */
               
                if (Process.arch == 'arm64') {
                    var bl_count = 0;
                    for (let off = 0;; off += 4) {
                        let disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
                        if (disasm.mnemonic == "bl") {
                            bl_count++;
                            if (bl_count == 2) {
                                GetSockAddr_func_addr = ptr(disasm.operands.find(op => op.type === 'imm')?.value);
                                console.log(`[*] Found GetSockAddr function address: ${GetSockAddr_func_addr}`);
                                break;
                            } else {
                                continue;
                            }
                        }
                    } 
                } else if (Process.arch == 'x64') {
                    var call_count = 0;
                    for (let off = 0;; off += 1) 
                    {
                        try {
                            let disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
                            if (disasm.mnemonic == "call") {
                                call_count++;
                                if (call_count == 2) {
                                    GetSockAddr_func_addr = ptr(disasm.operands.find(op => op.type === 'imm')?.value);
                                    console.log(`[*] Found GetSockAddr function address: ${GetSockAddr_func_addr}`);
                                    break;
                                } else {
                                    continue;
                                }
                            }
                        } catch (error) {
                            continue;
                        }
                    }
                }               
            }
        }, 
        onComplete: function(){
            // Scan adrp add opcode on the .text section to find the function which has "ssl_client" string
            if (for_what == "ssl_client" && ssl_client_string_pattern_found_addr != null) {
                if (Process.arch == 'arm64') {
                    var adrp_add_pattern = "?9 ?? ?? ?0 29 ?? ?? 91";
                    if (appId == "com.alibaba.intl.android.apps.poseidon") {
                        // alibaba.com (android) adrp add pattern is different
                        adrp_add_pattern = "?9 ?? ?? ?0 ?? ?? ?? ?? 29 ?? ?? 91";
                    }
                    scanMemory(flutter_base.add(PT_LOAD_text_p_vaddr), PT_LOAD_text_p_memsz, adrp_add_pattern, "ssl_client_adrp_add");
                } else if (Process.arch == 'x64') {
                    var lea_rdi_rip_pattern = "48 8d 3d ?? ?? ?? FF";
                    scanMemory(flutter_base.add(PT_LOAD_text_p_vaddr), PT_LOAD_text_p_memsz, lea_rdi_rip_pattern, "ssl_client_lea_rdi_rip");
                }
            }
            else if (for_what == "handshake" && handshake_string_pattern_found_addr != null) {
                var adrp_add_pattern = "?2 ?? 00 ?0 42 ?? ?? 91 00 02 80 52 21 22 80 52 c3 29 80 52";
                // In case we don't get the iOS app id yet, try to get it again after 0.1 second. This happens when spawning the iOS Flutter app
                if (appId_iOS == null) {
                    Thread.sleep(0.1);
                    appId_iOS = findAppId();
                }
                if (appId_iOS == "com.alibaba.sourcing") {
                    // alibaba.com (iOS) adrp add pattern is different
                    adrp_add_pattern = "?3 ?? 00 ?0 63 ?? ?? 91 00 02 80 52 01 00 80 52 22 22 80 52 84 25 80 52"
                }
                scanMemory(flutter_base.add(TEXT_segment_text_section_offset), TEXT_segment_text_section_size, adrp_add_pattern, "handshake_adrp_add");
            }
            // Scan "Socket_CreateConnect" string pattern found address on the .data.rel.ro section to find the address of "Socket_CreateConnect" function
            else if (for_what == "Socket_CreateConnect" && Socket_CreateConnect_string_pattern_found_addr != null) {
                var addr_to_find = convertHexToByteString(Socket_CreateConnect_string_pattern_found_addr.toString());
                if (Process.platform === 'linux') {
                    scanMemory(flutter_base.add(PT_GNU_RELRO_p_vaddr), PT_GNU_RELRO_p_memsz, addr_to_find, "Socket_CreateConnect_func_addr");
                }
                else if (Process.platform === 'darwin') {
                    scanMemory(flutter_base.add(DATA_segment_const_section_offset), DATA_segment_const_section_size, addr_to_find, "Socket_CreateConnect_func_addr");
                }
            }
            console.log("[*] scan memory done");
        }
    })
}
/* Util functions */

/* Some variables and functions for elf parsing */
var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_APPEND = 1024;
var O_LARGEFILE = 32768;
var O_CREAT = 64;
var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var p_types = {
    "PT_NULL":		0,		/* Program header table entry unused */
    "PT_LOAD":		1,		/* Loadable program segment */
    "PT_DYNAMIC":	2,		/* Dynamic linking information */
    "PT_INTERP":	3,		/* Program interpreter */
    "PT_NOTE":		4,		/* Auxiliary information */
    "PT_SHLIB":	    5,		/* Reserved */
    "PT_PHDR":		6,		/* Entry for header table itself */
    "PT_TLS":		7,		/* Thread-local storage segment */
    "PT_NUM":		8,		/* Number of defined types */
    "PT_LOOS":		0x60000000,	/* Start of OS-specific */
    "PT_GNU_EH_FRAME":	0x6474e550,	/* GCC .eh_frame_hdr segment */
    "PT_GNU_STACK":	0x6474e551,	/* Indicates stack executability */
    "PT_GNU_RELRO":	0x6474e552,	/* Read-only after relocation */
    "PT_GNU_PROPERTY":	0x6474e553,	/* GNU property */
    "PT_LOSUNW":	0x6ffffffa,
    "PT_SUNWBSS":	0x6ffffffa,	/* Sun Specific segment */
    "PT_SUNWSTACK":	0x6ffffffb,	/* Stack segment */
    "PT_HISUNW":	0x6fffffff,
    "PT_HIOS":		0x6fffffff,	/* End of OS-specific */
    "PT_LOPROC":	0x70000000,	/* Start of processor-specific */
    "PT_HIPROC":	0x7fffffff,	/* End of processor-specific */
}

function getExportFunction(name, ret, args) {
    var funcPtr;
    funcPtr = Module.getGlobalExportByName(name);
    if (funcPtr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        var func = new NativeFunction(funcPtr, ret, args);
        if (typeof func === "undefined") {
            console.log("parse error " + name);
            return null;
        }
        return func;
    }
}

var open = getExportFunction("open", "int", ["pointer", "int", "int"])
var close = getExportFunction("close", "int", ["int"]);
var lseek = getExportFunction("lseek", "int", ["int", "int", "int"]);
var read = getExportFunction("read", "int", ["int", "pointer", "int"]);
/* Some variables and functions for elf parsing */

/* Parsing elf function */
function parseElf(base) {
    base = ptr(base);
    var module = Process.findModuleByAddress(base);
    var fd = null;
    if (module !== null) {
        fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0);
    }
    
    // Read elf header
    var magic = "464c457f"
    var elf_magic = base.readU32()
    if (parseInt(elf_magic).toString(16) != magic) {
        console.log("[!] Wrong magic...ignore")
    }

    var arch = Process.arch
    var is32bit = arch == "arm" ? 1 : 0 // 1:32 0:64

    var size_of_Elf32_Ehdr = 0x34;
    var off_of_Elf32_Ehdr_shoff = 32;
    var off_of_Elf32_Ehdr_phentsize = 42;
    var off_of_Elf32_Ehdr_phnum = 44;
    var off_of_Elf32_Ehdr_shentsize = 46;
    var off_of_Elf32_Ehdr_shnum = 48;
    var off_of_Elf32_Ehdr_shstrndx = 50;

    var size_of_Elf64_Ehdr = 0x40;
    var off_of_Elf64_Ehdr_shoff = 40;
    var off_of_Elf64_Ehdr_phentsize = 54;
    var off_of_Elf64_Ehdr_phnum = 56;
    var off_of_Elf64_Ehdr_shentsize = 58;
    var off_of_Elf64_Ehdr_shnum = 60;
    var off_of_Elf64_Ehdr_shstrndx = 62;

    // Parse Ehdr(Elf header)
    var ehdrs_from_file = null;
    var phoff = is32bit ? size_of_Elf32_Ehdr : size_of_Elf64_Ehdr   // Program header table file offset
    var shoff = is32bit ? base.add(off_of_Elf32_Ehdr_shoff).readU32() : base.add(off_of_Elf64_Ehdr_shoff).readU64();   // Section header table file offset
    if (shoff == 0 && fd != null && fd !== -1) {
        console.log("[!] shoff is 0. Try to get it from the file")
        ehdrs_from_file = Memory.alloc(64);
        lseek(fd, 0, SEEK_SET);
        read(fd, ehdrs_from_file, 64);
        shoff = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shoff).readU32() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shoff).readU64();
        console.log(`[*] shoff from the file: ${shoff}`)
    }
    var phentsize = is32bit ? base.add(off_of_Elf32_Ehdr_phentsize).readU16() : base.add(off_of_Elf64_Ehdr_phentsize).readU16();    // Size of entries in the program header table
    if (is32bit && phentsize != 32) {  // 0x20
        console.log("[!] Wrong e_phentsize. Should be 32. Let's assume it's 32");
        phentsize = 32;
    } else if (!is32bit && phentsize != 56) {
        console.log("[!] Wrong e_phentsize. Should be 56. Let's assume it's 56");
        phentsize = 56;
    }
    var phnum = is32bit ? base.add(off_of_Elf32_Ehdr_phnum).readU16() : base.add(off_of_Elf64_Ehdr_phnum).readU16();    // Number of entries in program header table
    // If phnum is 0, try to get it from the file
    if (phnum == 0) {
        if (fd != null && fd !== -1){
            console.log("[!] phnum is 0. Try to get it from the file")
            ehdrs_from_file = Memory.alloc(64);
            lseek(fd, 0, SEEK_SET);
            read(fd, ehdrs_from_file, 64);
            phnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_phnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
            if (phnum == 0) {
                console.log("[!] phnum is still 0. Let's assume it's 10. because we just need to find .dynamic section");
                phnum = 10;
            } else {
                console.log(`[*] phnum from the file: ${phnum}`)
            }
        } else {
            console.log("[!] phnum is 0. Let's assume it's 10. because we just need to find .dynamic section")
            phnum = 10;
        }
    }

    var shentsize = is32bit ? base.add(off_of_Elf32_Ehdr_shentsize).readU16() : base.add(off_of_Elf64_Ehdr_shentsize).readU16();    // Size of the section header
    if (is32bit && shentsize != 40) {  // 0x28
        console.log("[!] Wrong e_shentsize. Let's assume it's 40");
        shentsize = 40;
    } else if (!is32bit && shentsize != 64) {
        console.log("[!] Wrong e_shentsize. Let's assume it's 64");
        shentsize = 64;
    }
    var shnum = is32bit ? base.add(off_of_Elf32_Ehdr_shnum).readU16() : base.add(off_of_Elf64_Ehdr_shnum).readU16();    // Number of entries in section header table
    var shstrndx = is32bit ? base.add(off_of_Elf32_Ehdr_shstrndx).readU16() : base.add(off_of_Elf64_Ehdr_shstrndx).readU16();  // Section header table index of the entry associated with the section name string table
    if (shnum == 0 && fd != null && fd !== -1) {
        console.log("[!] shnum is 0. Try to get it from the file");
        ehdrs_from_file = Memory.alloc(64);
        lseek(fd, 0, SEEK_SET);
        read(fd, ehdrs_from_file, 64);
        shnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shnum).readU16();
        shstrndx = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_shstrndx).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_shstrndx).readU16();
        console.log(`[*] shnum from the file: ${shnum}, shstrndx from the file: ${shstrndx}`)
    }
    // console.log(`phoff: ${phoff}, shoff: ${shoff}, phentsize: ${phentsize}, phnum: ${phnum}, shentsize: ${shentsize}, shnum: ${shnum}, shstrndx: ${shstrndx}`)

    // Parse Phdr(Program header)
    var phdrs = base.add(phoff)
    for (var i = 0; i < phnum; i++) {
        var phdr = phdrs.add(i * phentsize);
        var p_type = phdr.readU32();

        // if p_type is 0 check if it's really 0 from the file
        var phdrs_from_file = null;
        if (p_type === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            p_type = phdrs_from_file.add(i * phentsize).readU32();
        }
        var p_type_sym = null;

        // check if p_type matches the defined p_type
        var p_type_exists = false;
        for (let key in p_types) {
            if (p_types[key] === p_type) {
                p_type_exists = true;
                p_type_sym = key;
                break;
            }
        }
        if (!p_type_exists) break;

        var p_offset = is32bit ? phdr.add(0x4).readU32() : phdr.add(0x8).readU64();
        var p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
        var p_paddr = is32bit ? phdr.add(0xc).readU32() : phdr.add(0x18).readU64();
        var p_filesz = is32bit ? phdr.add(0x10).readU32() : phdr.add(0x20).readU64();
        var p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();
        var p_flags = is32bit ? phdr.add(0x18).readU32() : phdr.add(0x4).readU32();
        var p_align = is32bit ? phdr.add(0x1c).readU32() : phdr.add(0x30).readU64();
        // console.log(`p_type: ${p_type}, p_offset: ${p_offset}, p_vaddr: ${p_vaddr}, p_paddr: ${p_paddr}, p_filesz: ${p_filesz}, p_memsz: ${p_memsz}, p_flags: ${p_flags}, p_align: {p_align}`);

        // if p_flags is 0, check it from the file
        if (p_flags === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            var phdr_from_file = phdrs_from_file.add(i * phentsize);
            p_offset = is32bit ? phdr_from_file.add(0x4).readU32() : phdr_from_file.add(0x8).readU64();
            p_vaddr = is32bit ? phdr_from_file.add(0x8).readU32() : phdr_from_file.add(0x10).readU64();
            p_paddr = is32bit ? phdr_from_file.add(0xc).readU32() : phdr_from_file.add(0x18).readU64();
            p_filesz = is32bit ? phdr_from_file.add(0x10).readU32() : phdr_from_file.add(0x20).readU64();
            p_memsz = is32bit ? phdr_from_file.add(0x14).readU32() : phdr_from_file.add(0x28).readU64();
            p_flags = is32bit ? phdr_from_file.add(0x18).readU32() : phdr_from_file.add(0x4).readU32();
            p_align = is32bit ? phdr_from_file.add(0x1c).readU32() : phdr_from_file.add(0x30).readU64();
        }

        // .rodata section
        if (p_type_sym === 'PT_LOAD' && p_vaddr == 0) {
            PT_LOAD_rodata_p_memsz = p_memsz;
            continue;
        }

        // .text section
        if (p_type_sym === 'PT_LOAD' && p_vaddr != 0) {
            if (PT_LOAD_text_p_vaddr == null && PT_LOAD_text_p_memsz == null) {
                PT_LOAD_text_p_vaddr = p_vaddr;
                PT_LOAD_text_p_memsz = p_memsz;
            }
            continue;
        }

        if (p_type_sym === 'PT_GNU_RELRO') {
            PT_GNU_RELRO_p_vaddr = p_vaddr;
            PT_GNU_RELRO_p_memsz = p_memsz;
            break;
        }
    }
}
/* Parsing elf function */

/* Parsing MachO function */
function parseMachO(base) {
    base = ptr(base)
    var magic = base.readU32();
    var is64bit = false;
    if (magic == 0xfeedfacf) {
        is64bit = true;
        var number_of_commands_offset = 0x10
        var command_size_offset = 0x4
        var segment_name_offset = 0x8
        var vm_address_offset = 0x18
        var vm_size_offset = 0x20
        var file_offset = 0x28
        var number_of_sections_offset = 0x40
        var section64_header_base_offset = 0x48
        var section64_header_size = 0x50
    } else {
        console.log('Unknown magic:' + magic);
    }
    var cmdnum = base.add(number_of_commands_offset).readU32();
    // send({'parseMachO': {'cmdnum': cmdnum}})
    var cmdoff = is64bit ? 0x20 : 0x1C;
    for (var i = 0; i < cmdnum; i++) {
        var cmd = base.add(cmdoff).readU32();
        var cmdsize = base.add(cmdoff + command_size_offset).readU32();
        if (cmd === 0x19) { // SEGMENT_64
            var segname = base.add(cmdoff + segment_name_offset).readUtf8String();
            var vmaddr = base.add(cmdoff + vm_address_offset).readU32();
            var vmsize = base.add(cmdoff + vm_size_offset).readU32();
            var fileoffset = base.add(cmdoff + file_offset).readU32();
            var nsects = base.add(cmdoff + number_of_sections_offset).readU8();
            var secbase = base.add(cmdoff + section64_header_base_offset);

            if (base.add(cmdoff + command_size_offset).readU32() >= section64_header_base_offset + nsects * section64_header_size) {
                var TEXT_segment_text_section_index = 0;
                var TEXT_segment_cstring_section_index = 0;
                var DATA_segment_const_section_index = 0;
                for (var i = 0; i < nsects; i++) {
                    var secname = secbase.add(i * section64_header_size).readUtf8String()
                    var section_start_offset = secbase.add(i * section64_header_size + 0x30).readU32();                        

                    if (segname === '__TEXT' && secname === '__text') {
                        TEXT_segment_text_section_index = i;
                        TEXT_segment_text_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && i == (TEXT_segment_text_section_index + 1)) {
                        TEXT_segment_text_section_size = section_start_offset - TEXT_segment_text_section_offset;
                    } else if (segname === '__TEXT' && secname === '__cstring') {
                        TEXT_segment_cstring_section_index = i;
                        TEXT_segment_cstring_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && i == (TEXT_segment_cstring_section_index + 1)) {
                        TEXT_segment_cstring_section_size = section_start_offset - TEXT_segment_cstring_section_offset;
                    } else if (segname === '__DATA' && secname === '__const') {
                        DATA_segment_const_section_index = i;
                        DATA_segment_const_section_offset = section_start_offset;
                    } else if (segname === '__DATA' && i == (DATA_segment_const_section_index + 1)) {
                        DATA_segment_const_section_size = section_start_offset - DATA_segment_const_section_offset;
                    }
                }
            }
        }
        cmdoff += cmdsize;
    }
}
/* Parsing MachO function */

/* Hook flutter engine function to capture the network traffic */
function hook(target) {
    if (target == "GetSockAddr") {
        // Hook SocketAddress::GetSockAddr function so we can get the address of sockaddr structure
        Interceptor.attach(GetSockAddr_func_addr, {
            onEnter: function(args) { 
                // console.log(`[!] sockaddr: ${args[1]}`);
                sockaddr = args[1];
            },
            onLeave: function(retval) {}
        })
        // Hook the socket function and replace the IP and port with our burp ones.
        Interceptor.attach(Module.getGlobalExportByName("socket"), {
            onEnter: function(args) {
                // AF_INET(IPv4) == 2, AF_INET6(IPv6) == 10
                var overwrite = false;
                if (Process.platform === 'linux' && sockaddr != null && ptr(sockaddr).readU16() == 2) {
                    overwrite = true;
                }
                else if (Process.platform === 'darwin' && sockaddr != null && ptr(sockaddr).add(0x1).readU8() == 2) {
                    overwrite = true;
                }

                if (overwrite) {
                    // Read the real destination before clobbering it, then consult the allow list.
                    var dst = readSockaddrInEndpoint(sockaddr);
                    var dstHost = IP_TO_HOST[dst.ip] || null;
                    if (!isProxyTarget(dst.ip, dst.port, dstHost)) {
                        if (ALLOWLIST_DEBUG) {
                            var why = listMatches(PROXY_DENYLIST, dst.ip, dst.port, dstHost) ? 'deny-list' : 'not in allow-list';
                            console.log(`[ ] Direct   ${dstHost || dst.ip}:${dst.port} (${why})`);
                        }
                        return;
                    }
                    console.log(`[*] Redirect ${dstHost || dst.ip}:${dst.port} (${dst.ip}) --> ${BURP_PROXY_IP}:${BURP_PROXY_PORT}`);
                    ptr(sockaddr).add(0x2).writeU16(byteFlip(BURP_PROXY_PORT));
                    ptr(sockaddr).add(0x4).writeByteArray(convertIpToByteArray(BURP_PROXY_IP));
                }
            },
            onLeave: function(retval) {}
        })
    }
    else if (target == "verifyCertChain") {
        // Hook the verify_cert_chain function and replace the return value with true, so we can capture ssl traffic
        Interceptor.attach(verify_cert_chain_func_addr, {
            onEnter: function(args) {},
            onLeave: function(retval) {
                if (retval == "0x0") {
                    console.log(`[*] verify cert bypass`);
                    var newretval = ptr(0x1);
                    retval.replace(newretval);
                }
            }
        })
        // Mark pinning as handled so the pattern fallback stays a no-op.
        TLSValidationDisabled = true;
    }
    else if (target == "verifyPeerCert") {
        // Hook the verify_peer_cert function and replace it, so we can capture ssl traffic
        // https://github.com/NVISOsecurity/disable-flutter-tls-verification/blob/ecc6e9ed9e1182645b32da68d7be6aefb2b7e970/disable-flutter-tls.js#L151
        Interceptor.replace(verify_peer_cert_func_addr, new NativeCallback((pathPtr, flags) => {
            console.log(`[*] verify peer cert bypass`);
            return 0;
        }, 'int', ['pointer', 'int']));
        // Mark pinning as handled so the pattern fallback stays a no-op.
        TLSValidationDisabled = true;
    }
}
/* Hook flutter engine function to capture the network traffic */

/* main */
var target_flutter_library = ObjC.available ? "Flutter.framework/Flutter" : (Java.available ? "libflutter.so" : null);
if (target_flutter_library != null) { 
    var awaitForCondition = function(callback) {
        var module_loaded = 0;
        var base = null;
        var int = setInterval(function() {
            Process.enumerateModules()
            .filter(function(m){ return m['path'].indexOf(target_flutter_library) != -1; })
            .forEach(function(m) {
                if (ObjC.available) {
                    target_flutter_library = target_flutter_library.split('/').pop();
                }
                console.log(`[*] ${target_flutter_library} loaded!`);
                base = Process.getModuleByName(target_flutter_library).base;
                return module_loaded = 1;
            })
            if(module_loaded) {
                clearInterval(int);
                callback(+base);
                return;
            }
        }, 0);
    }
    
    function init(base) {
        flutter_base = ptr(base);
        console.log(`[*] ${target_flutter_library} base: ${flutter_base}`);
        if (Process.platform === 'linux') {
            appId = findAppId();
            console.log(`[*] package name: ${appId}`);    
        }

        var ssl_client_string = '73 73 6C 5F 63 6C 69 65 6E 74 00';
        var Socket_CreateConnect_string = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';
        // "third_party/boringssl/src/ssl/handshake.cc" string. First, Scan this string and then need to find the start address of "../../"
        var handshake_string = '74 68 69 72 64 5f 70 61 72 74 79 2f 62 6f 72 69 6e 67 73 73 6c 2f 73 72 63 2f 73 73 6c 2f 68 61 6e 64 73 68 61 6b 65 2e 63 63';
        if (Process.platform === 'linux') {
            parseElf(flutter_base);
            if (PT_LOAD_rodata_p_memsz != null) {
                // "ssl_client" string scan from the libflutter base address to the right before the .text section
                if (BYPASS_SSL_PINNING) {
                    scanMemory(flutter_base, PT_LOAD_rodata_p_memsz, ssl_client_string, "ssl_client");
                }
                // "Socket_CreateConnect" string scan
                scanMemory(flutter_base, PT_LOAD_rodata_p_memsz, Socket_CreateConnect_string, "Socket_CreateConnect");
            }
        } 
        else if (Process.platform === 'darwin') {
            parseMachO(flutter_base);
            // Find verify_peer_cert function address by scanning "third_party/boringssl/src/ssl/handshake.cc" string
            if (BYPASS_SSL_PINNING) {
                scanMemory(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, handshake_string, "handshake");
            }
            scanMemory(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, Socket_CreateConnect_string, "Socket_CreateConnect");
        }
    
        var int_getSockAddr = setInterval(() => {
            if (GetSockAddr_func_addr != null) {
                console.log("[*] Hook GetSockAddr function");
                hook("GetSockAddr");
                clearInterval(int_getSockAddr);
            }
        }, 0);
        
        if (BYPASS_SSL_PINNING) {
            if (Process.platform === 'linux') {
                var int_verifyCertBypass = setInterval(() => {
                    if (verify_cert_chain_func_addr != null) {
                        console.log("[*] Hook verify_cert_chain function");
                        hook("verifyCertChain");
                        clearInterval(int_verifyCertBypass);
                    }
                }, 0);
            }
            // On iOS, hooking verify_cert_chain doesn't work. Instead, hook verify_peer_cert
            else if (Process.platform === 'darwin') {
                var int_verifyPeerCertBypass = setInterval(() => {
                    if (verify_peer_cert_func_addr != null) {
                        console.log("[*] Hook verify_peer_cert function");
                        hook("verifyPeerCert");
                        clearInterval(int_verifyPeerCertBypass);
                    }
                }, 0);
            }

            // Fallback: if the string-scan method above cannot locate the verification
            // function (unusual Flutter build, or Windows targets), try the byte-pattern
            // engine from disable-flutter-tls.js. It self-guards on TLSValidationDisabled,
            // so it becomes a no-op once the primary method has already patched.
            setTimeout(disableTLSValidationByPattern, TLS_PATTERN_FALLBACK_DELAY);
        } else {
            console.log("[*] BYPASS_SSL_PINNING = false -> leaving TLS verification intact (proxy-only mode)");
        }
    }

    BURP_PROXY_IP = "192.168.1.31";
    BURP_PROXY_PORT = 8080;

    // See the decision order documented at the top of the file.

    // Narrow scope: only these are routed to the proxy (leave [] to proxy all).
    PROXY_ALLOWLIST = [
        // "*.cliente.com",
        // "api.cliente.com:443",
        // "203.0.113.10",
    ];

    // Never proxy these (always direct), even if the allow-list would match.
    // Broad scope: set PROXY_ALLOWLIST = [] above and list the noisy hosts here.
    PROXY_DENYLIST = [
        "*.apple.com",
        "*.google.com",
        "*.cloudflare.com",
    ];

    hookResolver();      // must be installed before the app resolves the target hosts
    awaitForCondition(init);
}
/* main */

/* =========================================================================
 * Pattern-based TLS bypass FALLBACK
 * Adapted from NVISO's disable-flutter-tls.js (pattern version: Jun 17 2026).
 *
 * This runs ONLY when BYPASS_SSL_PINNING === true AND the primary string-scan
 * bypass above has not managed to patch the verification function within
 * TLS_PATTERN_FALLBACK_DELAY ms. It is guarded by the shared TLSValidationDisabled
 * flag, so it becomes a no-op the moment the primary method succeeds, which
 * prevents double-hooking the same function. It also adds Windows coverage and
 * extra Android/iOS byte patterns that the string-scan method does not handle.
 * ======================================================================= */

// How long to give the primary (string-scan) bypass before trying byte patterns.
var TLS_PATTERN_FALLBACK_DELAY = 5000;

// Byte patterns that locate ssl_verify_peer_cert / verify_cert_chain per platform+arch.
var tlsPatternConfig = {
    "ios":{
        "modulename": "Flutter",
        "patterns":{
            "arm64": [
                // First pattern is actually for macos
                { pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F4 03 00 AA 68 31 00 F0 08 01 40 F9 08 01 40 F9 E8 07 00 F9", retval: 0 },
                { pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F? ?8 ?? 40 F9 ?? ?? 4? F9 ?? 00 00", retval: 0 },
                { pattern: "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9", retval: 0 },
            ],
        },
    },
    "android":{
        "modulename": "libflutter.so",
        "patterns":{
            "arm64": [
                { pattern: "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9", retval: 0 },
                { pattern: "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9", retval: 0 },
                { pattern: "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9", retval: 0 },
                // This one matches ssl_crypto_x509_session_verify_cert_chain (bool, 1 = verified) instead of
                // ssl_verify_peer_cert (ssl_verify_result_t, 0 = ok), so it needs retval: 1
                { pattern: "FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9", retval: 1 },
            ],
            "arm": [
                { pattern: "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8", retval: 0 },
            ],
            "x64": [
                { pattern: "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B", retval: 0 },
                { pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74", retval: 0 },
                { pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB", retval: 0 }
            ],
            "x86":[
                { pattern: "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01", retval: 0 }
            ]
        }
    },
    "windows": {
        "modulename": "flutter_windows.dll",
        "patterns":{
            "x64":[
                { pattern: "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 4? 89 CF 48 8B 05 ?? ?? ?? 00 48 31 E0 48 89 44 24 38 4? 8B 31 4? 8B", retval: 0 },
                { pattern: "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 48 89 CF 48 8B 05 20 45 C6 00 48 31 E0 48 89 44 24 30 48 8B 31 48", retval: 0 },
            ]
        }
    },
    "linux":{
        "modulename": "libflutter_linux_gtk.so",
        "patterns":{
            "x64":[
                // This one actually matches android x64 too
                { pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB", retval: 0 }
            ]
        }
    }
};

var tlsPatternFlutterFound = false;
var tlsTries = 0;
var tlsMaxTries = 5;
var tlsTimeout = 1000;
var tlsAndroidBypass = false;

// Main fallback routine: locate & patch ssl_verify_peer_cert by byte pattern.
function disableTLSValidationByPattern() {

    // Respect the master switch and the shared guard (primary method wins).
    if (!BYPASS_SSL_PINNING) return;
    if (TLSValidationDisabled) return;

    if (tlsTries === 0) {
        console.log("[*] Pattern-based TLS bypass fallback engaged (primary method has not patched yet)");
        console.log("[+] Pattern version: Jun 17 2026");
    }

    tlsTries ++;
    if(tlsTries > tlsMaxTries && !tlsAndroidBypass){
        console.warn(`\n`)
        console.warn('[!] Flutter library not found via patterns. Possible reasons:');
        console.warn('[!] - The application does not use Flutter');
        console.warn('[!] - The application has not loaded the Flutter library yet');
        console.warn('[!] - You are using an emulator + gadget (https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues/43)');
        console.warn('[!] The fallback will continue, but is likely to fail');
        console.warn(`\n`)
        tlsAndroidBypass = true;
    }else{
        // No module found yet
        if(m == null){
            if(tlsAndroidBypass){
                console.log(`[ ] Locating ssl_verify_peer_cert (${tlsTries}/${tlsMaxTries})`)
            }
            else{
                console.log(`[ ] Locating Flutter library ${tlsTries}/${tlsMaxTries}`);
            }
        }
        else
        {
            console.log(`[ ] Locating ssl_verify_peer_cert (${tlsTries}/${tlsMaxTries})`)
        }
    }

    // Figure out which patterns to use
    var platformConfig = {}
    if(Java.available){
        platformConfig = tlsPatternConfig["android"]
    }
    else if(Process.platform === 'darwin'){
        platformConfig = tlsPatternConfig["ios"]
    }
    else if(Process.platform in tlsPatternConfig){
        platformConfig = tlsPatternConfig[Process.platform]
    }
    else{
        console.log(`[!] Platform not supported: ${Process.platform}`)
    }

    var m = Process.findModuleByName(platformConfig["modulename"]);

    if (m === null && !tlsAndroidBypass) {
        setTimeout(disableTLSValidationByPattern, tlsTimeout);
        return;
    }
    else{
        if(!tlsAndroidBypass){
            console.log(`[+] Flutter library located`)
        }
        // reset counter so that searching for ssl_verify_peer_cert also gets x attempts
        if(tlsPatternFlutterFound == false){
            tlsPatternFlutterFound = true;
            tlsTries = 0;
        }
    }

    if (Process.arch in platformConfig["patterns"])
    {
        var ranges;
        if(Java.available){
            // On Android, getting ranges from the loaded module is buggy, so we revert to Process.enumerateRanges
            ranges = Process.enumerateRanges({protection: 'r-x'}).filter(isFlutterRangeByPattern)
        }else{
            // On iOS, there's no issue
            ranges = m.enumerateRanges('r-x')
        }

        findAndPatchByPattern(ranges, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0);
    }
    else
    {
        console.log('[!] Processor architecture not supported: ', Process.arch);
    }

    if (!TLSValidationDisabled)
    {
        if (tlsTries == tlsMaxTries)
        {
            if(tlsAndroidBypass){
                console.warn(`\n`)
                console.warn(`[!] No function matching ssl_verify_peer_cert could be found via patterns.`)
                console.warn(`[!] If you are sure that the application is using Flutter, please open an issue:`)
                console.warn(`[!] https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues`)
                console.warn(`\n`)
            }else{
                console.warn(`\n`)
                console.error(`[!] libFlutter was found, but ssl_verify_peer_cert could not be located via patterns`)
                console.error(`Please open an issue at https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues`);
                console.warn(`\n`)
            }
            // Not really, but we give up
            TLSValidationDisabled = true
        }
    }
}

// Find and patch the method in memory to disable TLS validation
function findAndPatchByPattern(ranges, patterns, thumb) {

    ranges.forEach(range => {
        patterns.forEach(({pattern, retval}) => {
            var matches = Memory.scanSync(range.base, range.size, pattern);
            matches.forEach(match => {
                var info = DebugSymbol.fromAddress(match.address)
                if(info.name){
                    console.log(`[+] ssl_verify_peer_cert found at offset: ${info.name || match.address}`);
                }else{

                    console.log(`[+] ssl_verify_peer_cert found at location: ${match.address}`);
                }
                TLSValidationDisabled = true;
                hook_ssl_verify_peer_cert_by_pattern(match.address.add(thumb), retval);
                console.log('[+] ssl_verify_peer_cert has been patched')

            });
            if(matches.length > 1){
                console.log('[!] Multiple matches detected. This can have a negative impact and may crash the app. Please open a ticket')
            }
        });

    });

    // Try again. disableTLSValidationByPattern will not do anything if TLSValidationDisabled = true
    setTimeout(disableTLSValidationByPattern, tlsTimeout);
}

function isFlutterRangeByPattern(range){
    if(tlsAndroidBypass) return true;

    var address = range.base
    var info = DebugSymbol.fromAddress(address)
    if(info.moduleName != null){
        if(info.moduleName.toLowerCase().includes("flutter")){
            return true;
        }
    }
    return false;
}

// Replace the target function's implementation to effectively disable the TLS check
function hook_ssl_verify_peer_cert_by_pattern(address, retval) {
    Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
        return retval;
    }, 'int', ['pointer', 'int']));
}
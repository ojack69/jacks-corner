/**
 * Merged Frida script for Flutter apps:
 *
 *  - SSL/TLS pinning bypass logic taken from:
 *    https://github.com/NVISOsecurity/disable-flutter-tls-verification
 *    (disable-flutter-tls.js) — pattern-matches ssl_verify_peer_cert in
 *    BoringSSL's handshake.cc and patches it to always return "verified".
 *
 *  - Proxy (Burp/mitmproxy) traffic redirection logic taken from:
 *    https://github.com/hackcatml/frida-flutterproxy (script.js) — locates
 *    the Socket::GetSockAddr function inside libflutter / Flutter.framework
 *    and hooks socket() to rewrite the destination sockaddr to point at
 *    your proxy, so all Flutter socket traffic gets redirected there.
 *
 * The two pieces are independent and run side by side:
 *   1) disableTLSValidation()  -> disables certificate verification
 *   2) awaitForCondition(init) -> finds & hooks GetSockAddr to redirect
 *      traffic to BURP_PROXY_IP:BURP_PROXY_PORT
 *
 * Set BURP_PROXY_IP / BURP_PROXY_PORT below before running.
 */

/* =========================================================================
 * SECTION 1: TLS / SSL pinning bypass
 * (verbatim logic from NVISOsecurity/disable-flutter-tls-verification)
 * ========================================================================= */

// Configuration object containing patterns to locate the ssl_verify_peer_cert function for different platforms and architectures.
var tlsBypassConfig = {
    "ios": {
        "modulename": "Flutter",
        "patterns": {
            "arm64": [
                // First pattern is actually for macos
                { pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F4 03 00 AA 68 31 00 F0 08 01 40 F9 08 01 40 F9 E8 07 00 F9", retval: 0 },
                { pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F? ?8 ?? 40 F9 ?? ?? 4? F9 ?? 00 00", retval: 0 },
                { pattern: "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9", retval: 0 },
            ],
        },
    },
    "android": {
        "modulename": "libflutter.so",
        "patterns": {
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
            "x86": [
                { pattern: "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01", retval: 0 }
            ]
        }
    },
    "windows": {
        "modulename": "flutter_windows.dll",
        "patterns": {
            "x64": [
                { pattern: "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 4? 89 CF 48 8B 05 ?? ?? ?? 00 48 31 E0 48 89 44 24 38 4? 8B 31 4? 8B", retval: 0 },
                { pattern: "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 48 89 CF 48 8B 05 20 45 C6 00 48 31 E0 48 89 44 24 30 48 8B 31 48", retval: 0 },
            ]
        }
    },
    "linux": {
        "modulename": "libflutter_linux_gtk.so",
        "patterns": {
            "x64": [
                // This one actually matches android x64 too
                { pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB", retval: 0 }
            ]
        }
    }
};

console.log("[+] TLS bypass pattern version: Jun 17 2026");
console.log("[+] Arch:", Process.arch);
console.log("[+] Platform: ", Process.platform);

// Flag to check if TLS validation has already been disabled
var TLSValidationDisabled = false;
var flutterLibraryFound = false;
var tlsTries = 0;
var tlsMaxTries = 5;
var tlsTimeout = 1000;
var androidBypass = false;

// Main function to disable TLS validation for Flutter
function disableTLSValidation() {

    // Stop if ready
    if (TLSValidationDisabled) return;

    tlsTries++;
    if (tlsTries > tlsMaxTries && !androidBypass) {
        console.warn(`\n`);
        console.warn('[!] Flutter library not found. Possible reasons:');
        console.warn('[!] - The application does not use Flutter');
        console.warn('[!] - The application has not loaded the Flutter library yet');
        console.warn('[!] - You are using an emulator + gadget (https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues/43)');
        console.warn('[!] The script will continue, but is likely to fail');
        console.warn(`\n`);
        androidBypass = true;
    } else {
        // No module found yet
        if (m == null) {
            if (androidBypass) {
                // But we are in bypass mode and are looking for the ssl_verify_peer_cert anyway
                console.log(`[ ] Locating ssl_verify_peer_cert (${tlsTries}/${tlsMaxTries})`);
            } else {
                // Still looking for flutter lib
                console.log(`[ ] Locating Flutter library ${tlsTries}/${tlsMaxTries}`);
            }
        } else {
            // Module has been located
            console.log(`[ ] Locating ssl_verify_peer_cert (${tlsTries}/${tlsMaxTries})`);
        }
    }

    // Figure out which patterns to use
    var platformConfig = {};
    if (Java.available) {
        platformConfig = tlsBypassConfig["android"];
    } else if (Process.platform === 'darwin') {
        platformConfig = tlsBypassConfig["ios"];
    } else if (Process.platform in tlsBypassConfig) {
        platformConfig = tlsBypassConfig[Process.platform];
    } else {
        console.log(`[!] Platform not supported: ${Process.platform}`);
    }

    var m = Process.findModuleByName(platformConfig["modulename"]);

    if (m === null && !androidBypass) {
        setTimeout(disableTLSValidation, tlsTimeout);
        return;
    } else {
        if (!androidBypass) {
            console.log(`[+] Flutter library located`);
        }
        // reset counter so that searching for ssl_verify_peer_cert also gets x attempts
        if (flutterLibraryFound == false) {
            flutterLibraryFound = true;
            tlsTries = 0;
        }
    }

    if (Process.arch in platformConfig["patterns"]) {
        var ranges;
        if (Java.available) {
            // On Android, getting ranges from the loaded module is buggy, so we revert to Process.enumerateRanges
            ranges = Process.enumerateRanges({ protection: 'r-x' }).filter(isFlutterRange);
        } else {
            // On iOS, there's no issue
            ranges = m.enumerateRanges('r-x');
        }

        findAndPatch(ranges, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0);
    } else {
        console.log('[!] Processor architecture not supported: ', Process.arch);
    }

    if (!TLSValidationDisabled) {
        if (tlsTries == tlsMaxTries) {
            if (androidBypass) {
                console.warn(`\n`);
                console.warn(`[!] No function matching ssl_verify_peer_cert could be found.`);
                console.warn(`[!] If you are sure that the application is using Flutter, please open an issue:`);
                console.warn(`[!] https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues`);
                console.warn(`\n`);
            } else {
                console.warn(`\n`);
                console.error(`[!] libFlutter was found, but ssl_verify_peer_cert could not be located`);
                console.error(`Please open an issue at https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues`);
                console.warn(`\n`);
            }
            // Not really, but we give up
            TLSValidationDisabled = true;
        }
    }
}

// Find and patch the method in memory to disable TLS validation
function findAndPatch(ranges, patterns, thumb) {

    ranges.forEach(range => {
        patterns.forEach(({ pattern, retval }) => {
            var matches = Memory.scanSync(range.base, range.size, pattern);
            matches.forEach(match => {
                var info = DebugSymbol.fromAddress(match.address);
                if (info.name) {
                    console.log(`[+] ssl_verify_peer_cert found at offset: ${info.name || match.address}`);
                } else {
                    console.log(`[+] ssl_verify_peer_cert found at location: ${match.address}`);
                }
                TLSValidationDisabled = true;
                hook_ssl_verify_peer_cert(match.address.add(thumb), retval);
                console.log('[+] ssl_verify_peer_cert has been patched');
            });
            if (matches.length > 1) {
                console.log('[!] Multiple matches detected. This can have a negative impact and may crash the app. Please open a ticket');
            }
        });
    });

    // Try again. disableTLSValidation will not do anything if TLSValidationDisabled = true
    setTimeout(disableTLSValidation, tlsTimeout);
}

function isFlutterRange(range) {
    if (androidBypass) return true;

    var address = range.base;
    var info = DebugSymbol.fromAddress(address);
    if (info.moduleName != null) {
        if (info.moduleName.toLowerCase().includes("flutter")) {
            return true;
        }
    }
    return false;
}

// Replace the target function's implementation to effectively disable the TLS check
function hook_ssl_verify_peer_cert(address, retval) {
    Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
        return retval;
    }, 'int', ['pointer', 'int']));
}

/* =========================================================================
 * SECTION 2: Proxy (Burp/mitmproxy) traffic redirection
 * (verbatim logic from hackcatml/frida-flutterproxy, minus its own
 * SSL-bypass hooks — TLS bypass is already handled by Section 1 above)
 * ========================================================================= */

/* Global variables */
var appId = null;
var appId_iOS = null;

// >>> SET YOUR PROXY HERE <<<
var BURP_PROXY_IP = "10.0.2.2";
var BURP_PROXY_PORT = 8080;

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
    let cleanHexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
    if (cleanHexString.length % 2 !== 0) {
        cleanHexString = '0' + cleanHexString;
    }
    let byteArray = cleanHexString.match(/.{1,2}/g);
    byteArray.reverse();
    let byteString = byteArray.join(' ');
    return byteString;
}

// Convert ip string (e.g, "192.168.0.12") to byte array
function convertIpToByteArray(ipString) {
    let octets = ipString.split('.');
    let byteArray = octets.map(octet => parseInt(octet, 10));
    return byteArray;
}

// Byte flip
function byteFlip(number) {
    let highByte = (number >> 8) & 0xFF;
    let lowByte = number & 0xFF;
    let flippedNumber = (lowByte << 8) | highByte;
    return flippedNumber;
}

// Memory scan (trimmed to only what's needed to locate GetSockAddr via
// the Socket_CreateConnect string reference — the ssl_client / handshake
// string scanning from the original script is no longer needed here since
// TLS bypass is handled independently in Section 1)
function scanMemory(scan_start_addr, scan_size, pattern, for_what) {
    Memory.scan(scan_start_addr, scan_size, pattern, {
        onMatch: function (address, size) {
            if (for_what == "Socket_CreateConnect") {
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
                    for (let off = 0; ; off += 4) {
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
                    for (let off = 0; ; off += 1) {
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
        onComplete: function () {
            // Scan "Socket_CreateConnect" string pattern found address on the .data.rel.ro
            // (linux/android) or __DATA __const (darwin) section to find the "Socket_CreateConnect" function
            if (for_what == "Socket_CreateConnect" && Socket_CreateConnect_string_pattern_found_addr != null) {
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
    });
}
/* Util functions */

/* Some variables and functions for elf parsing */
var O_RDONLY = 0;
var SEEK_SET = 0;

var p_types = {
    "PT_NULL": 0,
    "PT_LOAD": 1,
    "PT_DYNAMIC": 2,
    "PT_INTERP": 3,
    "PT_NOTE": 4,
    "PT_SHLIB": 5,
    "PT_PHDR": 6,
    "PT_TLS": 7,
    "PT_NUM": 8,
    "PT_LOOS": 0x60000000,
    "PT_GNU_EH_FRAME": 0x6474e550,
    "PT_GNU_STACK": 0x6474e551,
    "PT_GNU_RELRO": 0x6474e552,
    "PT_GNU_PROPERTY": 0x6474e553,
    "PT_LOSUNW": 0x6ffffffa,
    "PT_SUNWBSS": 0x6ffffffa,
    "PT_SUNWSTACK": 0x6ffffffb,
    "PT_HISUNW": 0x6fffffff,
    "PT_HIOS": 0x6fffffff,
    "PT_LOPROC": 0x70000000,
    "PT_HIPROC": 0x7fffffff,
};

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

var open = getExportFunction("open", "int", ["pointer", "int", "int"]);
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

    var magic = "464c457f";
    var elf_magic = base.readU32();
    if (parseInt(elf_magic).toString(16) != magic) {
        console.log("[!] Wrong magic...ignore");
    }

    var arch = Process.arch;
    var is32bit = arch == "arm" ? 1 : 0;

    var size_of_Elf32_Ehdr = 0x34;
    var off_of_Elf32_Ehdr_phentsize = 42;
    var off_of_Elf32_Ehdr_phnum = 44;

    var size_of_Elf64_Ehdr = 0x40;
    var off_of_Elf64_Ehdr_phentsize = 54;
    var off_of_Elf64_Ehdr_phnum = 56;

    var phoff = is32bit ? size_of_Elf32_Ehdr : size_of_Elf64_Ehdr;

    var phentsize = is32bit ? base.add(off_of_Elf32_Ehdr_phentsize).readU16() : base.add(off_of_Elf64_Ehdr_phentsize).readU16();
    if (is32bit && phentsize != 32) {
        console.log("[!] Wrong e_phentsize. Should be 32. Let's assume it's 32");
        phentsize = 32;
    } else if (!is32bit && phentsize != 56) {
        console.log("[!] Wrong e_phentsize. Should be 56. Let's assume it's 56");
        phentsize = 56;
    }
    var phnum = is32bit ? base.add(off_of_Elf32_Ehdr_phnum).readU16() : base.add(off_of_Elf64_Ehdr_phnum).readU16();
    if (phnum == 0) {
        if (fd != null && fd !== -1) {
            console.log("[!] phnum is 0. Try to get it from the file");
            var ehdrs_from_file = Memory.alloc(64);
            lseek(fd, 0, SEEK_SET);
            read(fd, ehdrs_from_file, 64);
            phnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_phnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
            if (phnum == 0) {
                console.log("[!] phnum is still 0. Let's assume it's 10. because we just need to find .dynamic section");
                phnum = 10;
            } else {
                console.log(`[*] phnum from the file: ${phnum}`);
            }
        } else {
            console.log("[!] phnum is 0. Let's assume it's 10. because we just need to find .dynamic section");
            phnum = 10;
        }
    }

    // Parse Phdr(Program header)
    var phdrs = base.add(phoff);
    for (var i = 0; i < phnum; i++) {
        var phdr = phdrs.add(i * phentsize);
        var p_type = phdr.readU32();

        var phdrs_from_file = null;
        if (p_type === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            p_type = phdrs_from_file.add(i * phentsize).readU32();
        }
        var p_type_sym = null;

        var p_type_exists = false;
        for (let key in p_types) {
            if (p_types[key] === p_type) {
                p_type_exists = true;
                p_type_sym = key;
                break;
            }
        }
        if (!p_type_exists) break;

        var p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
        var p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();
        var p_flags = is32bit ? phdr.add(0x18).readU32() : phdr.add(0x4).readU32();

        if (p_flags === 0 && fd != null && fd !== -1) {
            phdrs_from_file = Memory.alloc(phnum * phentsize);
            lseek(fd, phoff, SEEK_SET);
            read(fd, phdrs_from_file, phnum * phentsize);
            var phdr_from_file = phdrs_from_file.add(i * phentsize);
            p_vaddr = is32bit ? phdr_from_file.add(0x8).readU32() : phdr_from_file.add(0x10).readU64();
            p_memsz = is32bit ? phdr_from_file.add(0x14).readU32() : phdr_from_file.add(0x28).readU64();
            p_flags = is32bit ? phdr_from_file.add(0x18).readU32() : phdr_from_file.add(0x4).readU32();
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
    base = ptr(base);
    var magic = base.readU32();
    var is64bit = false;
    if (magic == 0xfeedfacf) {
        is64bit = true;
        var number_of_commands_offset = 0x10;
        var command_size_offset = 0x4;
        var segment_name_offset = 0x8;
        var vm_address_offset = 0x18;
        var vm_size_offset = 0x20;
        var file_offset = 0x28;
        var number_of_sections_offset = 0x40;
        var section64_header_base_offset = 0x48;
        var section64_header_size = 0x50;
    } else {
        console.log('Unknown magic:' + magic);
    }
    var cmdnum = base.add(number_of_commands_offset).readU32();
    var cmdoff = is64bit ? 0x20 : 0x1C;
    for (var i = 0; i < cmdnum; i++) {
        var cmd = base.add(cmdoff).readU32();
        var cmdsize = base.add(cmdoff + command_size_offset).readU32();
        if (cmd === 0x19) { // SEGMENT_64
            var segname = base.add(cmdoff + segment_name_offset).readUtf8String();
            var nsects = base.add(cmdoff + number_of_sections_offset).readU8();
            var secbase = base.add(cmdoff + section64_header_base_offset);

            if (base.add(cmdoff + command_size_offset).readU32() >= section64_header_base_offset + nsects * section64_header_size) {
                var TEXT_segment_text_section_index = 0;
                var TEXT_segment_cstring_section_index = 0;
                var DATA_segment_const_section_index = 0;
                for (var j = 0; j < nsects; j++) {
                    var secname = secbase.add(j * section64_header_size).readUtf8String();
                    var section_start_offset = secbase.add(j * section64_header_size + 0x30).readU32();

                    if (segname === '__TEXT' && secname === '__text') {
                        TEXT_segment_text_section_index = j;
                        TEXT_segment_text_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && j == (TEXT_segment_text_section_index + 1)) {
                        TEXT_segment_text_section_size = section_start_offset - TEXT_segment_text_section_offset;
                    } else if (segname === '__TEXT' && secname === '__cstring') {
                        TEXT_segment_cstring_section_index = j;
                        TEXT_segment_cstring_section_offset = section_start_offset;
                    } else if (segname === '__TEXT' && j == (TEXT_segment_cstring_section_index + 1)) {
                        TEXT_segment_cstring_section_size = section_start_offset - TEXT_segment_cstring_section_offset;
                    } else if (segname === '__DATA' && secname === '__const') {
                        DATA_segment_const_section_index = j;
                        DATA_segment_const_section_offset = section_start_offset;
                    } else if (segname === '__DATA' && j == (DATA_segment_const_section_index + 1)) {
                        DATA_segment_const_section_size = section_start_offset - DATA_segment_const_section_offset;
                    }
                }
            }
        }
        cmdoff += cmdsize;
    }
}
/* Parsing MachO function */

/* Hook flutter engine function to redirect socket traffic to the proxy */
function hookProxyRedirect() {
    // Hook SocketAddress::GetSockAddr function so we can get the address of the sockaddr structure
    Interceptor.attach(GetSockAddr_func_addr, {
        onEnter: function (args) {
            sockaddr = args[1];
        },
        onLeave: function (retval) { }
    });
    // Hook the socket function and replace the IP and port with our proxy's ones.
    Interceptor.attach(Module.getGlobalExportByName("socket"), {
        onEnter: function (args) {
            // AF_INET(IPv4) == 2, AF_INET6(IPv6) == 10
            var overwrite = false;
            if (Process.platform === 'linux' && sockaddr != null && ptr(sockaddr).readU16() == 2) {
                overwrite = true;
            }
            else if (Process.platform === 'darwin' && sockaddr != null && ptr(sockaddr).add(0x1).readU8() == 2) {
                overwrite = true;
            }

            if (overwrite) {
                console.log(`[*] Overwrite sockaddr as our proxy ip and port --> ${BURP_PROXY_IP}:${BURP_PROXY_PORT}`);
                ptr(sockaddr).add(0x2).writeU16(byteFlip(BURP_PROXY_PORT));
                ptr(sockaddr).add(0x4).writeByteArray(convertIpToByteArray(BURP_PROXY_IP));
            }
        },
        onLeave: function (retval) { }
    });
}
/* Hook flutter engine function to redirect socket traffic to the proxy */

/* main */
disableTLSValidation();

var target_flutter_library = ObjC.available ? "Flutter.framework/Flutter" : (Java.available ? "libflutter.so" : null);
if (target_flutter_library != null) {
    var awaitForCondition = function (callback) {
        var module_loaded = 0;
        var base = null;
        var int = setInterval(function () {
            Process.enumerateModules()
                .filter(function (m) { return m['path'].indexOf(target_flutter_library) != -1; })
                .forEach(function (m) {
                    if (ObjC.available) {
                        target_flutter_library = target_flutter_library.split('/').pop();
                    }
                    console.log(`[*] ${target_flutter_library} loaded!`);
                    base = Process.getModuleByName(target_flutter_library).base;
                    return module_loaded = 1;
                });
            if (module_loaded) {
                clearInterval(int);
                callback(+base);
                return;
            }
        }, 0);
    };

    function init(base) {
        flutter_base = ptr(base);
        console.log(`[*] ${target_flutter_library} base: ${flutter_base}`);
        if (Process.platform === 'linux') {
            appId = findAppId();
            console.log(`[*] package name: ${appId}`);
        }

        var Socket_CreateConnect_string = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';

        if (Process.platform === 'linux') {
            parseElf(flutter_base);
            if (PT_LOAD_rodata_p_memsz != null) {
                // "Socket_CreateConnect" string scan
                scanMemory(flutter_base, PT_LOAD_rodata_p_memsz, Socket_CreateConnect_string, "Socket_CreateConnect");
            }
        }
        else if (Process.platform === 'darwin') {
            parseMachO(flutter_base);
            scanMemory(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, Socket_CreateConnect_string, "Socket_CreateConnect");
        }

        var int_getSockAddr = setInterval(() => {
            if (GetSockAddr_func_addr != null) {
                console.log("[*] Hook GetSockAddr function");
                hookProxyRedirect();
                clearInterval(int_getSockAddr);
            }
        }, 0);
    }

    awaitForCondition(init);
}
/* main */

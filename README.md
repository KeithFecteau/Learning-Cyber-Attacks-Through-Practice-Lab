# Learning-Cyber-Attacks-Through-Practice-Lab

## Objective


The goal of this project was to gain hands-on experience with a range of ethical hacking tools in Kali Linux by simulating each stage of a cyber attack—from reconnaissance to post-exploitation. Using Metasploitable 2 as the vulnerable target system, I practiced identifying, exploiting, and reporting vulnerabilities to better understand how attackers operate and how defenders can counter them.

### Skills Learned


- Practical experience using Kali Linux tools to simulate real-world cyber attacks
- Strengthened ability to document vulnerabilities and recommend mitigation strategies
- Improved ability to identify and exploit common vulnerabilities in web applications and networks
- Proficiency in analyzing and interpreting network logs.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Practiced sniffing network traffic and identifying plaintext credentials
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Nmap – For network scanning and port enumeration
- Nikto – To identify web server misconfigurations and outdated software
- Cadaver – For interacting with vulnerable WebDAV services
- SQLmap – To automate SQL injection attacks and extract database contents
- John the Ripper – To crack password hashes and reveal weak credentials
- Ghidra – For reverse engineering and analyzing binary executables
- Social Engineering Toolkit (SET) – To simulate phishing attacks and clone login pages
- Wireshark – To sniff network traffic and capture credentials over HTTP
- Weevely – To gain remote shell access for post-exploitation tasks


## Steps
Learning Cyber Attacks Through Practice Lab 

Keith Fecteau 

Short description – This hands-on ethical hacking project focused on gaining practical 
experience with various Kali Linux tools by exploiting vulnerabilities in Metasploitable 2. I 
leveraged one tool from each of Kali Linux’s ten main categories to assess security weaknesses 
and create a structured vulnerability report. The project helped me refine my penetration testing 
skills and practice recommending mitigation strategies within a controlled virtual environment.


Here are the various categories of tools offered by Kali Linux  


![image](https://github.com/user-attachments/assets/3f9c2e28-bea3-4d5a-b662-83f4abb6348c)


      
<br><br>
<br><br>
<br><br>

**Information gathering tool- Nmap**

I initiated the reconnaissance phase by identifying the IP address of the Metasploitable 2 target machine. To achieve this, I used the ifconfig command within the Metasploitable 2 environment. This step was essential for mapping the network and determining the attack surface.

This indicated that the target IP for this was 192.168.9.238

![image](https://github.com/user-attachments/assets/c07a091a-2129-40ec-9a7d-06d52103c286)

<br><br>
**2. Information Gathering with Nmap**

 Next, I used Nmap to gather information about the target system on my Kali Linux machine. I started with a basic scan on the target machine's IP address (192.168.9.238) to identify open ports and running services. This step helped me understand the network exposure and potential attack vectors. I used the command nmap 192.168.9.238 

![image](https://github.com/user-attachments/assets/1b7cb0e3-511f-4344-b472-77378faa2d9f)

**3. Vulnerability Scanning with Nmap**

After performing a basic Nmap scan, I conducted a vulnerability assessment using Nmap’s built-in vulnerability detection script. I executed the following command to identify common vulnerabilities on the Metasploitable 2 machine. nmap --script vuln 192.168.9.238


![image](https://github.com/user-attachments/assets/84d6c7c7-a379-4064-8e24-ea6e6184a31f)


The scan highlights that the FTP service running on port 21 is vulnerable due to a vsFTPd version 2.3.4 backdoor (CVE-2011-2523). This vulnerability allows attackers to execute arbitrary commands and gain root access. Using the information provided by Nmap, you can exploit this vulnerability using tools like Metasploit with the prebuilt exploit module for vsFTPd backdoor 
<br><br>
Example Metasploit command:
<br><br>
use exploit/unix/ftp/vsftpd_234_backdoor
<br><br>
set RHOST 192.168.9.238
<br><br>

**Countermeasures/mitigations** 
    <br><br>
-Update vsFTPd: If the service is required, upgrade to the latest secure version of vsFTPd, as the 2.3.4 version contains a backdoor vulnerability.
-Disable or Remove FTP: If FTP is not necessary, disable or uninstall the service entirely to eliminate the attack vector.

<br><br>

 **Vulnerability Analysis tool-Nikto**

 The next tool I used in Kali Linux was Nikto, a web vulnerability scanner. I conducted a basic scan on the target machine to identify potential security issues, misconfigurations, and outdated software using the following command: nikto -h http://192.168.9.238
![image](https://github.com/user-attachments/assets/53326bc9-a6ef-49ba-871f-0a1d8b16413f)
![image](https://github.com/user-attachments/assets/5ee1b761-5f9f-4f52-845b-f8870446bec1)

<br><br>

**Nikto Scan Findings**

The Nikto scan revealed several security issues on the target machine:
**Outdated Apache Version (2.2.8) – End of Life (EOL)**
<br><br>
-Apache 2.2.8 is no longer supported, making it vulnerable to known exploits.
<br><br>
-Attackers can leverage unpatched vulnerabilities to gain unauthorized access or escalate privileges.
<br><br>

**Exposed phpMyAdmin ChangeLog File (/phpMyAdmin/ChangeLog)**
<br><br>
-The ChangeLog file is publicly accessible, exposing detailed version history and updates of phpMyAdmin.
<br><br>
-Attackers can analyze these logs to identify potential vulnerabilities or misconfigurations that could be exploited.
<br><br>

These findings highlight significant security risks that should be addressed to prevent unauthorized access and data exposure.
<br><br>
**Countermeasures/mitigations**
<br><br>
1.Secure phpMyAdmin:
-Restrict access to /phpMyAdmin/ to authorized users only using IP whitelisting or authentication.
<br><br>
-Remove or restrict access to sensitive files like /phpMyAdmin/ChangeLog and /phpMyAdmin/README to prevent exposure of version details and configurations.
<br><br>
**2.Enforce Regular Updates:**
-Update Apache, phpMyAdmin, and PHP to their latest secure versions to patch known vulnerabilities.
<br><br>
-Regularly monitor for security updates and apply patches to minimize the risk of exploitation.

<br><br>
Implementing these measures helps protect the web server from unauthorized access and reduces the risk of exploits targeting outdated software.




 












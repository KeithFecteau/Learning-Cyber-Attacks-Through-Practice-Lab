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

<br><br>

**Web Application Analysis tool-Cadaver**

1. Navigating to the Target Web Server<br><br> 
To begin web application analysis, I accessed the Metasploitable 2 web interface using a web browser in Kali Linux. I entered the following URL in the browser:  http://192.168.9.238
<br><br>    

Here is what the webpage provided me

![practicum7](https://github.com/user-attachments/assets/c65ceee9-311b-494f-85f9-65e05dc38952)

Then I clicked on the “WebDAV” link that brought me to this screen
![practicum8](https://github.com/user-attachments/assets/ca518232-163d-4a17-a3c4-2d59c6bd7468)

After identifying the WebDAV service, I copied the following directory URL for later use with Cadaver to test for vulnerabilities: http://192.168.9.238/dav/
<br><br>
2. Exploiting WebDAV with Cadaver<br><br> 
After launching Cadaver, I initiated a connection to the WebDAV directory using the following command: open  http://192.168.9.238/dav/

![practicum9](https://github.com/user-attachments/assets/aae7ec6c-8a74-4ccc-82f1-88632e169a41)

Through my research, I discovered that the put command in WebDAV allows file uploads to the server. This functionality can be exploited to inject files or arbitrary code, potentially leading to remote code execution if the server allows unauthorized file uploads.

<br><br>
I proceeded by creating a text file on my Kali Linux machine named “DefintelyNotAvirus” to inject into the web browser <br><br>

In a real-world attack scenario, an attacker could replace this file with a malicious payload (e.g., a web shell or exploit code) to achieve remote code execution or escalate privileges on the target system. However, for this project, I left the file with a simple, non-malicious message to test whether the WebDAV service accepted uploads.<br><br>

 3. Creating a Test File for WebDAV Injection <br><br>
To test the file upload functionality of the WebDAV server, I created a simple text file on my Kali Linux machine named "DefinitelyNotAVirus.txt"
![practicum11](https://github.com/user-attachments/assets/5470d643-7a99-4e31-9809-16515b3c9767)


4. Uploading the Test File Using Cadaver

  With the test file created, I returned to Cadaver and attempted to upload it to the WebDAV server using the PUT command. The command used was used:
put /home/user/Desktop/DefinitelyNotAVirus.txt

![practicum12](https://github.com/user-attachments/assets/ffa4224b-17f0-4cca-be99-a48d3c3fd9e2)


5. Verifying the File Upload on the WebDAV Server

After refreshing the WebDAV directory page in my web browser, I confirmed that the file now appeared on the server.

![practicum13](https://github.com/user-attachments/assets/d72e6512-d36b-42fc-97c0-d64d54103895)

In a real-world attack scenario, an attacker could upload and execute a malicious payload, such as a web shell, to gain remote access to the system.

**Countermeasures/Mitigations**

-If WebDAV functionality is not required, disable it entirely to eliminate the attack vector.<br><br>
-Configure the WebDAV server to allow write access only to authenticated and authorized users



**Database assessment tool- SQLmap**
<br><br>

SQLmap is an automated tool designed to detect and exploit SQL injection vulnerabilities in web applications. The goal of this assessment was to identify and exploit SQL injection weaknesses within DVWA (Damn Vulnerable Web Application), which is hosted on Metasploitable 2. This allowed me to test how attackers could extract sensitive database information from vulnerable applications.
<br><br>

1. Launching SQLmap and Navigating to DVWA

I began by opening SQLmap on my Kali Linux machine and navigating to the DVWA (Damn Vulnerable Web Application) hosted on the Metasploitable 2 server. I accessed the web application by clicking on the circled link.
![practicum14](https://github.com/user-attachments/assets/6cad4ca5-430e-440f-8d74-ed8fe4b9b391)

2. Targeting the SQL Injection Page in DVWA

    To utilize SQLmap, I navigated to the SQL Injection page within DVWA on the Metasploitable 2 server. This page is specifically designed to be vulnerable, making it an ideal target for testing SQL injection techniques.

   ![practicum15](https://github.com/user-attachments/assets/2b84c285-6df6-49ad-9718-e64017e8824e)

3. Executing a Basic SQL Injection Attack

   To manually test for SQL injection vulnerabilities, I entered the following basic SQL injection payload into the input field on the SQL Injection page in DVWA: 'or '1'='1

   ![practicum16](https://github.com/user-attachments/assets/886ccc66-4392-4b74-bbf7-e14678615593)

   Here are my results

   ![practicum18](https://github.com/user-attachments/assets/832c79c4-5723-4832-a620-025f04f6b538)


4. Extracting the Session Cookie for SQLmap

   Next, I left-clicked the page and inspected the element to grab the session cookie under the “network” tab for sqlmap to use for the next attack 

![practicum19](https://github.com/user-attachments/assets/30edb3d5-21ca-4546-80f8-2d1ddc62a116)

5. Running SQLmap to Scan for SQL Injection Vulnerabilities

   With the session cookie extracted, I executed SQLmap to scan the SQL Injection page for vulnerabilities. The command included both the target URL and the session cookie for authentication. The command I used was: <br><br>

   "http://192.168.9.238/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" -p id -H "Cookie: security=low; PHPSESSID=07ba58be37c341b647cda687f917280”


![practicum20](https://github.com/user-attachments/assets/10b7bb62-a5e3-470f-aed9-670788292baf)

**Explanation of the Command:**
"http://192.168.9.238/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"  Specifies the target URL where the SQL injection vulnerability is being tested.<br><br>
-p id Instructs SQLmap to focus on the "id" parameter, where the injection is attempted.<br><br>
-H "Cookie: security=low; PHPSESSID=07ba58be37c341b647cda687f917280" Uses the previously copied session cookie to authenticate SQLmap with DVWA.



6. SQLmap Scan Results – Confirmed Vulnerability

The SQLmap scan successfully identified an SQL injection vulnerability within the "id" parameter of the SQL Injection page in DVWA. This confirmed that the web application was improperly handling user input, making it susceptible to database exploitation.

![practicum21](https://github.com/user-attachments/assets/cb5a8436-1097-4bf1-b3ae-adad4879b5c4)

7. Enumerating Database Tables with SQLmap

   After confirming the SQL injection vulnerability, I proceeded to enumerate the tables within the DVWA database using the following SQLmap command below

    ![practicum22](https://github.com/user-attachments/assets/7d31d3d6-a3c4-47ed-9f50-163777b3cc8e)

**Explanation of the Command:**
-D dvwa → Specifies the target database (dvwa).<br><br>
--tables → Retrieves and lists all available tables within the database.


Here are the command results, two tables within the database were found
![practicum23](https://github.com/user-attachments/assets/8e9069a4-874b-4b10-a0ea-09b9b86fab0a)

8. Extracting User Credentials from the Database

Since user credentials are often stored in a users table, I attempted to retrieve the contents of this table, specifically targeting usernames and password hashes. Using the following command below

![practicum24](https://github.com/user-attachments/assets/cfd122bf-21f9-4438-87c4-c9a8594d3d22)

**Explanation of the Command:**
-D dvwa  Specifies the target database (dvwa).<br><br>
-T users  Targets the users table for extraction.<br><br>
--dump  Dumps all stored data from the users table, including usernames and password hashes.

9. Extracted and Cracked User Credentials

    After executing the SQLmap command, I successfully retrieved usernames and password hashes from the users table in the DVWA database. SQLmap also automatically cracked some hashes, revealing plaintext passwords. Below are my results <br><br> 

   ![practicum25](https://github.com/user-attachments/assets/830e862e-1220-495a-94b4-15fd321294c7)

   **Countermeasures/Mitigations**
 1. Input Validation & Sanitization<br><br>
-Reject inputs containing SQL-specific characters such as:
', --, ;, /*, */, and OR 1=1
<br><br>-Use input whitelisting to allow only expected characters (e.g., numbers for IDs).
2. Implement Strong Password Policies<br><br> 
-Require long, complex passwords (e.g., 12+ characters with uppercase, lowercase, numbers, and symbols).<br><br>
-Enforce multi-factor authentication (MFA) for accounts.



**Password attack tool- John the Ripper**

John the Ripper is a powerful password-cracking tool used to recover plaintext passwords from hashed credentials. It supports various hashing algorithms and uses techniques such as dictionary attacks, brute-force attacks, and rule-based attacks to crack passwords efficiently.

1.Creating a Test User and Hash File

To begin my password-cracking experiment with John the Ripper, I created a test user and a password hash file named "pass.txt". This file contained the hashed password for the test account, allowing me to gain practical experience cracking password hashes.


Here is the hash for the test user 
![practicum26](https://github.com/user-attachments/assets/dd0431e0-24e9-456c-a6ce-b462a974552e)


2. Cracking the Password Hash with John the Ripper

 Using John the Ripper, I successfully cracked the hashed password stored in pass.txt. I executed the following command: john -format=crypt pass.txt


 ![practicum27](https://github.com/user-attachments/assets/dcf7ae7c-8a45-43c2-adeb-7ba9d4227ff2)

 Within seconds it cracked the password of 1234. This can be done with many password hashes it just may take longer for passwords with increasing complexity, this is why simple passwords should never be used.


**Countermeasures/mitigations**

-Use Strong Password Policies<br><br>
-Implement MFA, multi-factor authentication


**Reverse engineering tool-Ghidra**

Ghidra is a powerful reverse engineering tool that provides detailed insights into binary executables. It can convert assembly instructions for easier analysis. It is beneficial for analyzing malicious binaries to understand their behavior and intent while in a controlled environment. Cybersecurity professionals should use this to reverse engineer malware to understand its functionality and detect indicators of compromise.


1: Setting Up a New Project in Ghidra

I began by launching Ghidra, then clicking file, new project, and nonshared project and named it test

![practicum28](https://github.com/user-attachments/assets/28c24be2-eee8-436f-a2ec-855f31ecea06)

2: Importing an Executable for Analysis

After setting up my Ghidra project, the next step was to import a binary executable for analysis. This file could potentially contain malicious code or vulnerabilities that I aimed to investigate.


First, while clicking on the test project I created I navigated to “file” then “import file”
![practicum29](https://github.com/user-attachments/assets/20554a40-5547-49e0-9734-bffb701ae25a)

3: Analyzing the Executable in Ghidra


For this reverse engineering lab, I chose to inspect the /bin/ls executable—a standard Linux binary responsible for listing directory contents. This analysis allowed me to examine its assembly code, functions, and potential vulnerabilities.


For the “Analysis Options” I went with the default configuration and then clicked “Analyze”
![practicum30](https://github.com/user-attachments/assets/9803a986-bc6c-4070-8749-9204e1f848e2)


4. Results

   These were my results, The left panel, “Symbol tree” is a hierarchical list of symbols present in the binary, including imports, exports, functions, and labels. This can be a good starting point for malware analysis.


   The center panel “Listing” Displays the raw assembly instructions of the selected function or section of the binary.

   The right panel, “Decompiler,” converts the selected function's assembly code into high-level pseudocode, making it easier to understand and analyze.

![practicum31](https://github.com/user-attachments/assets/ddb90868-9dcf-47ab-ad32-ca9ca542b699)

**Why This Matters in Cybersecurity:**<br><br> 
-The Symbol Tree helps locate key functions in malware analysis.<br><br>
-The Listing Panel reveals low-level execution behavior.<br><br>
-The Decompiler makes analyzing the binary faster and more accessible.



**Exploitation tool- Social Engineering Toolkit**

The social engineering toolkit is a widely used, open-source penetration testing tool in Kali Linux. It focuses on automating and controlling social engineering attacks to breach security systems. Some key features of this tool include cloning websites, creating spear-fishing emails, and wireless access point attacks. It is a valuable resource for pen testing and security training.


My goal for this part of the project was to clone a legitimate website and harvest user credentials to understand an attacker's process to gain access to a system.


1: Launching the Social Engineering Toolkit and Configuring the Attack 

I began by opening the social engineering toolkit on my Kali Linux machine and typing 1 to select “1 Social engineering attacks”
![practicum32](https://github.com/user-attachments/assets/3cdf2aaa-5a6a-44ac-9249-c09d0846471f)


After, I typed in 2 to select ‘ Website attack vectors”

![practicum33](https://github.com/user-attachments/assets/4bbf47db-1162-4665-8c94-c53a89efd9f6)

Then, 3 for “credential harvester attack method”

![practicum34](https://github.com/user-attachments/assets/5471405b-f5a2-46d8-b79d-eb87936e899b)

Finally, option 2 for “site cloner”

![practicum35](https://github.com/user-attachments/assets/605a344a-c26f-4a73-a576-bf527ca4411a)


2: Entering the Local Machine’s IP Address

Then the Social Engineering Toolkit prompted me to enter the IP address of the host (local machine). This is necessary because the tool needs to know where to redirect captured credentials when a victim interacts with the cloned website.

For the next step, the tool asks for the ip address of the host/local machine, so I entered that into the tool as indicated below
![practicum36](https://github.com/user-attachments/assets/5346b82e-6933-4f37-979e-e747b45383d1)


3.Cloning the Target Website

After entering my local machine's IP address, the Social Engineering Toolkit prompted me to specify the website URL to clone. Since my goal was to simulate a phishing attack, I selected the DVWA (Damn Vulnerable Web Application) login page as my target.

![practicum37](https://github.com/user-attachments/assets/c495d36f-be6d-4ed1-a581-479e2f90a219)


Code input for the toolkit

![practicum38](https://github.com/user-attachments/assets/dd5086d5-0fd1-4aa7-9e9f-dcdfcf8e7d2b)


4: Capturing Keystrokes and Harvesting Credentials

With the DVWA login page successfully cloned, the tool was now actively listening for user input. Any credentials entered into the fake login form would be sent to my terminal in real-time.In a real scenario, attackers could send the cloned websites to clients to steal their personal information.

I entered fake credentials to see if the tool would grab them.
![practicum39](https://github.com/user-attachments/assets/06a8c5ab-a574-4111-b0c2-f1b09d773eeb)


Here is what the tool displayed
![practicum40](https://github.com/user-attachments/assets/694529fc-369f-40dc-b862-64b6ab2b73ff)


**Countermeasures/mitigations**

1. User Awareness & Training<br><br>
-Educate users on phishing tactics, such as fake login pages, urgent messages, and suspicious email requests.<br><br>
-Encourage skepticism—users should be cautious of unexpected login prompts, especially those asking for credentials.<br><br>

2. URL Verification & Link Awareness<br><br>
-Teach users to verify URLs before entering credentials:<br><br>
-Check for misspellings or slight variations,<br><br>
-Hover over links before clicking to see the actual destination.



**Sniffing and spoofing tool-Wireshark**

Wireshark is a powerful tool for capturing and analyzing network traffic It provides a detailed view of all packets traveling through a network interface, including source and destination IP addresses and the protocols they use. Cyber professionals have many use cases for this tool, such as analyzing network activity for suspicious traffic or anomalies and monitoring the communication of a target system during penetration tests.


1: Launching Wireshark and Starting a Capture

To begin analyzing network traffic, I launched Wireshark on my Kali Linux machine and I began by selecting the interface “eth0’ and the blue shark fin in the top left corner to begin capturing network traffic
![practicum41](https://github.com/user-attachments/assets/1457e337-aff0-4121-9b9b-cb0910bb91df)


2: Generating Network Traffic by Logging into DVWA

While Wireshark was actively capturing traffic, I navigated to the DVWA (Damn Vulnerable Web Application) hosted on the Metasploitable 2 machine and attempted to log in using test credentials.
![practicum42](https://github.com/user-attachments/assets/fb0746ae-6c20-4ed8-9d6d-821271bc296f)


 3: Filtering and Identifying the POST Request in Wireshark

 To analyze the login traffic and look for exposed credentials, I used Wireshark’s filtering capabilities to isolate relevant packets. I first used the HTTP filter to clear up the packets and found the POST packet, When a user submits a login form, the browser sends the entered credentials (username and password) to the server in an HTTP POST request. If the connection is not encrypted for example, HTTP instead of HTTPS this data is sent as plaintext and can be intercepted by tools like Wireshark


 ![practicum43](https://github.com/user-attachments/assets/207188dd-2d16-434d-bf39-f48eb15e16f8)


 **Countermeasures/mitigations**<br><br>
-Use HTTPS instead of HTTP on all pages that transmit or receive user data.<br><br>
-Warn users to avoid entering credentials on insecure sites




**Post exploitation tool- Weavly** 

   Weevely is a stealthy PHP web shell used in post-exploitation to maintain access to a compromised web server. Once deployed, it enables an attacker (or ethical hacker) to execute system commands, browse the file system, upload/download files, and escalate privileges—all from a remote terminal. 


 My objective in this section was to exploit a vulnerable file upload function on the DVWA web server, upload a Weevely payload, and establish remote control over the server for post-exploitation tasks.



 1: Generating a PHP Web Shell with Weevely

To begin the post-exploitation phase, I launched Weevely on my Kali Linux machine and generated a malicious PHP payload using the following commands below:
![practicum44](https://github.com/user-attachments/assets/ee266f90-1e86-49e9-aa87-4163d607d864)

2: Uploading the PHP Shell to DVWA

With the Weevely payload (shell.php) generated, I navigated to the file upload section of the DVWA (Damn Vulnerable Web Application) to exploit its insecure file-handling feature
![practicum45](https://github.com/user-attachments/assets/88a3b18b-3328-4feb-a62a-0a5b788ce483)


3: Connecting to the Uploaded Shell with Weevely

After successfully uploading the shell.php file to DVWA, I noted the directory path where the file was stored—displayed in red text on the upload confirmation screen, this will be entered into Weevely to establish the connection

![practicum46](https://github.com/user-attachments/assets/aca17d5f-a60e-4784-a653-9952c300ea42)


Once connected to the uploaded Weevely shell, I established a persistent remote session with the compromised DVWA web server.

![practicum47](https://github.com/user-attachments/assets/b1715cd6-9f6a-418f-8773-58f8cde2edf4)

This tool enables an attacker to access sensitive server data, such as the directory structure and configuration files. It also provides detailed information about the operating system and installed software, which can be used to target outdated software or misconfigurations for further exploitation.


**Countermeasures/mitigations**<br><br>

1. Secure File Upload Functionality<br><br>
-Restrict accepted file types to safe formats like .jpg, .png, or .pdf.<br><br>
-Rename uploaded files and store them outside of the web root to prevent direct execution.<br><br>


2. Deploy a Web Application Firewall (WAF)<br><br>
-Use a WAF (e.g., AWS WAF, Cloudflare) to monitor and block malicious file uploads, command injection attempts, and known web shell signatures.<br><br>
-Configure the WAF to detect unusual traffic behavior and alert security teams in real time.<br><br>


3. Disable Execution in Upload Directories<br><br>
-Configure the web server to prevent execution of scripts (e.g., .php, .exe, .jsp) in upload directories.





















































 












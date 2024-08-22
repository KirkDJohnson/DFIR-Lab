<h1>Digital Forensics, Incident Response Lab</h1>


<h2>Description</h2>
In this lab, I was givwn a Windows Sysmon Event logs and a packet capture and was tasked with investigating a suspected intrusion, with the only information being the file had a .doc extension. I first focused on the sysmon logs, and using Eric Zimmerman's tools, coverted the logs into .csv and used Timeline Explorer to view the logs. I quickly discovered the suspected malicious file and begun my investigation by idenifying the user that was affected and the PID of the file. Examining the .doc file as the parent process, i discovered a 
<br />


<h2>Utilities Used</h2>

- <b>Brim</b> 
- <b>Sysmon</b>
- <b>Timeline Explorer</b>
- <b>EvtxEcmd</b>
- <b>VirusTotal</b>
- <b>CyberChef</b>


<h2>Environments Used </h2>

- <b>Windows 10 VM </b> 

<h2>Lab Overview:</h2>

<p align="center">
Scenario for the lab.<br/>
<img src="https://github.com/user-attachments/assets/b60ba3ca-702d-4a11-84c7-4e69540b0c3e"  alt="DFIR Lab"/>
<br />
<br />
In the lab, I was provided a packet capture and Windows Event Viewer Sysmon logs. I decided to start the investigation examining the Sysmon logs. Useing EZ Tools (Eric Zimmerman tools) I used EvtxEcmd to convert the event logs into a .csv file for processing in Timeline explorer. This was done through Powershell.  <br/>
<img src="https://github.com/user-attachments/assets/8a171437-d205-4f24-a527-4e1215f0a41f"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/15bfd80c-2612-4b73-9b69-6e2e7087533d"  alt="DFIR Lab"/>
<br />
<br />
The scenario for the lab, gave us a hint or a place to start the investigation in which it mentioned that the malicious document has a .doc extension, so within Timeline Explorer in the executable info I searched for an file that has a .doc extension and found one file which I wanted to investigate further.<br/>
<img src="https://github.com/user-attachments/assets/e358c6a9-9b24-4879-be54-531081660038"  alt="DFIR Lab"/>
<br />
<br />
With examing the log of that contained the .doc file, I discovered the user logged in as benimaru and the PID of the file as 496. I then changed the filter to include the username, the PID and Event Code 22, to determine if the file made any DNS requests outside the network found that it did contact an IP address of 167[.]71[.]199[.]191.<br/>
<img src="https://github.com/user-attachments/assets/71c4df43-79fc-4d04-be83-89c096b8f284"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/1457c147-338b-4f05-9c61-160ee7830714"  alt="DFIR Lab"/>
<br />
<br />
 That alone is cause for concern as outbound connections can allow for further malware to be downloaded. I continued investigating events by changing the filter to include 496 being the Parent PID and Event Code 1 to see if the document spawned any new processes and found that it started the process C:\Windows\SysWOW64\msdt.exe followed by script with base64 encoded text and what appears to be directory traversal. I used cyberchef to decode the the base64 string and found it to be a command that is launched from ...\Start Menu\Programs\Startup which contacts the domain phishteam[.]xyz/02dcf07, downloaded a file named update.zip, unzips it, runs, it and removes it. <br/>
<img src="https://github.com/user-attachments/assets/87dc0424-7c2b-43a1-87ba-bbf919387513"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/05be0917-8815-4f88-833f-0a31e04d8bc5"  alt="DFIR Lab"/>
<br />
<br />
After conducting some OSINT on this attack vector I discovered a post explaining that it was a discovered vulnerbility that is exploited using the start menu. This was seen in the decoded command, and likely the purpose of the .doc file as a dropper for further malware.<br/>
<img src="https://github.com/user-attachments/assets/273aeded-cfc0-454a-9bd5-0879a4012570"  alt="DFIR Lab"/>
<br />
<br />
Now that part of the intital access has been discovered I moved on to part two of the lab where another hint was given that said, "The Autostart execution reflects explorer.exe as its parent process ID. Child processes of explorer.exe within the event timeframe could be significant. Process Creation (Event ID 1) and File Creation (Event ID 11) succeeding the document execution are worth checking". With this, I changed the Event Code to 11 and Payload 4 to include "startup" from what we know about the vulnerability. This revealed the update.zip that we saw in the decoded base-64 string.<br/>
<img src="https://github.com/user-attachments/assets/883bffde-bae2-4a1c-b6d9-be513b15cf56"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/fa639fae-0175-40ef-b2b9-3872c782512a"  alt="DFIR Lab"/>
<br />
<br />
Also, knowing that "The Autostart execution reflects explorer.exe as its parent process ID.", I changed Payload 4 to contain "explorer" and Event Code to 1 to discover any processes created by explorer and came accross Poweshell being executed as "-w hidden -noni certutil..." a common attack method for Powershell to be ran without user being aware. The Powershell command contacted the malicious domain earlier phishtem[.]xyz and downloaded first.exe. Uptaining the hash of first.exe, I did not find any OSINT data signifying that is a known malicious file or executable, however, due to the circumstances under which it is downloaded, I will treat it as malicious.<br/>
<img src="https://github.com/user-attachments/assets/2b3fcc6a-9b4a-475f-a545-c28e9388ff2a"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/5af4f1a2-7678-4028-9565-cf1c1c0c7403"  alt="DFIR Lab"/>
<br />
<br />
Continuing down the attack, I changed first.exe to the parent process and Event Code back to 1 to see if it created any processes and I discovered further malicious actions. Particularly, that first.exe contacted a new domain resolvecyber[.]xyz and downloaded and ran ch.exe which ran and connected to the IP address 167.71.199.191 over port 8080 which is used for HTTP traffic in most cases. I obtained the hash of ch.exe and upon researching it, I can confirm that is malicious and particularly the malware chisel, used for tunneling C2 traffic through encypted tunnels such as HTTPS.<br/>
<img src="https://github.com/user-attachments/assets/d35435ed-1422-4359-ae51-9176914a3c0e"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/13614ba5-2c47-4d6b-a2df-df62048dffc4"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/b7f71cbe-c236-4057-8b87-b632348d89d0"  alt="DFIR Lab"/>
<br />
<br />
With what appears to be a potential Command and Control (c2) server being created by first.exe, I switched my focus to the packet capture to see what kind of traffic was made to the malicious domains and IP addresses. I used Brim/Zui for this task. Within Brim, I filtered for HTTP GET requests to the second malicious donmain/potential C2 server, resolvesyber[.]xyz and discovered numerous GET requests encoded over the port 8080 which we saw connection to.<br/>
<img src="https://github.com/user-attachments/assets/46903726-f565-4dec-bd67-94ff81d61b6c"  alt="DFIR Lab"/>
<br />
<br />
I noticed that the GET requests to have the same struture in which they start with /9ab62b5?q= and then the string is vastly different which I found to be base64 encoded text. With this knowledge, I went through the the GET requests, decoded them in cyberchef and realized that the attacker is executing commands on the host, confirming that this is a C2 server. Some of the most intresting and troubling commands/actions the attacker did include: discovering the users on the machine, focusing on the user benimaru and discovering a powershell script, automation.ps1 which included a password, and a port scan which showed many HTTP and HTTPS connections.  <br/>
<img src="https://github.com/user-attachments/assets/e18e529b-bf45-4ed9-8710-1581f68ec9e9"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/983ec824-f9dd-46c3-aff2-083c57908fca"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/543b8ad0-7dca-4bae-b095-ded3e511234e"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/3445ded7-a00f-4664-9f39-fa373b84870b"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/34002265-d5dc-412e-bd68-2c04084b47fe"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/cbd7f2e3-7e77-4b5e-bcc2-576853e52a57"  alt="DFIR Lab"/>
<br />
<br />
 At this point I knew there was more to uncover but I was stuck so I went back to Timeline Explorer, filterd for Event Code 1 and User benimaru to see what processes were created after the establishment of the C2 server. I found that the service C:\Windows\system32\wsmprovhost.exe was run with -Embedding, followed with what appeared to be discovery commands, so I conducted research on wsmprovhost and found it to be used as part of LOBINS (living off the land binaries), specfically with Winrm which was used to authenticate and connect to the endpoint.<br/>
<img src="https://github.com/user-attachments/assets/e69263e3-5571-4196-8d97-7da2e82ffa28"  alt="DFIR Lab"/>
<br />
<br />
Once again, I moved wsmprovhost.exe to the parent process to see if spawned any other process and found that it was used to downloaded two addtional binaries through powershell, from the inital malicious domain phishteam[.]xyz, spf.exe and final.exe. Obtaining the hashes of these binaries, I found clear evidence that the binary was malicious and specifically "printspoofer". I conducted further OSINT this and came across a GitHub repo which explained it allows: "From LOCAL/NETWORK SERVICE to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 and Server 2016/2019."  (https://github.com/itm4n/PrintSpoofer). <br/>
<img src="https://github.com/user-attachments/assets/108433f4-0cb2-4c44-b744-28f5f4c9d099"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/d7df92be-12dc-49e9-a145-4242e1e8494f"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/90ba68f7-98e2-4e4f-9501-ed7b4228cf54"  alt="DFIR Lab"/>
<br />
<br />
Intrestingly, when inputting final.exe into payload 3, it was making queries to the same C2 we saw earlier, resolvecyber[.]xyz. Going back to Brim, I had overlooked that the commands were coming from two different ports, 80 and 8080, which indicates that there is a second C2 sever that was established by final.exe. <br/>
<img src="https://github.com/user-attachments/assets/1f785942-da9e-4267-a1b8-8aac79731ba2"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/12d5b094-ce21-4ec5-bf83-abf7ead9d20a"  alt="DFIR Lab"/>
<br />
<br />
I again moved final.exe into the parent process and Event ID to 1 to see if it spawned any other programs... and found that now it appeared the attack was establishing persistance through different means. These included, adding the users "shuna" and "shion" and adding them to the group "administrators". The other persistance mechanism appears to be a adding a registry key to allow final.exe to start on boot.<br/>
<img src="https://github.com/user-attachments/assets/b9b8574d-e3b4-437f-a836-3866fae0d22c"  alt="DFIR Lab"/>
<br />
<br />
<h2>Thoughts</h2>
This lab was exceptionally well put together. It was definitely one of the longer ones I have done, but it did a phenomenal job of showcasing the investigation from start to finish, including how an attacker would gain initial access, conduct discovery, and then add persistence. It did not touch on extraction or attacks on objectives, but it was still a marathon of a lab. I gained experience with EZ tools, which were surprisingly straightforward. I had the impression that DFIR tools were extremely complex, but with Timeline Explorer, I am much more confident and comfortable using them. Moreover, I have had much practice and exposure with Brim and conducting threat intelligence/OSINT, so that was also good practice to keep my skills sharp. The lab provided a few hints to put us on the right track but left the heavy lifting to us as SOC Analysts, which was also great. Overall, I really enjoyed this lab and seeing how an attacker downloads/drops so many different malicious files and creates multiple C2 servers rather than just one. Seeing data being tunneled through HTTP GET requests, further obfuscated with Base64 encoding, was very interesting, which makes me consider examining any suspicious web traffic as it can be tunneling commands used to add persistence to your endpoints.
<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

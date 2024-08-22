<h1>Digital Forensics, Incident Response Lab</h1>


<h2>Description</h2>
Text
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
In the lab I was provided a packet capture and windows Event Viewer sysmon logs. I decided to start the investigation examining the sysmon logs. Uses EZ Tools (Eric Zimmerman tools) I used EvtxEcmd to convert the event logs into a .csv file for processing in Timeline explorer. This was done through powershell. I loaded the logs into Timeline explorer and they populated correctly. <br/>
<img src="https://github.com/user-attachments/assets/8a171437-d205-4f24-a527-4e1215f0a41f"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/15bfd80c-2612-4b73-9b69-6e2e7087533d"  alt="DFIR Lab"/>
<br />
<br />
The scenario for the lab, gave us a hint or a place to start the investigation in which it mentioned that the malicious document has a .doc extension, so within Timeline Explorer in the executable info I seatched for an file that has a .doc extension and found one file which I wanted to investigate further.<br/>
<img src="https://github.com/user-attachments/assets/e358c6a9-9b24-4879-be54-531081660038"  alt="DFIR Lab"/>
<br />
<br />
With examing the log of that contained the .doc file, I discovered the user logged in as benimaru and the PID of the file as 496. I then changed the filter to include the username, the PID and Event Code 22, to determine if the file made any DNS requests outside the network found that it did contact an IP address of 167[.]71[.]199[.]191.<br/>
<img src="https://github.com/user-attachments/assets/71c4df43-79fc-4d04-be83-89c096b8f284"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/1457c147-338b-4f05-9c61-160ee7830714"  alt="DFIR Lab"/>
<br />
<br />
 That alone is cause for concern as outbount connection can allow for further malware to be downloaded. I continued investigating events by changing the filter to 496 being the ParentPID and Event Code 1 to see if the document spawned any new process and found that it started the process C:\Windows\SysWOW64\msdt.exe followed by script with base64 encoded text and what appears to be direcotry traversal. I used cyberchef to decode the the base64 string and found it to be a command that is launched from ...\Start Menu\Programs\Startup which contacts the domain phishteam[.]xyz/02dcf07, downloaded a file named update.zip, unzips it, runs, it and removes it. <br/>
<img src="https://github.com/user-attachments/assets/87dc0424-7c2b-43a1-87ba-bbf919387513"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/05be0917-8815-4f88-833f-0a31e04d8bc5"  alt="DFIR Lab"/>
<br />
<br />
After conducting some OSINT on this attack vector I discovered a post explaining that I was a discovered vulnerbility and explained how it is exploited which is how the attack occured after the .doc file made in onto the endpoint.<br/>
<img src="https://github.com/user-attachments/assets/273aeded-cfc0-454a-9bd5-0879a4012570"  alt="DFIR Lab"/>
<br />
<br />
Now that part of the intital access has been discovered I moved on to part two of the lab where another hint was given that said "The Autostart execution reflects explorer.exe as its parent process ID. Child processes of explorer.exe within the event timeframe could be significant. Process Creation (Event ID 1) and File Creation (Event ID 11) succeeding the document execution are worth checking". With this, I changed the Event Code to 11 and Paylod 4 to include startup from what we know about the vulnerability and found the update.zip that we saw in the decoded base-64 string.<br/>
<img src="https://github.com/user-attachments/assets/883bffde-bae2-4a1c-b6d9-be513b15cf56"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/fa639fae-0175-40ef-b2b9-3872c782512a"  alt="DFIR Lab"/>
<br />
<br />
Also, knowing that "The Autostart execution reflects explorer.exe as its parent process ID.", U changed Paylod 4 to contain explorer and Event Code to 1 to discover any processes created with explorer and came accross poweshell being executed as "-w hidden -noni certutil..." a common attack method for it powershell to be ran without user being aware. The Powershell command contacted the malicious domain earlier phishtem[.]xyz and downloaded first.exe. Uptaining the hash of first.exe, I did not find any OSINT data signifying that is a known malicious file or executable, however due to the circumstances under which it is downloaded, I will treat it as malicious.<br/>
<img src="https://github.com/user-attachments/assets/2b3fcc6a-9b4a-475f-a545-c28e9388ff2a"  alt="DFIR Lab"/>
<img src="https://github.com/user-attachments/assets/5af4f1a2-7678-4028-9565-cf1c1c0c7403"  alt="DFIR Lab"/>
<br />
<br />
Continuing down the attack, I changed first.exe to the parent process and Event Code back to 1 to see if it created any process and I discovered further malicious actions. Particularly, that first, contacted a new domain resolvecyber[.]xyz and downloaded and ran ch.exe which ran and connected to the IP address 167.71.199.191 over port 8080 which is used for HTTP traffic in most cases.<br/>
<img src="https://github.com/user-attachments/assets/d35435ed-1422-4359-ae51-9176914a3c0e"  alt="DFIR Lab"/>
 <img src="https://github.com/user-attachments/assets/13614ba5-2c47-4d6b-a2df-df62048dffc4"  alt="DFIR Lab"/>
<br />
<br />
With what appears to be a potential Command and Control (c2) server being created by first.exe, I switched by focus to the packet capture to see what kind of traffic was made to the malicious domains and IP addresses. I used Brim/Zui for this task. Within Brim, I filtered for HTTP GET requests ti tge second malicious donmain/potential C2 server, resolvesyber[.]xyz and discovered numerous GET requests encoded over the port 8080 which we saw connection to.<br/>
<img src="https://github.com/user-attachments/assets/46903726-f565-4dec-bd67-94ff81d61b6c"  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
  Text<br/>
<img src=""  alt="DFIR Lab"/>
<br />
<br />
<h2>Thoughts</h2>
This lab was exceptionally put together


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

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
Text


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

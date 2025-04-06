<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/itn8/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

the DeviceFileEvents table was searched for any file with the string "tor" in it. An associated device, "onboardingwinvm" and user, "labuser" was returned from the query. 
After discovering what seemed to be the first instance of suspicious related file executions, the query was further narrowed to project hits after this first instance's timestamp, and eliminate entries of expected system processes. 
The remaining events allowed deduction through their timeline that a tor installer preceded multiple tor-related files being copied to the device's desktop, and the creation of a text file named `tor-shopping-list.exe`. 
These events began at: `2025-04-02T00:45:38.6247811Z`
The `tor-shopping-list` text file was created at: `2025-04-02T01:04:34.6741532Z`

**Combined query elements:**

```kql
DeviceFileEvents
| where DeviceName == "onboardingwinvm"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
   	and FileName !contains "history"
   	and FileName !contains "storage"  
   	and FileName !contains "tutorial"
   	and FileName !contains "validator"
   	and FileName !contains "webappsstore"
| where Timestamp >= datetime(2025-04-02T00:45:38.6247811Z)
| project Timestamp, ActionType, FileName, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ab4c8dc8-4132-47b1-b773-86ae0ada5b5a" />

---

### 2. Searched the `DeviceProcessEvents` Table

The first suspicious instance in the previously-searched `DeviceFileEvents` table contained a file named "tor-browser-windows-x86_64-portable-14.0.9.exe". 
A web browser search showed the filename reflected the most recent stable release of TOR browser. The SHA256 hash of the executable logged on the VM was compared to TOR's public hash of the same version and showed a match, confirming the executable's contents. 

With this information, the `DeviceProcessEvents` table was queried to find concrete information on any executions that were run. This query contained the device name, username, and browser executable to begin. 
Results found a single hit for the file name, and further, showed a `tor-browser-windows-x86_64-portable-14.0.9.exe  /S` entry under the `ProcessCommandLine` column. This highlighted a deliberate silent installation of the file from the Downloads directory by using the "/S" switch in the command line. 
The associated timestamp with this installation was: `2025-04-02T00:47:54.9755596Z`.

**Combined query elements:**

```kql
DeviceProcessEvents
| where DeviceName == "onboardingwinvm"
| where AccountName == "labuser"
| where FileName contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/9620f187-1f0a-433e-9c9c-2c4551ae8aa7" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

A web search was conducted to determine common executable names for the TOR browser. These names were used in a new search in the `DeviceProcessEvents` table by isolating hits with filenames containing "firefox.exe", "tor.exe" or "tor-browser.exe". 
Results showed multiple `firefox.exe` processes created with directory paths originating from the TOR browser installation folder, and a later `tor.exe` process. The associated timestamp for the first process instance was logged at: `2025-04-02T00:51:44.0556845Z`
This further served the TOR browser narrative, as the TOR browser is a modified version of Mozilla's Firefox browser. 

**Combined query elements:**

```kql
DeviceProcessEvents
| where DeviceName == "onboardingwinvm"
| where AccountName == "labuser"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f8582ab7-ff4c-48f5-b59e-3671be84d21f" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The file sizes of the tor.exe and firefox.exe executables were noted. To determine searches were performed with the browser, the `DeviceNetworkEvents` table was searched for the VM in question with a query narrowing to the noted file sizes. 
Common ports associated with the TOR browser were investigated, then narrowed in the query. 

It was found that at timestamp `2025-04-02T00:52:19.290646Z`, that the user `labuser` created a successful connection utilizing the TOR browser with `firefox.exe` found in directory path `c:\users\labuser\desktop\torbrowser\browser\tor.exe` over port 9001 from local port 50525.

**Combined query elements:**


```kql
DeviceNetworkEvents
| where DeviceName == "onboardingwinvm"
| where InitiatingProcessAccountName == "labuser"
| where InitiatingProcessFileSize in (1758208, 8979968)
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName, InitiatingProcessFolderPath 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/703e7c99-73e4-447c-8420-cd4443c85549" />


---

## Chronological Event Timeline

### 1. File Creation - TOR Installer

- **Timestamp:** `2025-04-02T00:45:38.6247811Z`  
- **Event:** The file `tor-browser-windows-x86_64-portable-14.0.9.exe` was created or accessed on the device `onboardingwinvm` by user `labuser`.  
- **Action:** File creation/access detected.  
- **File Path:** *(Not explicitly stated)*

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-02T00:47:54.9755596Z`  
- **Event:** The TOR installer `tor-browser-windows-x86_64-portable-14.0.9.exe` was executed in silent mode using the `/S` flag, indicating an unattended installation.  
- **Action:** Process creation detected.  
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`  
- **File Path:** *(Not explicitly stated)*

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-02T00:51:44.0556845Z`  
- **Event:** Execution of `firefox.exe` from within the TOR Browser directory by user `labuser` was recorded. Multiple instances followed shortly after installation.  
- **Action:** Process creation of TOR browser executable detected.  
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Relay Node

- **Timestamp:** `2025-04-02T00:52:11Z`  
- **Event:** A network connection using TOR-related infrastructure was established, likely via `firefox.exe` or `tor.exe`.  
- **Action:** Connection success.  
- **Remote IP:** `85.215.145.68`  
- **Remote Port:** `9001`  
- **Local Port:** `50525`  
- **Process:** Likely `firefox.exe` or `tor.exe`

### 5. Network Connection - TOR SOCKS Proxy

- **Timestamp:** `2025-04-02T00:52:19.290646Z`  
- **Event:** A loopback network connection on port `9150` was initiated by `firefox.exe`, indicating routing through the TOR network.  
- **Action:** Connection success.  
- **Process:** `firefox.exe`  
- **Remote Port:** `9150`  
- **Local IP:** `127.0.0.1`  
- **Local Port:** `50534`

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-02T01:04:34.6741532Z`  
- **Event:** A file named `tor-shopping-list.txt` was created on the desktop by user `labuser`, possibly indicating planned TOR browser activity or task tracking.  
- **Action:** File creation detected.  
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

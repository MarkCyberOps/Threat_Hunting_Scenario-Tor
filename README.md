# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MarkCyberOps/Threat_Hunting_Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it discovered what looks like the user “vmfinalmark0331$” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2026-02-23T00:37:41.8332387Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-mark-hun"
| where InitiatingProcessAccountName == "vmfinalmark0331$"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-23T00:27:28.2936528Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvents table for any ProcessCommandLine that contains the string "tor-browser-windows-x86_64-portable-15.0.6.exe". Based on the logs returned at 7:27 PM on February 22, 2026, the virtual machine “threat-mark-hun” recorded the system account vmfinalmark0331$ launching a file named tor-browser-windows-x86_64-portable-15.0.6.exe from the Downloads folder, executing it with a silent install command (/S) — meaning the Tor Browser installer began running quietly in the background without any user prompts or visible setup windows.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-mark-hun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.6.exe"
| project Timestamp,DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search the DeviceProcessEvents table for any indication that the user “vmfinalmark0331$”actually opened the tor browser. There was evidence that they did open it at 2026-02-23T00:28:39.272434Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned after.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-mark-hun"
| where FileName has_any ("tor.exe", "tor-browser-windows-x86_64.exe", "tor-browser-windows-i686.exe", "torbrowser-install.exe", "tor-browser-installer.exe", "firefox.exe")
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents  table for any indication the tor browser was used to establish a connection using any of the known tor ports at 2026-02-23T00:29:05.6903536Z.  At 7:29 PM on February 22, 2026, the virtual machine “threat-mark-hun” successfully established a network connection from firefox.exe, running inside the Tor Browser directory on the user’s desktop, to 127.0.0.1 (localhost) on port 9151 — which is the Tor control port — indicating that the Tor Browser was actively communicating with its local Tor service on the machine. There were other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-mark-hun"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-22T19:14:48.6065231Z`
- **Event:** The user "vmfinalmark0331$" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\VMFinalMark0331$\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-22T19:27:40Z`
- **Event:** The user "vmfinalmark0331$" executed the file `tor-browser-windows-x86_64-portable-15.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.6.exe /S`
- **File Path:** `C:\Users\VMFinalMark0331$\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-22T19:28:12Z`
- **Event:** User "vmfinalmark0331$" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\vmfinalmark0331$\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-22T19:28:39.272434Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "vmfinalmark0331$" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\vmfinalmark0331$\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp:** `2026-02-22T19:29:05.6903536Z`
    - **Event:** - Firefox.exe established a connection to localhost on port 9151, confirming communication with the local Tor service.
- **Timestamp:** `2026-02-22T19:29:59Z`
    - **Event:**  Additional local Tor communication observed over port 9150.
Action: Connection success.
- **Timestamp:** `2026-02-22T19:18:08Z`
    - **Event:**  Outbound encrypted connection established over port 443 consistent with Tor network activity.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-22T19:27:19.7259964Z`
- **Event:** The user "vmfinalmark0331$" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\vmfinalmark0331$\Desktop\tor-shopping-list.txt`

---

## Summary

On February 22, 2026, user vmfinalmark0331$ downloaded and silently installed Tor Browser on workstation threat-mark-hun. The installation deployed Tor application files to the desktop, after which the user launched the browser. Process creation events confirmed execution of firefox.exe and tor.exe within the Tor Browser directory.
Subsequent network telemetry showed successful connections to Tor control ports 9151 and 9150 on localhost, confirming active Tor service communication. Additional outbound encrypted traffic over port 443 was observed, consistent with Tor network usage.
A file named tor-shopping-list.txt was created on the desktop during the activity window, indicating active user interaction while Tor was running.
The collected evidence confirms unauthorized installation and active use of Tor Browser on endpoint threat-mark-hun.

---

## Response Taken

TOR usage was confirmed on endpoint threat-mark-hun by the user vmfinalmark0331$. The device was isolated and the user’s direct manager was notified.

---

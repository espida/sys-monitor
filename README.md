# Sys-Monitor.ps1

A lightweight PowerShell script for real-time system resource monitoring on Windows.

## 🧾 Features

- Displays system resource usage:
  - CPU usage
  - RAM usage
  - Disk status
  - Network status (Sent and Received)
- Clean, tabular output in the console
- Real-time updating with screen refresh

## ⚙️ Requirements

- PowerShell 5 or higher
- Windows operating system

## 🛠️ Installation & Usage

1. Clone the repository or download the [`sys-monitor.ps1`](https://github.com/espida/sys-monitor/blob/main/sys-monitor.ps1) file:

   ```bash
   git clone https://github.com/espida/sys-monitor.git
   ```

2. Run the script:

   Navigate to the script directory and execute:

   ```powershell
   .\sys-monitor.ps1
   ```

   > ⚠️ If you encounter an execution policy error, you may need to adjust the script execution policy:

   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## ⌛ Stopping the Script

To stop the monitoring, press `Ctrl + C` in the PowerShell window.

## 📂 Output Overview

The script continuously displays:

- **CPU Usage (%)**
- **Memory Usage (Used / Total / Free)**
- **Disk usage for each logical drive**
- **Network data (Sent / Received in MB)**

## 🧑‍💻 Author

- [@espida](https://github.com/espida)

## 📄 License

This project is licensed under the [MIT License](LICENSE).

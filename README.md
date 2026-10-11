# NetPulse: Multi-Threaded Network Port & Security Audit Tool

**NetPulse** is a concurrent TCP network reconnaissance utility written in 100% Pure Java. It inspects IP addresses and port ranges to discover active services, measure latency, and flag unencrypted or risky open ports (e.g., FTP, Telnet, exposed databases, cleartext HTTP).

---

## 🛠️ Key Architectural Features
1. **100% Pure Java (Java SE 8 / 11 / 17 / 21 compatible)**: Zero external Maven/Gradle dependencies. Uses standard java.net.*, java.util.concurrent.*, and javax.swing.*.
2. **High-Performance Asynchronous Concurrency**: Built with ExecutorService (25 to 150 configurable worker threads) to audit thousands of ports in seconds.
3. **Responsive GUI**: Uses SwingWorker for background scanning so the UI never freezes or stutters.
4. **Vulnerability & Security Risk Analysis**: Built-in ServiceCatalog maps open ports to known protocols and labels them as **SAFE**, **CAUTION**, or **HIGH VULNERABILITY** with descriptive security advisories.
5. **Real-time Feedback**: Dynamic progress bar, live port inspector, and color-coded table rows.
6. **Report Export**: Save audit reports into .csv (spreadsheet ready) or .txt (formatted ASCII audit table) with timestamping via JFileChooser.
7. **Quick Presets**: Fast one-click buttons for Web ports, Well-known ports (1–1024), Databases, and Critical infrastructure.

---

## 📂 Project Structure
`	ext
c:\Users\LENOVO\Downloads\Java miniproject\
├── ScanResult.java        # Immutable data model for scanned ports & security risk levels
├── ServiceCatalog.java    # Knowledge base mapping port numbers to services and risk advisories
├── ScannerEngine.java     # Core TCP handshake connection & port scanner logic
├── ScannerWorker.java     # SwingWorker orchestrating thread pools, cancellation, & UI callbacks
├── NetPulseGUI.java       # Modern dark-mode Java Swing desktop interface
├── Main.java              # Application launcher
└── README.md              # Documentation & Run Guide
`

---

## 🚀 How to Compile and Run

### 1. From Command Line (Windows PowerShell / Command Prompt / Terminal)
Make sure you have JDK (Java Development Kit 8 or higher) installed.

#### Compile:
`ash
javac *.java
`

#### Run:
`ash
java Main
# OR
java NetPulseGUI
`

### 2. In VS Code
1. Open folder Java miniproject in VS Code.
2. Install the **Extension Pack for Java** (by Microsoft).
3. Open NetPulseGUI.java or Main.java.
4. Click the **Run** button (play icon) at the top right, or press F5.

### 3. In IntelliJ IDEA
1. Open IntelliJ -> **Open** -> Select c:\Users\LENOVO\Downloads\Java miniproject.
2. Ensure your Project SDK is set (File -> Project Structure -> SDK -> Java 8 or higher).
3. Right-click Main.java or NetPulseGUI.java -> Click **Run 'Main.main()'**.

### 4. In Eclipse
1. File -> **Open Projects from File System...** -> Select directory.
2. Right-click Main.java -> **Run As** -> **Java Application**.

---

## 🔒 Security Risk Classifications
- 🟢 **SAFE**: Encrypted and secure services (SSH: 22, HTTPS: 443, SMTPS: 465, LDAPS: 636, IMAPS: 993).
- 🟡 **CAUTION**: Unencrypted protocols, admin interfaces, or protocols requiring caution (HTTP: 80, SMTP: 25, RDP: 3389, HTTP-Alt: 8080).
- 🔴 **HIGH VULNERABILITY**: Cleartext remote shells, insecure file transfer, or exposed databases (Telnet: 23, FTP: 21, SMB: 445, MySQL: 3306, Postgres: 5432, MongoDB: 27017, Redis: 6379, Elasticsearch: 9200).
- 🔵 **INFO**: Unclassified / custom services.

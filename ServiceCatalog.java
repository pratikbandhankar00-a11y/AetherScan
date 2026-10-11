import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * NetPulse: Multi-Threaded Network Port & Security Audit Tool
 * 
 * Built-in lookup mapping port numbers to protocol names, security descriptions,
 * and risk classifications.
 */
public class ServiceCatalog {

    public static class ServiceInfo {
        private final String name;
        private final ScanResult.RiskLevel riskLevel;
        private final String advisory;

        public ServiceInfo(String name, ScanResult.RiskLevel riskLevel, String advisory) {
            this.name = name;
            this.riskLevel = riskLevel;
            this.advisory = advisory;
        }

        public String getName() {
            return name;
        }

        public ScanResult.RiskLevel getRiskLevel() {
            return riskLevel;
        }

        public String getAdvisory() {
            return advisory;
        }
    }

    private static final Map<Integer, ServiceInfo> CATALOG;

    static {
        Map<Integer, ServiceInfo> map = new HashMap<>();

        // Well-known & common network ports with security classification
        map.put(20, new ServiceInfo("FTP-Data", ScanResult.RiskLevel.HIGH, "File Transfer Protocol (Data) — unencrypted traffic"));
        map.put(21, new ServiceInfo("FTP", ScanResult.RiskLevel.HIGH, "Plaintext file transfer — high risk of credential sniffing"));
        map.put(22, new ServiceInfo("SSH", ScanResult.RiskLevel.SAFE, "Encrypted remote terminal / Secure Shell"));
        map.put(23, new ServiceInfo("Telnet", ScanResult.RiskLevel.HIGH, "Obsolete unencrypted remote shell — credentials transmitted in cleartext"));
        map.put(25, new ServiceInfo("SMTP", ScanResult.RiskLevel.CAUTION, "Mail transfer agent — ensure TLS / STARTTLS is enforced"));
        map.put(43, new ServiceInfo("WHOIS", ScanResult.RiskLevel.INFO, "Directory lookup protocol"));
        map.put(53, new ServiceInfo("DNS", ScanResult.RiskLevel.SAFE, "Domain Name System resolver"));
        map.put(67, new ServiceInfo("DHCP-Server", ScanResult.RiskLevel.CAUTION, "Bootstrap/DHCP server protocol"));
        map.put(68, new ServiceInfo("DHCP-Client", ScanResult.RiskLevel.CAUTION, "Bootstrap/DHCP client protocol"));
        map.put(69, new ServiceInfo("TFTP", ScanResult.RiskLevel.HIGH, "Trivial FTP — unauthenticated file transfer"));
        map.put(80, new ServiceInfo("HTTP", ScanResult.RiskLevel.CAUTION, "Unencrypted web server — sensitive data vulnerable to MITM"));
        map.put(88, new ServiceInfo("Kerberos", ScanResult.RiskLevel.SAFE, "Authentication agent service"));
        map.put(110, new ServiceInfo("POP3", ScanResult.RiskLevel.HIGH, "Post Office Protocol v3 — cleartext mail retrieval"));
        map.put(111, new ServiceInfo("RPCBind", ScanResult.RiskLevel.HIGH, "ONC RPC portmapper — frequent target for enumeration"));
        map.put(123, new ServiceInfo("NTP", ScanResult.RiskLevel.SAFE, "Network Time Protocol"));
        map.put(135, new ServiceInfo("MS-RPC", ScanResult.RiskLevel.HIGH, "Microsoft Windows RPC endpoint mapper — potential exploit surface"));
        map.put(137, new ServiceInfo("NetBIOS-NS", ScanResult.RiskLevel.HIGH, "NetBIOS Name Service — prone to spoofing & information disclosure"));
        map.put(138, new ServiceInfo("NetBIOS-DGM", ScanResult.RiskLevel.HIGH, "NetBIOS Datagram Service"));
        map.put(139, new ServiceInfo("NetBIOS-SSN", ScanResult.RiskLevel.HIGH, "NetBIOS Session Service — SMB exposure"));
        map.put(143, new ServiceInfo("IMAP", ScanResult.RiskLevel.CAUTION, "Internet Message Access Protocol — plaintext mail access without STARTTLS"));
        map.put(161, new ServiceInfo("SNMP", ScanResult.RiskLevel.HIGH, "Simple Network Management Protocol — default community strings risk"));
        map.put(162, new ServiceInfo("SNMP-Trap", ScanResult.RiskLevel.CAUTION, "SNMP Trap notifications"));
        map.put(389, new ServiceInfo("LDAP", ScanResult.RiskLevel.CAUTION, "Lightweight Directory Access Protocol — use LDAPS (636) instead"));
        map.put(443, new ServiceInfo("HTTPS", ScanResult.RiskLevel.SAFE, "TLS/SSL encrypted web server"));
        map.put(445, new ServiceInfo("SMB", ScanResult.RiskLevel.HIGH, "Microsoft-DS Active Directory / Windows Share — critical attack vector"));
        map.put(465, new ServiceInfo("SMTPS", ScanResult.RiskLevel.SAFE, "Encrypted SMTP over SSL/TLS"));
        map.put(514, new ServiceInfo("Syslog", ScanResult.RiskLevel.CAUTION, "System logging stream — unencrypted"));
        map.put(587, new ServiceInfo("SMTP-Submission", ScanResult.RiskLevel.SAFE, "Mail submission with mandatory TLS"));
        map.put(636, new ServiceInfo("LDAPS", ScanResult.RiskLevel.SAFE, "Secure LDAP over TLS/SSL"));
        map.put(993, new ServiceInfo("IMAPS", ScanResult.RiskLevel.SAFE, "Encrypted IMAP over TLS/SSL"));
        map.put(995, new ServiceInfo("POP3S", ScanResult.RiskLevel.SAFE, "Encrypted POP3 over TLS/SSL"));
        map.put(1080, new ServiceInfo("SOCKS-Proxy", ScanResult.RiskLevel.HIGH, "SOCKS Proxy server — possible open relay/pivot"));
        map.put(1433, new ServiceInfo("MS-SQL", ScanResult.RiskLevel.HIGH, "Microsoft SQL Server directly exposed — risk of brute-force & exploit"));
        map.put(1521, new ServiceInfo("Oracle-DB", ScanResult.RiskLevel.HIGH, "Oracle TNS Listener database port directly exposed"));
        map.put(2049, new ServiceInfo("NFS", ScanResult.RiskLevel.HIGH, "Network File System — misconfigured shares lead to data leakage"));
        map.put(2375, new ServiceInfo("Docker-Plain", ScanResult.RiskLevel.HIGH, "Unencrypted Docker REST API daemon — root container escape hazard"));
        map.put(2376, new ServiceInfo("Docker-TLS", ScanResult.RiskLevel.SAFE, "TLS-secured Docker daemon"));
        map.put(3306, new ServiceInfo("MySQL", ScanResult.RiskLevel.HIGH, "MySQL database port directly exposed — risk of credential attacks"));
        map.put(3389, new ServiceInfo("RDP", ScanResult.RiskLevel.CAUTION, "Windows Remote Desktop Protocol — high-value target for ransomware/bruteforce"));
        map.put(5432, new ServiceInfo("PostgreSQL", ScanResult.RiskLevel.HIGH, "PostgreSQL database port directly exposed"));
        map.put(5900, new ServiceInfo("VNC", ScanResult.RiskLevel.HIGH, "Virtual Network Computing — unencrypted remote desktop interface"));
        map.put(6379, new ServiceInfo("Redis", ScanResult.RiskLevel.HIGH, "In-memory database — typically lacks authentication by default"));
        map.put(8000, new ServiceInfo("HTTP-Alt-8000", ScanResult.RiskLevel.CAUTION, "Alternative web/dev server (e.g., Python SimpleHTTPServer, Django)"));
        map.put(8080, new ServiceInfo("HTTP-Alt-8080", ScanResult.RiskLevel.CAUTION, "Alternative web server / development proxy / Tomcat"));
        map.put(8443, new ServiceInfo("HTTPS-Alt", ScanResult.RiskLevel.SAFE, "Alternative HTTPS web server / Tomcat SSL"));
        map.put(8888, new ServiceInfo("HTTP-Alt-8888", ScanResult.RiskLevel.CAUTION, "Jupyter / Alternate web application"));
        map.put(9000, new ServiceInfo("SonarQube/PHP-FPM", ScanResult.RiskLevel.CAUTION, "Development management interface / FastCGI"));
        map.put(9200, new ServiceInfo("Elasticsearch", ScanResult.RiskLevel.HIGH, "Elasticsearch cluster API — often exposed without authorization"));
        map.put(11211, new ServiceInfo("Memcached", ScanResult.RiskLevel.HIGH, "Memcached caching server — risk of unauthenticated data dump or DDoS amplification"));
        map.put(27017, new ServiceInfo("MongoDB", ScanResult.RiskLevel.HIGH, "NoSQL database directly exposed — frequent target for ransomware"));

        CATALOG = Collections.unmodifiableMap(map);
    }

    /**
     * Resolves service information for a given port.
     */
    public static ServiceInfo lookup(int port) {
        ServiceInfo info = CATALOG.get(port);
        if (info != null) {
            return info;
        }
        return new ServiceInfo("Unknown Service", ScanResult.RiskLevel.INFO, "Unclassified TCP port — verify application profile");
    }

    /**
     * Presets for quick scanning.
     */
    public static final int[] PRESET_COMMON_WEB = { 80, 443, 8000, 8080, 8443, 8888 };
    public static final int[] PRESET_DATABASES = { 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017 };
    public static final int[] PRESET_CRITICAL_ADMIN = { 21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080 };
}

/**
 * NetPulse: Multi-Threaded Network Port & Security Audit Tool
 * 
 * Model class representing the outcome of scanning a specific network port.
 */
public class ScanResult {

    public enum RiskLevel {
        SAFE("Safe", "Encrypted / Low Risk"),
        CAUTION("Caution", "Plaintext / Sensitive / Admin"),
        HIGH("High Vulnerability", "High Risk / Known Insecure / Exposed DB"),
        INFO("Info", "Unknown / Unclassified Service");

        private final String displayName;
        private final String description;

        RiskLevel(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }
    }

    private final int port;
    private final String serviceName;
    private final String status;
    private final long latencyMs;
    private final RiskLevel riskLevel;
    private final String securityNotes;

    public ScanResult(int port, String serviceName, String status, long latencyMs, RiskLevel riskLevel, String securityNotes) {
        this.port = port;
        this.serviceName = serviceName;
        this.status = status;
        this.latencyMs = latencyMs;
        this.riskLevel = riskLevel;
        this.securityNotes = securityNotes;
    }

    public int getPort() {
        return port;
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getStatus() {
        return status;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public String getSecurityNotes() {
        return securityNotes;
    }

    @Override
    public String toString() {
        return String.format("Port %d [%s] - %s (%d ms) | Risk: %s - %s",
                port, serviceName, status, latencyMs, riskLevel.getDisplayName(), securityNotes);
    }
}

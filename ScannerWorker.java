import javax.swing.SwingWorker;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * NetPulse: Multi-Threaded Network Port & Security Audit Tool
 * 
 * Background worker handling multi-threaded asynchronous port scanning
 * with live GUI progress and cancellation support.
 */
public class ScannerWorker extends SwingWorker<Void, ScanResult> {

    public interface ScanProgressListener {
        void onScanStarted(int totalPorts);
        void onPortScanned(int scannedCount, int totalPorts, int openCount, int currentPort);
        void onScanCompleted(int totalPorts, int openCount, boolean wasCancelled);
        void onScanError(String errorMessage);
    }

    private final String targetHost;
    private final List<Integer> portsToScan;
    private final int timeoutMs;
    private final int threadPoolSize;
    private final ScanProgressListener listener;

    private final AtomicInteger scannedCount = new AtomicInteger(0);
    private final AtomicInteger openCount = new AtomicInteger(0);
    private final AtomicBoolean isCancelled = new AtomicBoolean(false);

    private ExecutorService executor;

    public ScannerWorker(String targetHost, List<Integer> portsToScan, int timeoutMs,
                         int threadPoolSize, ScanProgressListener listener) {
        this.targetHost = targetHost;
        this.portsToScan = portsToScan;
        this.timeoutMs = timeoutMs;
        this.threadPoolSize = threadPoolSize;
        this.listener = listener;
    }

    @Override
    protected Void doInBackground() {
        final int totalPorts = portsToScan.size();
        if (totalPorts == 0) {
            return null;
        }

        if (listener != null) {
            listener.onScanStarted(totalPorts);
        }

        // Pre-validate target host resolution before launching concurrent threads
        try {
            java.net.InetAddress.getByName(targetHost);
        } catch (UnknownHostException e) {
            if (listener != null) {
                listener.onScanError("Host resolution failed: Unknown host '" + targetHost + "'. Please check IP or hostname.");
            }
            return null;
        } catch (Exception e) {
            if (listener != null) {
                listener.onScanError("Error resolving host: " + e.getMessage());
            }
            return null;
        }

        executor = Executors.newFixedThreadPool(threadPoolSize);

        for (final int port : portsToScan) {
            if (isCancelled.get() || isCancelled()) {
                break;
            }

            executor.submit(new Runnable() {
                @Override
                public void run() {
                    if (isCancelled.get() || Thread.currentThread().isInterrupted()) {
                        return;
                    }

                    ScanResult result = scanPort(targetHost, port, timeoutMs);
                    int currentScanned = scannedCount.incrementAndGet();

                    if (result != null) {
                        int currentOpen = openCount.incrementAndGet();
                        publish(result);
                        if (listener != null) {
                            listener.onPortScanned(currentScanned, totalPorts, currentOpen, port);
                        }
                    } else {
                        if (listener != null) {
                            listener.onPortScanned(currentScanned, totalPorts, openCount.get(), port);
                        }
                    }
                }
            });
        }

        executor.shutdown();
        try {
            // Wait until all tasks finish or scan is stopped
            while (!executor.awaitTermination(300, TimeUnit.MILLISECONDS)) {
                if (isCancelled.get() || isCancelled()) {
                    executor.shutdownNow();
                    break;
                }
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        return null;
    }

    /**
     * Attempts a TCP connection to the given host:port and measures latency.
     * Returns a ScanResult if OPEN, or null if CLOSED/FILTERED/UNREACHABLE.
     */
    private ScanResult scanPort(String host, int port, int timeout) {
        Socket socket = null;
        try {
            long startTime = System.currentTimeMillis();
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeout);
            long latency = Math.max(1, System.currentTimeMillis() - startTime);

            // Port is open! Look up risk advisory
            ServiceCatalog.ServiceInfo info = ServiceCatalog.lookup(port);
            return new ScanResult(
                    port,
                    info.getName(),
                    "OPEN",
                    latency,
                    info.getRiskLevel(),
                    info.getAdvisory()
            );
        } catch (SocketTimeoutException ignored) {
            // Port filtered / connection timed out
            return null;
        } catch (IOException ignored) {
            // Port closed / refused connection
            return null;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {}
            }
        }
    }

    @Override
    protected void process(List<ScanResult> chunks) {
        // Handled via publish -> consumed by GUI table model listener in NetPulseGUI
    }

    @Override
    protected void done() {
        boolean cancelled = isCancelled.get() || isCancelled();
        if (listener != null) {
            listener.onScanCompleted(portsToScan.size(), openCount.get(), cancelled);
        }
    }

    /**
     * Gracefully aborts an active scan and shuts down worker threads immediately.
     */
    public void cancelScan() {
        isCancelled.set(true);
        cancel(true);
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }
}

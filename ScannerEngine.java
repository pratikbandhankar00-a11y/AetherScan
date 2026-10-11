import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.*;

/**
 * NetPulse: Multi-Threaded Network Port & Security Audit Tool
 * 
 * Standalone CLI Scanner Engine that can be executed directly or called programmatically.
 */
public class ScannerEngine {

    public interface ScanCallback {
        void onPortScanned(int scanned, int total, ScanResult result);
    }

    private final int timeoutMs;
    private final int threadPoolSize;

    public ScannerEngine(int timeoutMs, int threadPoolSize) {
        this.timeoutMs = timeoutMs;
        this.threadPoolSize = threadPoolSize;
    }

    /**
     * Inspects a single port on target host.
     * @return ScanResult if OPEN, or null if CLOSED/FILTERED.
     */
    public ScanResult scanSinglePort(String host, int port) {
        Socket socket = null;
        try {
            long start = System.currentTimeMillis();
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            long latency = Math.max(1, System.currentTimeMillis() - start);

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
            return null;
        } catch (IOException ignored) {
            return null;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {}
            }
        }
    }

    /**
     * Scans a list of ports concurrently using ExecutorService.
     */
    public void scanPorts(final String host, final List<Integer> ports, final ScanCallback callback) {
        ExecutorService executor = Executors.newFixedThreadPool(threadPoolSize);
        final int total = ports.size();
        final java.util.concurrent.atomic.AtomicInteger scanned = new java.util.concurrent.atomic.AtomicInteger(0);

        for (final int port : ports) {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    ScanResult res = scanSinglePort(host, port);
                    int count = scanned.incrementAndGet();
                    if (callback != null) {
                        callback.onPortScanned(count, total, res);
                    }
                }
            });
        }

        executor.shutdown();
        try {
            executor.awaitTermination(30, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

package dev.cats.dozing;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Guest workload for the Dozing memory-reclaim experiment.
 *
 * <p>Two things are being probed at once. First, a realistic Spring Boot resident
 * footprint, so the reclaim ladder measures a floor a real user would hit rather
 * than a synthetic one. Second, whether an in-process scheduler survives host-side
 * memory reclaim and VM pause: every fire records both wall clock and monotonic
 * clock, which discriminates the two failure modes. If the monotonic clock stops
 * while the VM is paused, the monotonic delta stays at the nominal period and the
 * wall delta grows by the pause; if it keeps running, both deltas grow together and
 * the task fires immediately on resume.
 */
@SpringBootApplication
@EnableScheduling
@RestController
public class DozingApp {

    /** Kept short so a rung's measurement window captures several fires. */
    private static final long FIXED_RATE_MS = 120_000L;

    private static final Path FIRE_LOG = Path.of("/var/log/dozing/fires.csv");

    private final AtomicLong fixedRateSeq = new AtomicLong();
    private final AtomicLong cronSeq = new AtomicLong();
    private final List<byte[]> retained = new ArrayList<>();

    private volatile long lastFixedWallMs = -1;
    private volatile long lastFixedNanos = -1;

    public static void main(String[] args) throws IOException {
        Files.createDirectories(FIRE_LOG.getParent());
        if (!Files.exists(FIRE_LOG)) {
            Files.writeString(FIRE_LOG,
                "kind,seq,wall_ms,nano_ms,uptime_ms,wall_delta_ms,nano_delta_ms\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        SpringApplication.run(DozingApp.class, args);
    }

    @Scheduled(fixedRate = FIXED_RATE_MS)
    public void fixedRateTask() {
        long wallMs = System.currentTimeMillis();
        long nanos = System.nanoTime();
        long wallDelta = lastFixedWallMs < 0 ? -1 : wallMs - lastFixedWallMs;
        long nanoDelta = lastFixedNanos < 0 ? -1 : (nanos - lastFixedNanos) / 1_000_000L;
        lastFixedWallMs = wallMs;
        lastFixedNanos = nanos;
        record("fixed_rate", fixedRateSeq.incrementAndGet(), wallMs, nanos, wallDelta, nanoDelta);
    }

    /** CronTrigger recomputes from the current time, so it should not burst-catch-up. */
    @Scheduled(cron = "0 */2 * * * *")
    public void cronTask() {
        record("cron", cronSeq.incrementAndGet(), System.currentTimeMillis(), System.nanoTime(), -1, -1);
    }

    private void record(String kind, long seq, long wallMs, long nanos, long wallDelta, long nanoDelta) {
        String line = String.join(",",
            kind,
            Long.toString(seq),
            Long.toString(wallMs),
            Long.toString(nanos / 1_000_000L),
            Long.toString(uptimeMs()),
            Long.toString(wallDelta),
            Long.toString(nanoDelta)) + "\n";
        try {
            Files.writeString(FIRE_LOG, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // The fire log is best effort; losing a line must not kill the scheduler.
        }
    }

    @GetMapping("/ready")
    public Map<String, Object> ready() {
        return Map.of("ok", true, "uptime_ms", uptimeMs());
    }

    /**
     * Allocates and touches {@code mib} of heap, then drops it. Produces the garbage
     * churn that gives the guest's own LRU something cold to find.
     */
    @GetMapping("/touch")
    public Map<String, Object> touch(@RequestParam(defaultValue = "128") int mib) {
        long start = System.nanoTime();
        for (int i = 0; i < mib; i++) {
            byte[] block = new byte[1024 * 1024];
            for (int offset = 0; offset < block.length; offset += 4096) {
                block[offset] = (byte) (offset >>> 12);
            }
        }
        return Map.of("ok", true, "mib", mib,
            "elapsed_ms", (System.nanoTime() - start) / 1_000_000L);
    }

    /** Retains {@code mib} of live heap: unreclaimable without guest swap. */
    @GetMapping("/hold")
    public Map<String, Object> hold(@RequestParam(defaultValue = "64") int mib) {
        for (int i = 0; i < mib; i++) {
            byte[] block = new byte[1024 * 1024];
            for (int offset = 0; offset < block.length; offset += 4096) {
                block[offset] = (byte) 0x5a;
            }
            retained.add(block);
        }
        return Map.of("ok", true, "retained_mib", retained.size());
    }

    /**
     * Runs a shell command in the guest. This exists so the harness does not have
     * to install an SSH server: sshd would be resident during every measurement
     * and would inflate the very floor this experiment reports. The guest sits on
     * an isolated tap with no route to anything but the host.
     */
    @GetMapping("/exec")
    public Map<String, Object> exec(@RequestParam String cmd) {
        try {
            ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", cmd);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            String output = new String(process.getInputStream().readAllBytes());
            boolean done = process.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
            return Map.of("ok", done, "exit", done ? process.exitValue() : -1, "output", output);
        } catch (Exception e) {
            return Map.of("ok", false, "error", String.valueOf(e));
        }
    }

    @GetMapping("/fires")
    public String fires() throws IOException {
        return Files.exists(FIRE_LOG) ? Files.readString(FIRE_LOG) : "";
    }

    /**
     * Full GC so the collector can hand committed heap back to the OS. Without
     * this the floor is set by whatever the heap high-water mark happened to be,
     * which measures a JVM flag rather than the reclaim mechanism under test.
     */
    @GetMapping("/gc")
    public Map<String, Object> gc() {
        Runtime runtime = Runtime.getRuntime();
        long before = runtime.totalMemory() / 1024;
        for (int i = 0; i < 3; i++) {
            System.gc();
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return Map.of("heap_total_kib_before", before,
            "heap_total_kib_after", runtime.totalMemory() / 1024,
            "rss_kib", procStatusKib("VmRSS"));
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("uptime_ms", uptimeMs());
        out.put("wall_ms", System.currentTimeMillis());
        out.put("nano_ms", System.nanoTime() / 1_000_000L);
        out.put("jvm_rss_kib", procStatusKib("VmRSS"));
        out.put("jvm_swap_kib", procStatusKib("VmSwap"));
        Runtime runtime = Runtime.getRuntime();
        out.put("heap_used_kib", (runtime.totalMemory() - runtime.freeMemory()) / 1024);
        out.put("heap_total_kib", runtime.totalMemory() / 1024);
        out.putAll(meminfo());
        out.put("fixed_rate_fires", fixedRateSeq.get());
        out.put("cron_fires", cronSeq.get());
        return out;
    }

    private static long uptimeMs() {
        try {
            String first = Files.readString(Path.of("/proc/uptime")).trim().split("\\s+")[0];
            return (long) (Double.parseDouble(first) * 1000);
        } catch (Exception e) {
            return -1;
        }
    }

    private static long procStatusKib(String key) {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith(key + ":")) {
                    return Long.parseLong(line.replaceAll("[^0-9]", ""));
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return -1;
    }

    private static Map<String, Object> meminfo() {
        Map<String, Object> out = new LinkedHashMap<>();
        List<String> wanted = List.of("MemTotal", "MemFree", "MemAvailable", "Cached",
            "Buffers", "SwapTotal", "SwapFree", "AnonPages", "Slab");
        try {
            for (String line : Files.readAllLines(Path.of("/proc/meminfo"))) {
                int colon = line.indexOf(':');
                if (colon < 0) {
                    continue;
                }
                String key = line.substring(0, colon);
                if (wanted.contains(key)) {
                    out.put("guest_" + key.toLowerCase() + "_kib",
                        Long.parseLong(line.substring(colon + 1).replaceAll("[^0-9]", "")));
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return out;
    }
}

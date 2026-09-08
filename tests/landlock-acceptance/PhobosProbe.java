import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Runs one probe inside the sandboxed JVM and prints a single parsable line:
 *   RESULT <check> <target> OK|DENIED <detail>
 */
public final class PhobosProbe {

    private static final int CONNECT_TIMEOUT_MS = 3000;

    public static void main(String[] args) throws Exception {
        String check = args[0];
        switch (check) {
            case "read" -> read(args[1]);
            case "write" -> write(args[1]);
            case "connect" -> connect(args[1], Integer.parseInt(args[2]));
            case "spin" -> spin();
            case "spawn" -> spawn(args);
            default -> {
                System.out.println("RESULT " + check + " - DENIED unknown-check");
                System.exit(2);
            }
        }
    }

    private static void report(String check, String target, boolean ok, String detail) {
        System.out.println("RESULT " + (ok ? "OK" : "DENIED") + " " + check + " " + target + " " + detail);
    }

    private static void read(String target) {
        try {
            String content = Files.readString(Path.of(target)).strip();
            report("read", target, true, "content=" + content);
        }
        catch (IOException e) {
            report("read", target, false, e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    private static void write(String target) {
        try {
            Files.write(Path.of(target), "written-by-probe\n".getBytes(StandardCharsets.UTF_8));
            report("write", target, true, "bytes-written");
        }
        catch (IOException e) {
            report("write", target, false, e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    private static void connect(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            OutputStream out = socket.getOutputStream();
            out.write("ping\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            report("connect", host + ":" + port, true, "connected");
        }
        catch (Exception e) {
            report("connect", host + ":" + port, false, e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    /** Escape attempt: does a freshly spawned child process inherit the sandbox? */
    private static void spawn(String[] args) {
        String[] command = new String[args.length - 1];
        System.arraycopy(args, 1, command, 0, command.length);
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
            int code = process.waitFor();
            boolean ok = (code == 0);
            report("spawn", String.join(" ", command), ok, "exit=" + code + " out=" + output.replace('\n', '|'));
        }
        catch (Exception e) {
            report("spawn", String.join(" ", command), false, e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    /**
     * Actively tries to survive the timeout: a shutdown hook that never returns
     * makes the JVM ignore SIGTERM, so only SIGKILL can end this process.
     */
    private static void spin() throws InterruptedException {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("RESULT OK spin - shutdown-hook-blocking");
            System.out.flush();
            while (true) {
                try {
                    Thread.sleep(60_000L);
                }
                catch (InterruptedException ignored) {
                    // deliberately keep blocking
                }
            }
        }));
        System.out.println("RESULT OK spin - spinning-and-ignoring-sigterm");
        System.out.flush();
        while (true) {
            Thread.sleep(60_000L);
        }
    }
}

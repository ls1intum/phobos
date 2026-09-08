import java.net.ServerSocket;
import java.net.Socket;

/** Two loopback TCP servers: one the policy allows, one it does not. */
public final class NetServers {

    public static void main(String[] args) throws Exception {
        for (String arg : args) {
            int port = Integer.parseInt(arg);
            ServerSocket server = new ServerSocket(port, 16);
            Thread thread = new Thread(() -> accept(server, port));
            thread.setDaemon(true);
            thread.start();
        }
        System.out.println("servers-ready");
        System.out.flush();
        Thread.sleep(Long.MAX_VALUE);
    }

    private static void accept(ServerSocket server, int port) {
        while (true) {
            try (Socket client = server.accept()) {
                client.getInputStream().read();
            }
            catch (Exception e) {
                return;
            }
        }
    }
}

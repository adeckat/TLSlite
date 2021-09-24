import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    static ServerSocket serverSocket;
    static Socket socket;
    static TLSHandshake tlsHandshake;

    private class PartyType {
        final static int CLIENT = 1;
        final static int SERVER = 2;
    }

    public static void main(String[] args) throws Exception {
        int port = 6789;
        serverSocket = new ServerSocket(port);
        tlsHandshake = new TLSHandshake(PartyType.SERVER);
        System.out.println("Generating server...");

        while (true) {
            socket = serverSocket.accept();
            System.out.println("Client is connecting to server");
            try {
                new TLSHandshake(socket).start();
            } catch (Exception e) {
                System.err.println(e.toString());
            }
        }
    }
}

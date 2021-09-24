import java.io.IOException;
import java.net.Socket;

public class Client {

    static Socket sock;
    static TLSHandshake tlsHandshake;

    private class PartyType {
        final static int CLIENT = 1;
        final static int SERVER = 2;
    }

    public static void main(String[] args) throws Exception {
        String host = "127.0.0.1";
        int port = 6789;
        tlsHandshake = new TLSHandshake(PartyType.CLIENT);
        System.out.println("Generating client...");

        try {
            sock = new Socket(host, port);
            new TLSHandshake(sock).start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

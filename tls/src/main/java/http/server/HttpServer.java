package http.server;

import http.common.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Locale;

import static http.common.Config.LISTEN_PORT;

/**
 * @author Ivan Konstantinov (ikonstantino@vmware.com)
 */
public class HttpServer {

    private static final Logger log = LoggerFactory.getLogger("SERVER");
    private final Config config;

    HttpServer() {
        try {
            log.info("Reading configuration");
            config = new Config("server");
        } catch (IOException e) {
            throw new RuntimeException(String.format("Failed to initialize server : %s", e.getMessage()), e);
        }
    }

    private SSLServerSocketFactory createSocketFactory() {
        try {
            // Get the keystore
            log.info("Initializing stores and loading the server certificate");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = ClassLoader.getSystemClassLoader()
                    .getResourceAsStream("server/" + config.getServerCertificateFile());
            keyStore.load(inputStream, "".toCharArray());


            // TrustManagerFactory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
            trustManagerFactory.init((KeyStore) null);
            X509TrustManager x509TrustManager = null;
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    x509TrustManager = (X509TrustManager) trustManager;
                    break;
                }
            }

            if (x509TrustManager == null) {
                throw new NullPointerException();
            }

            // KeyManagerFactory ()
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            keyManagerFactory.init(keyStore, "".toCharArray());
            X509KeyManager x509KeyManager = null;
            for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509KeyManager) {
                    x509KeyManager = (X509KeyManager) keyManager;
                    break;
                }
            }
            if (x509KeyManager == null) {
                throw new NullPointerException();
            }


            // set up the SSL Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(new KeyManager[]{x509KeyManager}, new TrustManager[]{x509TrustManager}, null);
            return sslContext.getServerSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException("Caught exception while initializing server socket factory", e);
        }
    }

    void accept() {
        log.info("Listening and accepting connections");
        try {
            ServerSocket serverSocket = createServerSocket();
            Socket socket = serverSocket.accept();
            log.info("Accepted connection from {}", socket.getInetAddress().getAddress());
            try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                while (true) {
                    String msg = in.readLine();
                    log.info("Got message from client: {}", msg);
                    if ("bye".equals(msg.toLowerCase(Locale.ROOT))) {
                        log.info("Bye");
                        return;
                    }
                    log.info("Sending message back to client");
                    out.println(msg);
                    out.flush();
                }


            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private ServerSocket createServerSocket() {
        try {
            if (Config.useTLS) {
                SSLServerSocketFactory serverSocketFactory = createSocketFactory();
                SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(LISTEN_PORT);
                if (config.getProtocols() != null) {
                    serverSocket.setEnabledProtocols(config.getProtocols());
                }
                if (config.getCipherSuites() != null) {
                    serverSocket.setEnabledCipherSuites(config.getCipherSuites());
                }
                return serverSocket;
            } else {
                return new ServerSocket(LISTEN_PORT);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    public static void main(String[] args) throws IOException {
        new HttpServer().accept();
    }
}

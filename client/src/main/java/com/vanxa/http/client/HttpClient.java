package com.vanxa.http.client;

import com.vanxa.http.common.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.Scanner;

import static com.vanxa.http.common.Config.LISTEN_PORT;


public class HttpClient {

    private static final Logger log = LoggerFactory.getLogger("CLIENT");
    private final Config config;

    HttpClient() {
        log.info("Reading configuration");
        try {
            config = Config.load("client");
        } catch (IOException e) {
            log.error("Failed to read configuration", e);
            throw new RuntimeException(e);
        }

    }

    private SSLSocketFactory createSocketFactory() throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, KeyManagementException, CertificateException, IOException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");

        if (config.getServerCertificateFile() != null) {
            log.info("Loading server certificate against which client will validate the connection");
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            String password2 = "";

            InputStream inputStream1 = config.loadCertificate();
            trustStore.load(inputStream1, password2.toCharArray());
            trustManagerFactory.init(trustStore);
        } else {
            log.info("No certificate loaded");
            trustManagerFactory.init((KeyStore) null);
        }

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
        // set up the SSL Context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[0], new TrustManager[]{x509TrustManager}, null);
        return sslContext.getSocketFactory();
    }

    public void connect() {
        try {
            try (Socket serverSocket = createSocket()) {
                try (PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);
                     BufferedReader in = new BufferedReader(
                             new InputStreamReader(serverSocket.getInputStream()))) {
                    Scanner scanner = new Scanner(System.in);
                    while (true) {
                        log.info("Message:");
                        String msg = scanner.nextLine();
                        if ("bye".equals(msg.toLowerCase(Locale.ROOT))) {
                            log.info("Closing connection. bye");
                            out.println(msg);
                            out.flush();
                            return;
                        }
                        log.info("Sending message: {} to server", msg);
                        out.println(msg);
                        out.flush();
                        log.info("Response from server: {} ", in.readLine());
                    }
                }
            }

        } catch (IOException e) {
            log.error("Caught exception", e);
            throw new RuntimeException(e);
        }
    }

    private Socket createSocket() {
        try {
            if (Config.useTLS) {
                log.info("Creating Socket Factory for future connections");
                SSLSocketFactory socketFactory = createSocketFactory();
                log.info("Client initalized");
                SSLSocket sock = (SSLSocket) socketFactory.createSocket("localhost", LISTEN_PORT);
                if (config.getProtocols() != null) {
                    sock.setEnabledProtocols(config.getProtocols());
                }

                if (config.getCipherSuites() != null) {
                    sock.setEnabledCipherSuites(config.getCipherSuites());
                }
                return sock;
            } else {
                return new Socket("localhost", LISTEN_PORT);
            }
        } catch (Exception e) {
            log.error("Caught exception while creating ssl socket", e);
            throw new RuntimeException(e);
        }
    }


    public static void main(String[] args) {
        new HttpClient().connect();
    }
}

package com.vanxa.http.common;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author Ivan Konstantinov (ikonstantino@vmware.com)
 */
public class Config {

    private final String serverCertificateFile;
    private final String[] cipherSuites;
    private final String[] protocols;
    private final String[] algorithms;
    public static final int LISTEN_PORT = 4443;
    public static final boolean useTLS = false;

    public Config(String app) throws IOException {
        Properties props = new Properties();
        props.load(Config.class.getResourceAsStream(String.format("/%s/app.properties", app)));

        serverCertificateFile = props.getProperty("certificate.file");
        cipherSuites = StringUtils.isNotEmpty(props.getProperty("tls.ciphers", "")) ?
                props.getProperty("tls.ciphers").split(",") : null;
        protocols = StringUtils.isNotEmpty(props.getProperty("tls.protocols", "")) ?
                props.getProperty("tls.protocols").split(",") : null;
        algorithms = StringUtils.isNotEmpty(props.getProperty("tls.algorithms", "")) ?
                props.getProperty("tls.algorithms").split(",") : null;
    }

    public static Config load(String client) throws IOException {
        return new Config(client);
    }

    public String getServerCertificateFile() {
        return serverCertificateFile;
    }

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public String[] getProtocols() {
        return protocols;
    }

    public String[] getAlgorithms() {
        return algorithms;
    }

    public InputStream loadCertificate() {
        return getClass().getClassLoader().getResourceAsStream("certs/" + getServerCertificateFile());

    }
}

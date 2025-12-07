package com.example.asiceverifier;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.X509CRL;
import java.util.*;

public final class Config {
    public static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private final Set<String> signatureVersionNamespaces;
    private final Set<String> asicNamespaces;
    private final Set<String> c14nUris;
    private final Set<String> signatureMethodUris;
    private final Set<String> digestMethodUris;
    private final Set<String> transformUris;

    private Config(Set<String> signatureVersionNamespaces,
                   Set<String> asicNamespaces,
                   Set<String> c14nUris,
                   Set<String> signatureMethodUris,
                   Set<String> digestMethodUris,
                   Set<String> transformUris) {
        this.signatureVersionNamespaces = signatureVersionNamespaces;
        this.asicNamespaces = asicNamespaces;
        this.c14nUris = c14nUris;
        this.signatureMethodUris = signatureMethodUris;
        this.digestMethodUris = digestMethodUris;
        this.transformUris = transformUris;
    }

    public Set<String> signatureVersionNamespaces() { return signatureVersionNamespaces; }
    public Set<String> asicNamespaces() { return asicNamespaces; }
    public Set<String> c14nUris() { return c14nUris; }
    public Set<String> signatureMethodUris() { return signatureMethodUris; }
    public Set<String> digestMethodUris() { return digestMethodUris; }
    public Set<String> transformUris() { return transformUris; }
    private final List<String> containerFiles = new ArrayList<>();

    private Date timestampTime;
    private X509CRL lastCrl;

    // getters & setters
    public Date getTimestampTime() {
        return timestampTime;
    }

    public void setTimestampTime(Date timestampTime) {
        this.timestampTime = timestampTime;
    }

    public X509CRL getLastCrl() {
        return lastCrl;
    }

    public void setLastCrl(X509CRL lastCrl) {
        this.lastCrl = lastCrl;
    }

    public static Config load(Path externalProperties) throws IOException {
        Properties p = new Properties();

        // defaults from resources
        try (InputStream in = Config.class.getClassLoader().getResourceAsStream("verifier.properties")) {
            if (in != null) p.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }

        // override
        if (externalProperties != null) {
            Properties ext = new Properties();
            try (InputStream in = Files.newInputStream(externalProperties)) {
                ext.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            }
            p.putAll(ext);
        }

        Set<String> sigVerNs = getSet(p, "signatureVersion.namespaces",
                Set.of("http://www.ditec.sk/ep/signature_formats/xades_zepbp/v1.0"));
        Set<String> asicNs = getSet(p, "asic.namespaces",
                Set.of("http://uri.etsi.org/02918/v1.2.1#", "http://uri.etsi.org/02918/v1.3.1#"));
        Set<String> c14n = getSet(p, "algo.c14n",
                Set.of("http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2006/12/xml-c14n11"));
        Set<String> sigM = getSet(p, "algo.signatureMethod",
                Set.of("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
        Set<String> digM = getSet(p, "algo.digestMethod",
                Set.of("http://www.w3.org/2001/04/xmlenc#sha256"));
        Set<String> tr = getSet(p, "algo.transform",
                Set.of("http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"));

        return new Config(sigVerNs, asicNs, c14n, sigM, digM, tr);
    }

    private static Set<String> getSet(Properties p, String key, Set<String> def) {
        String v = p.getProperty(key);
        if (v == null || v.trim().isEmpty()) return new LinkedHashSet<>(def);
        Set<String> out = new LinkedHashSet<>();
        for (String part : v.split(",")) {
            String s = part.trim();
            if (!s.isEmpty()) out.add(s);
        }
        return out;
    }

    public List<String> getContainerFiles() {
        return containerFiles;
    }
}

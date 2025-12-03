package com.example.asiceverifier;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.xpath.*;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class AsiceReader {
    private final XmlLoader loader = new XmlLoader();

    public Document readSignatureXml(Path asiceFile) {
        try (ZipFile zip = new ZipFile(asiceFile.toFile())) {

            List<ZipEntry> candidates = new ArrayList<>();
            Enumeration<? extends ZipEntry> en = zip.entries();

            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                if (ze.isDirectory()) continue;
                String name = ze.getName();
                if (name.toLowerCase(Locale.ROOT).endsWith(".xml") && name.startsWith("META-INF/")) {
                    candidates.add(ze);
                }
            }

            candidates.sort(Comparator.comparingInt((ZipEntry z) -> rank(z.getName())).reversed());

            for (ZipEntry c : candidates) {
                byte[] data = readAll(zip, c);
                try {
                    Document d = loader.parseSecure(data);
                    if (hasDsSignature(d)) return d;
                } catch (VerificationException ignored) {}
            }

            throw new VerificationException(
                    Errors.SIGNATURE_XML_NOT_FOUND,
                    "No signature XML found in " + asiceFile.getFileName() + " (expected META-INF/*.xml with ds:Signature)"
            );

        } catch (VerificationException ve) {
            throw ve;
        } catch (Exception e) {
            throw new VerificationException(Errors.ASICE_OPEN_FAILED,
                    "Cannot open .asice (zip): " + asiceFile.getFileName() + " - " + e.getMessage());
        }
    }

    private boolean hasDsSignature(Document d) {
        try {
            XPath xp = XPathFactory.newInstance().newXPath();
            NodeList nl = (NodeList) xp.evaluate(
                    "//*[local-name()='Signature' and namespace-uri()='" + Config.DS_NS + "']",
                    d,
                    XPathConstants.NODESET
            );
            return nl.getLength() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private int rank(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        int r = 0;
        if (n.startsWith("meta-inf/")) r += 20;
        if (n.contains("signature")) r += 50;
        return r;
    }

    private byte[] readAll(ZipFile zip, ZipEntry entry) throws Exception {
        try (InputStream in = zip.getInputStream(entry)) {
            return in.readAllBytes();
        }
    }
}

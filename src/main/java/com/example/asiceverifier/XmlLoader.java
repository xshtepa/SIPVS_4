package com.example.asiceverifier;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;

public final class XmlLoader {
    public Document parseSecure(byte[] xmlBytes) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            // XXE protection (best effort)
            trySet(dbf, "http://apache.org/xml/features/disallow-doctype-decl", true);
            trySet(dbf, "http://xml.org/sax/features/external-general-entities", false);
            trySet(dbf, "http://xml.org/sax/features/external-parameter-entities", false);
            trySet(dbf, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            DocumentBuilder b = dbf.newDocumentBuilder();
            return b.parse(new ByteArrayInputStream(xmlBytes));
        } catch (Exception e) {
            throw new VerificationException(Errors.SIGNATURE_XML_PARSE_FAILED, "XML parse failed: " + e.getMessage());
        }
    }

    private static void trySet(DocumentBuilderFactory dbf, String feat, boolean v) {
        try { dbf.setFeature(feat, v); } catch (Exception ignored) {}
    }
}

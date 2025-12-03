package com.example.asiceverifier;

import org.w3c.dom.*;

import javax.xml.xpath.*;

public final class XadesTVerifier {

    private static final String DS_NS = Config.DS_NS;

    private static final String XZEP_PREFIX = "http://www.ditec.sk/ep/signature_formats/xades_zepbp/";

    private static final String ASIC_PREFIX = "http://uri.etsi.org/02918/";

    public void verify(Document doc, Config cfg) {
        // 1) Overenie profilu
        check1a_signatureVersion_and_xmlnsDs(doc);
        check1b_asicNamespace(doc);

        // 2) Overenie XML Signature
        check2a_methods(doc, cfg);
        check2b_references(doc, cfg);
    }

    // 1a: SignatureVersion namespace podľa profilu + Signature musí mať xmlns:ds (v scope)
    private void check1a_signatureVersion_and_xmlnsDs(Document doc) {
        // SignatureVersion exists + namespace looks like xades_zepbp/*
        NodeList sv = nodes(doc, "//*[local-name()='SignatureVersion']");
        if (sv.getLength() == 0) {
            throw new VerificationException(Errors.PROFILE_SIGNATUREVERSION_MISSING,
                    "1a: Missing element SignatureVersion.");
        }

        Element e = (Element) sv.item(0);
        String ns = e.getNamespaceURI();
        ns = (ns == null) ? "" : ns;

        if (!ns.startsWith(XZEP_PREFIX)) {
            throw new VerificationException(Errors.PROFILE_SIGNATUREVERSION_NAMESPACE_UNSUPPORTED,
                    "1a: SignatureVersion has unsupported namespace: '" + ns + "'. Expected prefix: " + XZEP_PREFIX);
        }

        // Signature element presence + xmlns:ds in scope
        Element sig = firstElement(doc, "//*[local-name()='Signature']");
        if (sig == null) {
            throw new VerificationException(Errors.XMLSIG_SIGNATURE_ELEM_MISSING,
                    "1a: Missing Signature element.");
        }

        if (!hasDsNamespaceInScope(sig)) {
            throw new VerificationException(Errors.PROFILE_DS_PREFIX_MISSING_ON_SIGNATURE,
                    "1a: Signature does not have xmlns:ds in scope (expected ds='" + DS_NS + "').");
        }
    }

    // 1b: xmlns:asic exists on XAdESSignature(или XAdESSignatures) and looks like ASiC ns
    private void check1b_asicNamespace(Document doc) {
        Element container = firstElement(doc,
                "//*[local-name()='XAdESSignature' or local-name()='XAdESSignatures']");
        if (container == null) {
            throw new VerificationException(Errors.PROFILE_XADESSIGNATURE_MISSING,
                    "1b: Missing element XAdESSignature (or XAdESSignatures).");
        }

        String asic = container.getAttribute("xmlns:asic");
        if (asic == null || asic.trim().isEmpty()) {
            throw new VerificationException(Errors.PROFILE_ASIC_NAMESPACE_MISSING,
                    "1b: Missing xmlns:asic on XAdES container.");
        }

        asic = asic.trim();
        if (!asic.startsWith(ASIC_PREFIX)) {
            throw new VerificationException(Errors.PROFILE_ASIC_NAMESPACE_UNSUPPORTED,
                    "1b: Unsupported xmlns:asic='" + asic + "'. Expected prefix: " + ASIC_PREFIX);
        }
    }

    // 2a: SignatureMethod + CanonicalizationMethod must be from supported set (cfg)
    private void check2a_methods(Document doc, Config cfg) {
        NodeList signedInfos = nodes(doc,
                "//*[local-name()='Signature' and namespace-uri()='" + DS_NS + "']/*[local-name()='SignedInfo']");
        if (signedInfos.getLength() == 0) {
            signedInfos = nodes(doc, "//*[local-name()='SignedInfo']");
        }
        if (signedInfos.getLength() == 0) {
            throw new VerificationException(Errors.XMLSIG_SIGNEDINFO_MISSING,
                    "2a: Missing SignedInfo.");
        }

        Element si = (Element) signedInfos.item(0);

        Element c14n = first(si, "./*[local-name()='CanonicalizationMethod']");
        if (c14n == null) {
            throw new VerificationException(Errors.XMLSIG_C14N_METHOD_MISSING,
                    "2a: Missing CanonicalizationMethod.");
        }
        String c14nAlg = attr(c14n, "Algorithm");
        if (c14nAlg.isEmpty() || !cfg.c14nUris().contains(c14nAlg)) {
            throw new VerificationException(Errors.XMLSIG_C14N_ALGO_UNSUPPORTED,
                    "2a: Unsupported CanonicalizationMethod Algorithm: '" + c14nAlg + "'. Allowed: " + cfg.c14nUris());
        }

        Element sm = first(si, "./*[local-name()='SignatureMethod']");
        if (sm == null) {
            throw new VerificationException(Errors.XMLSIG_SIGNATURE_METHOD_MISSING,
                    "2a: Missing SignatureMethod.");
        }
        String smAlg = attr(sm, "Algorithm");
        if (smAlg.isEmpty() || !cfg.signatureMethodUris().contains(smAlg)) {
            throw new VerificationException(Errors.XMLSIG_SIGNATURE_ALGO_UNSUPPORTED,
                    "2a: Unsupported SignatureMethod Algorithm: '" + smAlg + "'. Allowed: " + cfg.signatureMethodUris());
        }
    }

    // 2b: DigestMethod required; Transforms
    private void check2b_references(Document doc, Config cfg) {
        NodeList refs = nodes(doc, "//*[local-name()='SignedInfo']/*[local-name()='Reference']");
        if (refs.getLength() == 0) {
            throw new VerificationException(Errors.XMLSIG_REFERENCE_MISSING,
                    "2b: No Reference elements in SignedInfo.");
        }

        for (int r = 0; r < refs.getLength(); r++) {
            Element ref = (Element) refs.item(r);
            String refUri = ref.hasAttribute("URI") ? ref.getAttribute("URI") : "(no URI)";

            // DigestMethod MUST exist
            Element dm = first(ref, "./*[local-name()='DigestMethod']");
            if (dm == null) {
                throw new VerificationException(Errors.XMLSIG_DIGEST_METHOD_MISSING,
                        "2b: Missing DigestMethod in Reference URI=" + refUri);
            }
            String digAlg = attr(dm, "Algorithm");
            if (digAlg.isEmpty() || !cfg.digestMethodUris().contains(digAlg)) {
                throw new VerificationException(Errors.XMLSIG_DIGEST_ALGO_UNSUPPORTED,
                        "2b: Unsupported DigestMethod Algorithm: '" + digAlg + "' in Reference URI=" + refUri
                                + ". Allowed: " + cfg.digestMethodUris());
            }

            Element transforms = first(ref, "./*[local-name()='Transforms']");
            if (transforms != null) {
                NodeList ts = nodes(transforms, "./*[local-name()='Transform']");
                for (int t = 0; t < ts.getLength(); t++) {
                    Element tr = (Element) ts.item(t);
                    String trAlg = attr(tr, "Algorithm");
                    if (trAlg.isEmpty() || !cfg.transformUris().contains(trAlg)) {
                        throw new VerificationException(Errors.XMLSIG_TRANSFORM_ALGO_UNSUPPORTED,
                                "2b: Unsupported Transform Algorithm: '" + trAlg + "' in Reference URI=" + refUri
                                        + ". Allowed: " + cfg.transformUris());
                    }
                }
            }
        }
    }

    // ---- helpers ----
    private static boolean hasDsNamespaceInScope(Element el) {
        Node cur = el;
        while (cur instanceof Element) {
            Element e = (Element) cur;
            if (e.hasAttribute("xmlns:ds") && DS_NS.equals(e.getAttribute("xmlns:ds").trim())) return true;
            cur = e.getParentNode();
        }
        // also accept if Signature element itself is in ds namespace
        String ns = el.getNamespaceURI();
        return DS_NS.equals(ns);
    }

    private static NodeList nodes(Node n, String expr) {
        try {
            XPath xp = XPathFactory.newInstance().newXPath();
            return (NodeList) xp.evaluate(expr, n, XPathConstants.NODESET);
        } catch (Exception e) {
            throw new RuntimeException("XPath error: " + e.getMessage(), e);
        }
    }

    private static Element first(Node n, String expr) {
        NodeList nl = nodes(n, expr);
        if (nl.getLength() == 0) return null;
        return (Element) nl.item(0);
    }

    private static Element firstElement(Node n, String expr) {
        return first(n, expr);
    }

    private static String attr(Element e, String a) {
        return e.hasAttribute(a) ? e.getAttribute(a).trim() : "";
    }
}

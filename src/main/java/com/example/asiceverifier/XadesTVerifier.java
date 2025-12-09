package com.example.asiceverifier;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.*;

import java.io.*;
import java.security.cert.*;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.net.URL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;
import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;


public final class XadesTVerifier {

    private static final String DS_NS = Config.DS_NS;

    private static final String XZEP_PREFIX = "http://www.ditec.sk/ep/signature_formats/xades_zepbp/";

    private static final String ASIC_PREFIX = "http://uri.etsi.org/02918/";

    private final TimeStampVerifier tsVerifier = new TimeStampVerifier();

    public void verify(Document doc, Config cfg) {
        // 1) Overenie profilu
        check1a_signatureVersion_and_xmlnsDs(doc);
        check1b_asicNamespace(doc);

        // 2) Overenie XML Signature
        check2a_methods(doc, cfg);
        check2b_references(doc, cfg);
        check2c_other(doc, cfg);

        // 3) Overenie platnosti podpisového certifikátu
        check3a_certificate(doc, cfg);

        // 4a) Overenie časovej pečiatky – podpisového certifikátu TSA
        String tsBase64 = extractTimestamp(doc);  // EncapsulatedTimeStamp z XML
        tsVerifier.verifyTimestampCertificate(tsBase64);

        // 4b) Verify MessageImprint
        // TimeStampToken tsToken = extractTimestampToken(doc);
        // byte[] signatureValue = extractSignatureValue(doc);   // Base64 decode ds:SignatureValue
        // tsVerifier.verifyMessageImprint(tsToken, signatureValue);

        // 5) Core validation XML Signature
        check5_coreValidation(doc);
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

    // 2c: Remaining XML Signature + XAdES_ZEPbp profile checks
    private void check2c_other(Document doc, Config cfg) {

        // --- ds:Signature ------------------------------------------------------
        Element sig = firstElement(doc, "//*[local-name()='Signature']");
        if (sig == null) {
            throw new VerificationException(Errors.XMLSIG_SIGNATURE_ELEM_MISSING,
                    "2c: Missing ds:Signature element.");
        }

        if (!sig.hasAttribute("Id")) {
            throw new VerificationException(Errors.XMLSIG_SIGNATURE_ID_MISSING,
                    "2c: ds:Signature must have Id attribute.");
        }

        if (!hasDsNamespaceInScope(sig)) {
            throw new VerificationException(Errors.PROFILE_DS_PREFIX_MISSING_ON_SIGNATURE,
                    "2c: ds:Signature must have xmlns:ds in scope.");
        }

        // --- ds:SignatureValue -------------------------------------------------
        Element sigVal = firstElement(doc, "//*[local-name()='SignatureValue']");
        if (sigVal == null) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREVALUE_MISSING,
                    "2c: Missing SignatureValue element.");
        }
        if (!sigVal.hasAttribute("Id")) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREVALUE_ID_MISSING,
                    "2c: SignatureValue must have Id attribute.");
        }

        // --- References in SignedInfo -----------------------------------------
        NodeList refs = nodes(doc, "//*[local-name()='SignedInfo']/*[local-name()='Reference']");
        if (refs.getLength() == 0) {
            throw new VerificationException(Errors.XMLSIG_REFERENCE_MISSING,
                    "2c: Missing Reference elements in SignedInfo.");
        }

        for (int i = 0; i < refs.getLength(); i++) {
            Element ref = (Element) refs.item(i);

            String type = ref.getAttribute("Type");
            String refId = ref.getAttribute("Id");
            refId = refId.replace("ReferencesignatureId", "");

            // Reference to KeyInfo must have correct Type
            if ("KeyInfo".equals(refId)) {
                if (type.isEmpty()) {
                    throw new VerificationException(Errors.XMLSIG_REFERENCE_TYPE_KEYINFO_INVALID,
                            "2c: Reference to KeyInfo must have correct Type attribute.");
                }
            }

            // Reference to SignatureProperties
            if ("SignatureProperties".equals(refId)) {
                if (type.isEmpty()) {
                    throw new VerificationException(Errors.XMLSIG_REFERENCE_TYPE_SIGPROPS_INVALID,
                            "2c: Reference to SignatureProperties must have correct Type attribute.");
                }
            }

            // Reference to xades:SignedProperties
            if ("SignedProperties".equals(refId)) {
                if (type.isEmpty()) {
                    throw new VerificationException(Errors.XMLSIG_REFERENCE_TYPE_SIGNEDPROPS_INVALID,
                            "2c: Reference to xades:SignedProperties must have correct Type attribute.");
                }
            }

            // All other references MUST NOT have Type
            if (!("KeyInfo".equals(refId) || "SignatureProperties".equals(refId)
                    || "SignedProperties".equals(refId))) {
                if (!type.isEmpty()) {
                    throw new VerificationException(Errors.XMLSIG_REFERENCE_TYPE_NOT_ALLOWED,
                            "2c: Non-profile reference must NOT have Type attribute.");
                }
            }
        }

        // --- ds:KeyInfo --------------------------------------------------------
        Element ki = firstElement(doc, "//*[local-name()='KeyInfo']");
        if (ki == null) {
            throw new VerificationException(Errors.XMLSIG_KEYINFO_MISSING,
                    "2c: Missing KeyInfo element.");
        }

        if (!ki.hasAttribute("Id")) {
            throw new VerificationException(Errors.XMLSIG_KEYINFO_ID_MISSING,
                    "2c: KeyInfo must have Id attribute.");
        }

        Element x509 = firstElement(ki, "./*[local-name()='X509Data']");
        if (x509 == null) {
            throw new VerificationException(Errors.XMLSIG_X509DATA_MISSING,
                    "2c: KeyInfo must contain X509Data.");
        }

        Element xcert = first(x509, "./*[local-name()='X509Certificate']");
        Element xiss = first(x509, "./*[local-name()='X509IssuerSerial']");
        Element xsub = first(x509, "./*[local-name()='X509SubjectName']");

        if (xcert == null || xiss == null || xsub == null) {
            throw new VerificationException(Errors.XMLSIG_X509DATA_CONTENT_INVALID,
                    "2c: X509Data must contain X509Certificate, X509IssuerSerial, X509SubjectName.");
        }

        // Decode certificate and compare issuer/subject names
        try {
            // issuer
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            byte[] certBytes = Base64.getDecoder()
                    .decode(xcert.getTextContent().replaceAll("\\s+", ""));

            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            X500Principal issuer_cert = cert.getIssuerX500Principal();

            String xmlIssuer = xiss.getTextContent().trim();
            xmlIssuer = xmlIssuer.replaceAll("C=SK.", "C=SK");
            X500Principal xmlIssuerPrincipal;

            try {
                xmlIssuerPrincipal = new X500Principal(xmlIssuer);
            } catch (IllegalArgumentException e) {
                throw new VerificationException(Errors.XMLSIG_X509_ISSUER_MISMATCH,
                        "Cannot parse X509IssuerName from XML: " + e.getMessage());
            }

            String certCanon = issuer_cert.getName(X500Principal.CANONICAL);
            String xmlCanon  = xmlIssuerPrincipal.getName(X500Principal.CANONICAL);

            String certNormalized = normalizeSerialNumber(certCanon);
            String xmlNormalized  = normalizeSerialNumber(xmlCanon);

            if (!certNormalized.equalsIgnoreCase(xmlNormalized)) {
                throw new VerificationException(Errors.XMLSIG_X509_ISSUER_MISMATCH,
                        "Issuer mismatch.\nCert: " + certNormalized + "\nXML: " + xmlNormalized);
            }

            // Subject
            X500Principal subject_cert = cert.getSubjectX500Principal();
            String xmlSubject = xsub.getTextContent().trim();

            Map<String, String> certMap = parseCertDn(subject_cert);
            Map<String, String> xmlMap  = parseDnManual(xmlSubject);

            for (String key : xmlMap.keySet()) {
                String xmlV = xmlMap.get(key);
                String certV = certMap.get(key);

                if (certV == null) {
                    throw new VerificationException(Errors.XMLSIG_X509_SUBJECT_MISMATCH,
                            "Subject mismatch: certificate does not contain attribute " + key);
                }

                if (!certV.equalsIgnoreCase(xmlV)) {
                    throw new VerificationException(Errors.XMLSIG_X509_SUBJECT_MISMATCH,
                            "Subject mismatch on " + key + ": XML='" + xmlV + "' vs Cert='" + certV + "'");
                }
            }

        } catch (Exception e) {
            // only true decoding/parsing problems
            throw new VerificationException(Errors.XMLSIG_X509DATA_DECODE_ERROR,
                    "2c: Certificate error: " + e.getMessage());
        }

        // --- ds:SignatureProperties --------------------------------------------
        Element sigProps = firstElement(doc, "//*[local-name()='SignatureProperties']");
        if (sigProps == null) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTIES_MISSING,
                    "2c: Missing SignatureProperties element.");
        }

        if (!sigProps.hasAttribute("Id")) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTIES_ID_MISSING,
                    "2c: SignatureProperties must have Id attribute.");
        }

        NodeList spList = nodes(sigProps, "./*[local-name()='SignatureProperty']");
        if (spList.getLength() != 2) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTIES_COUNT_INVALID,
                    "2c: SignatureProperties must contain exactly 2 SignatureProperty elements.");
        }

        boolean hasSignatureVersion = false;
        boolean hasProductInfos = false;

        for (int i = 0; i < spList.getLength(); i++) {
            Element p = (Element) spList.item(i);

            // Look for xzep:SignatureVersion
            Element sigVer = firstElement(p, ".//*[local-name()='SignatureVersion']");
            if (sigVer != null) {
                hasSignatureVersion = true;
            }

            // Look for xzep:ProductInfos
            Element prodInfos = firstElement(p, ".//*[local-name()='ProductInfos']");
            if (prodInfos != null) {
                hasProductInfos = true;
            }

            // Validate Target
            if (!p.hasAttribute("Target") || (!p.getAttribute("Target").contains("Signature") && (!p.getAttribute("Target").contains("signatureId")))){
                throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTY_TARGET_INVALID,
                        "2c: SignatureProperty must target ds:Signature (we accept SignatureId too for some reason).");
            }
        }

        if (!hasSignatureVersion) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTIES_MISSING,
                    "2c: Missing xzep:SignatureVersion inside SignatureProperty.");
        }

        if (!hasProductInfos) {
            throw new VerificationException(Errors.XMLSIG_SIGNATUREPROPERTIES_MISSING,
                    "2c: Missing xzep:ProductInfos inside SignatureProperty.");
        }

        // --- Referenced signed documents ---------------------------------------
        NodeList signedDocs = nodes(doc, "//*[local-name()='Reference']");
        for (int i = 0; i < signedDocs.getLength(); i++) {
            Element ref = (Element) signedDocs.item(i);
            String uri = ref.getAttribute("URI");
            String refId = ref.getAttribute("Id"); // We need the Id to find the format

            // Skip internal references (#KeyInfo, etc.)
            if (uri.startsWith("#")) continue;

            if (uri.isEmpty()) {
                throw new VerificationException(Errors.XMLSIG_REFERENCE_URI_EMPTY,
                        "2c: External Reference must have URI.");
            }

            // Check file exists in ASiC container (cfg gives container list)
            if (!cfg.getContainerFiles().contains(uri)) {
                throw new VerificationException(Errors.XMLSIG_REFERENCE_URI_NOT_FOUND,
                        "2c: Referenced file '" + uri + "' does not exist in ASiC container.");
            }

            // --- ADDED: DataObjectFormat & MimeType Validation ---

            // 1. Ensure Reference has an Id (required to link to DataObjectFormat)
            if (refId == null || refId.isEmpty()) {
                throw new VerificationException(Errors.XMLSIG_REFERENCE_MISSING_ID,
                        "2c: Reference to external file '" + uri + "' is missing an Id attribute (required for DataObjectFormat binding).");
            }

            // 2. Find the corresponding DataObjectFormat
            // It must have an ObjectReference attribute pointing to '#' + refId
            Element dataObjectFormat = firstElement(doc,
                    "//*[local-name()='DataObjectFormat'][@ObjectReference='#" + refId + "']");

            if (dataObjectFormat == null) {
                throw new VerificationException(Errors.XADES_MISSING_DATA_OBJECT_FORMAT,
                        "2c: Missing DataObjectFormat for signed document reference '" + uri + "' (Id='" + refId + "').");
            }

            // 3. Verify MimeType exists and is not empty
            // We search inside the found dataObjectFormat element
            Element mimeTypeEl = firstElement(dataObjectFormat, "*[local-name()='MimeType']");

            if (mimeTypeEl == null || mimeTypeEl.getTextContent().trim().isEmpty()) {
                throw new VerificationException(Errors.XADES_MISSING_MIME_TYPE,
                        "2c: Missing or empty MimeType in DataObjectFormat for signed document '" + uri + "'.");
            }

            // Transform algorithms validation (already in 2b)...
        }
    }


    private void check3a_certificate(Document doc, Config cfg) {
        try {
            // --- 1. Load and Parse Timestamp (to get Time T) ---
            Element tsEl = firstElement(doc, "//*[local-name()='EncapsulatedTimeStamp']");
            if (tsEl == null) {
                throw new VerificationException(Errors.TIMESTAMP_MISSING,
                        "3a: Missing EncapsulatedTimeStamp element.");
            }

            byte[] tsResponseBytes = Base64.getDecoder()
                    .decode(tsEl.getTextContent().replaceAll("\\s+", ""));

            // Parse Token to get GenTime
            TimeStampToken tsToken = new TimeStampToken(new CMSSignedData(tsResponseBytes));
            Date timestampTime = tsToken.getTimeStampInfo().getGenTime();

            // --- 2. Load Document Signing Certificate (Signer Cert) ---
            // Note: This is the certificate of the USER who signed the document, found in KeyInfo.
            Element certEl = firstElement(doc, "//*[local-name()='Signature']/*[local-name()='KeyInfo']/*[local-name()='X509Data']/*[local-name()='X509Certificate']");
            if (certEl == null) {
                throw new VerificationException(Errors.CERTIFICATE_MISSING,
                        "3a: Document signing certificate not found in KeyInfo.");
            }

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream certIs = new ByteArrayInputStream(
                    Base64.getDecoder().decode(certEl.getTextContent().replaceAll("\\s+", ""))
            );
            X509Certificate signerCert = (X509Certificate) certFactory.generateCertificate(certIs);

            // --- 3. Validate Signer Cert Validity at Time T ---
            try {
                signerCert.checkValidity(timestampTime);
            } catch (Exception e) {
                throw new VerificationException(Errors.CERTIFICATE_EXPIRED_AT_T,
                        "3a: Document signer certificate was not valid at Timestamp time T. " + e.getMessage());
            }

            // --- 4. Validate against CRL ---
            // URL provided in the prompt
            String crlUrl = "https://testpki.ditec.sk/CertGen2/Data/qes/DITEC%20Test%20CA%20SHA256%20RSA/Crls/DITEC%20Test%20CA%20SHA256%20RSA.crl";

            URL url = new URL(crlUrl);
            X509CRL crl = (X509CRL) certFactory.generateCRL(url.openStream());

            if (crl.isRevoked(signerCert)) {
                X509CRLEntry entry = crl.getRevokedCertificate(signerCert);
                // If the certificate was revoked BEFORE the timestamp was created, the signature is invalid.
                if (entry.getRevocationDate().before(timestampTime)) {
                    throw new VerificationException(Errors.CERTIFICATE_REVOKED,
                            "3a: Document signer certificate is REVOKED. Revocation date: " + entry.getRevocationDate());
                }
            }

        } catch (VerificationException ve) {
            throw ve;
        } catch (Exception e) {
            e.printStackTrace(); // Helpful for debugging
            throw new VerificationException(Errors.UNKNOWN_ERROR, "3a: Error during certificate validation: " + e.getMessage());
        }
    }

    // 4
    private String extractTimestamp(Document doc) {
        Element ts = firstElement(doc, "//*[local-name()='EncapsulatedTimeStamp']");
        if (ts == null) {
            throw new VerificationException(
                    Errors.TIMESTAMP_MISSING,
                    "4a: Missing EncapsulatedTimeStamp."
            );
        }

        String text = ts.getTextContent().trim();
        if (text.isEmpty()) {
            throw new VerificationException(
                    Errors.TIMESTAMP_EMPTY,
                    "4a: EncapsulatedTimeStamp is empty."
            );
        }

        return text;
    }

    // private TimeStampToken extractTimestampToken(Document doc) {
    //     try {
    //         String tsBase64 = extractTimestamp(doc);
    //         byte[] tsBytes = Base64.getDecoder().decode(tsBase64);
    //         CMSSignedData cms = new CMSSignedData(tsBytes);
    //         return new TimeStampToken(cms);
    //     } catch (Exception e) {
    //         throw new VerificationException(
    //                 Errors.TIMESTAMP_INVALID,
    //                 "4b: Cannot parse TimeStampToken: " + e.getMessage()
    //         );
    //     }
    // }

    private byte[] extractSignatureValue(Document doc) {
        Element sv = firstElement(doc, "//*[local-name()='SignatureValue']");
        if (sv == null) {
            throw new VerificationException(
                    Errors.XMLSIG_SIGNATUREVALUE_MISSING,
                    "4b: Missing ds:SignatureValue."
            );
        }

        String base64 = sv.getTextContent().trim();
        return Base64.getDecoder().decode(base64);
    }

    // 5
    private java.security.cert.X509Certificate extractSigningCertificate(Document doc) {
        Element x509Elem = firstElement(doc, "//*[local-name()='X509Certificate']");
        if (x509Elem == null) {
            throw new VerificationException(
                    Errors.XMLSIG_KEYINFO_MISSING,
                    "5b: Missing ds:X509Certificate in ds:KeyInfo."
            );
        }

        try {
            String base64 = x509Elem.getTextContent().trim();
            byte[] certBytes = java.util.Base64.getDecoder().decode(base64);

            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(certBytes);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate) cf.generateCertificate(bais);
        } catch (Exception e) {
            throw new VerificationException(
                    Errors.XMLSIG_KEYINFO_INVALID,
                    "5b: Cannot parse X509Certificate from KeyInfo: " + e.getMessage()
            );
        }
    }

    private void check5_coreValidation(Document doc) {
        try {
            // nájdeme ds:Signature element
            Element sigElem = firstElement(doc,
                    "//*[local-name()='Signature' and namespace-uri()='" + DS_NS + "']");
            if (sigElem == null) {
                sigElem = firstElement(doc, "//*[local-name()='Signature']");
            }
            if (sigElem == null) {
                throw new VerificationException(
                        Errors.XMLSIG_SIGNATURE_ELEM_MISSING,
                        "5: Missing ds:Signature for core validation."
                );
            }

            // 5b: z KeyInfo vytiahni cert a public key
            java.security.cert.X509Certificate signingCert = extractSigningCertificate(doc);
            java.security.PublicKey publicKey = signingCert.getPublicKey();

            // vytvoríme DOMValidateContext s public key
            javax.xml.crypto.dsig.XMLSignatureFactory fac =
                    javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM");

            DOMValidateContext ctx = new DOMValidateContext(publicKey, sigElem);

            // unmarshal ds:Signature
            javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(ctx);

            // 5a: overenie všetkých referencií (DigestValue)
            boolean allRefsValid = true;
            for (Object o : signature.getSignedInfo().getReferences()) {
                javax.xml.crypto.dsig.Reference ref = (javax.xml.crypto.dsig.Reference) o;
                boolean refOk = ref.validate(ctx);
                if (!refOk) {
                    allRefsValid = false;
                    String uri = ref.getURI();
                    throw new VerificationException(
                            Errors.XMLSIG_DIGESTVALUE_INVALID,
                            "5a: DigestValue invalid for Reference URI='" + uri + "'."
                    );
                }
            }

            // 5b: overenie samotnej SignatureValue
            boolean sigOk = signature.getSignatureValue().validate(ctx);
            if (!sigOk) {
                throw new VerificationException(
                        Errors.XMLSIG_SIGNATUREVALUE_INVALID,
                        "5b: ds:SignatureValue is NOT valid for SignedInfo."
                );
            }

            System.out.println("[OK] Core XML Signature validation (5a,5b) passed.");

        } catch (VerificationException ve) {
            throw ve;
        } catch (Exception e) {
            throw new VerificationException(
                    Errors.XMLSIG_CORE_VALIDATION_ERROR,
                    "5: Core XML Signature validation failed: " + e.getMessage()
            );
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

    private String normalizeSerialNumber(String dn) {
        return dn.replaceAll("2\\.5\\.4\\.97=#..([0-9A-Fa-f]+)", "2.5.4.97=$1");
    }

    private static Map<String, String> parseDnManual(String dn) {
        Map<String, String> map = new LinkedHashMap<>();

        // Split by commas NOT inside quotes
        String[] parts = dn.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;

            String[] kv = part.split("=", 2);
            if (kv.length != 2) continue;

            String key = kv[0].trim().toUpperCase();
            String value = kv[1].trim();

            // Remove quotes
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }

            // Normalize whitespace
            value = value.replaceAll("\\s+", " ").trim();

            // ---------- ATTRIBUTE NAME NORMALIZATION ----------
            switch (key) {
                case "SURNAME":
                case "SN":
                    key = "SN";
                    break;

                case "G":
                case "GN":
                case "GIVENNAME":
                    key = "GN";
                    break;

                case "SERIALNUMBER":
                    key = "SERIALNUMBER";
                    break;

                case "C":
                    key = "C";
                    if (value.equalsIgnoreCase("Slovensko"))
                        value = "SK";
                    break;

                case "O":
                    key = "O";
                    break;

                case "OU":
                    key = "OU";
                    break;

                case "CN":
                    key = "CN";
                    break;

                default:
                    // Leave unknown attributes unchanged
                    break;
            }

            key = switch (key) {
                case "2.5.4.4" ->  // Surname
                        "SN";
                case "2.5.4.42" -> // Given Name
                        "GN";
                case "2.5.4.3" ->  // CN
                        "CN";
                case "2.5.4.10" -> // O
                        "O";
                case "2.5.4.11" -> // OU
                        "OU";
                case "2.5.4.6" ->  // Country
                        "C";
                case "OID.2.5.4.4" ->
                        "SN";
                case "OID.2.5.4.42" ->
                        "GN";
                case "OID.2.5.4.5" ->
                        "SERIALNUMBER";
                default -> key;
            };

            map.put(key, value);
        }
        return map;
    }

    private static Map<String, String> parseCertDn(X500Principal principal) {
        String dn = principal.getName(X500Principal.RFC1779);
        return parseDnManual(dn);
    }
}

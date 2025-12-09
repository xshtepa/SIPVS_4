package com.example.asiceverifier;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

public class TimeStampVerifier {

    // 4a — Verify timestamp certificate and CRL
    public void verify(String base64Timestamp) {
        try {
            byte[] tsResponseBytes = Base64.getDecoder()
                    .decode(base64Timestamp.replaceAll("\\s+", ""));
            CMSSignedData cmsSignedData = new CMSSignedData(tsResponseBytes);
            TimeStampToken tsToken = new TimeStampToken(cmsSignedData);

            // Extract TSA certificate 
            Collection<X509CertificateHolder> certs =
                    tsToken.getCertificates().getMatches(tsToken.getSID());

            X509CertificateHolder holder = certs.iterator().next();

            X509Certificate tsaCert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);

            Date genTime = tsToken.getTimeStampInfo().getGenTime();

            // Check certificate validity at timestamp time and now
            tsaCert.checkValidity(genTime);
            tsaCert.checkValidity(new Date());

            // ---- CRL check ----
            String crlUrl = extractCRL_URL(tsaCert);
            if (crlUrl != null) {
                X509CRL crl = downloadCRL(crlUrl);
                if (crl.isRevoked(tsaCert)) {
                    throw new VerificationException(
                            Errors.TIMESTAMP_CERT_INVALID,
                            "4a: TSA certificate revoked according to CRL."
                    );
                }
            }

            System.out.println("[OK] Timestamp certificate valid (including CRL).");

        } catch (Exception ex) {
            throw new VerificationException(
                    Errors.TIMESTAMP_CERT_INVALID,
                    "4a: Timestamp certificate invalid: " + ex.getMessage()
            );
        }
    }

    // Extract CRL URL from certificate
    private String extractCRL_URL(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (ext == null) return null;

            byte[] octets = ASN1OctetString.getInstance(ext).getOctets();
            CRLDistPoint dist = CRLDistPoint.getInstance(octets);

            DistributionPoint[] points = dist.getDistributionPoints();
            if (points == null || points.length == 0) return null;

            return points[0].getDistributionPoint().getName().toString().replace("URI:", "");

        } catch (Exception e) {
            return null;
        }
    }

    // Download CRL from URL
    private X509CRL downloadCRL(String crlUrl) throws Exception {
        URL url = new URL(crlUrl);
        try (InputStream in = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(in);
        }
    }

    // 4b — MessageImprint vs digest(SignatureValue)
    public void verifyMessageImprint(TimeStampToken tsToken, byte[] signatureValue) {
        try {
            String algorithmOid = tsToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

            MessageDigest md;

            if (algorithmOid.contains("1.3.14.3.2.26")) {
                md = MessageDigest.getInstance("SHA-1");
            } else {
                md = MessageDigest.getInstance("SHA-256");
            }

            byte[] computedDigest = md.digest(signatureValue);
            byte[] imprintDigest = tsToken.getTimeStampInfo().getMessageImprintDigest();

            if (!java.util.Arrays.equals(computedDigest, imprintDigest)) {
                throw new VerificationException(
                        Errors.TIMESTAMP_MESSAGEIMPRINT_INVALID,
                        "4b: MessageImprint does NOT match ds:SignatureValue."
                );
            }

            System.out.println("[OK] MessageImprint matches SignatureValue.");

        } catch (Exception ex) {
            throw new VerificationException(
                    Errors.TIMESTAMP_MESSAGEIMPRINT_INVALID,
                    "4b: Cannot verify MessageImprint — " + ex.getMessage()
            );
        }
    }
}

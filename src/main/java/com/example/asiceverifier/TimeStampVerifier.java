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
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

public class TimeStampVerifier {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }


    // 4a – overenie platnosti podpisového certifikátu časovej pečiatky
    public void verifyTimestampCertificate(String base64Timestamp) {
        try {
            // 1) Decode a parse TST (TimeStampToken)
            byte[] tsBytes = Base64.getDecoder()
                    .decode(base64Timestamp.replaceAll("\\s+", ""));
            CMSSignedData cms = new CMSSignedData(tsBytes);
            TimeStampToken tsToken = new TimeStampToken(cms);

            // 2) Získaj TSA certifikát (ten, kto vydal časovú pečiatku)
            Collection<X509CertificateHolder> certs =
                    tsToken.getCertificates().getMatches(tsToken.getSID());

            if (certs.isEmpty()) {
                throw new RuntimeException("Timestamp does not contain TSA certificate.");
            }

            X509CertificateHolder holder = certs.iterator().next();

            X509Certificate tsaCert = new JcaX509CertificateConverter()
                    .getCertificate(holder);

            // 3) Čas z pečiatky (GenTime)
            Date genTime = tsToken.getTimeStampInfo().getGenTime();

            // 4) Over platnosť certifikátu voči času pečiatky a voči aktuálnemu času (UtcNow)
            tsaCert.checkValidity(genTime);      // "bol platný v čase vytvorenia pečiatky"
            tsaCert.checkValidity(new Date());   // "je platný aj teraz"

            // 5) Overenie voči CRL
            String crlUrl = extractCRL_URL(tsaCert);

            if (crlUrl == null) {
                System.out.println("[INFO] TSA certificate does not contain CRL URL → skipping CRL validation.");
            } else {
                X509CRL crl = downloadCRL(crlUrl);
                if (crl.isRevoked(tsaCert)) {
                    X509CRLEntry entry = crl.getRevokedCertificate(tsaCert);
                    if (entry.getRevocationDate().before(genTime)) {
                        throw new RuntimeException("4a: TSA certificate is revoked at timestamp time.");
                    }
                }
            }


            // System.out.println("[OK] 4a: Timestamp certificate is valid (time + CRL).");

        } catch (Exception e) {
            throw new RuntimeException("4a: Timestamp certificate invalid: " + e.getMessage(), e);
        }
    }

    // 4b – overenie MessageImprint voči ds:SignatureValue
    // public void verifyMessageImprint(TimeStampToken tsToken, byte[] signatureValue) {
    //     try {
    //         // 1) Algoritmus hashovania z časovej pečiatky (OID)
    //         String algorithmOid = tsToken.getTimeStampInfo()
    //                 .getHashAlgorithm()
    //                 .getAlgorithm()
    //                 .getId();

    //         // 2) Namapuj OID → názov algoritmu pre MessageDigest
    //         String jcaName;
    //         switch (algorithmOid) {
    //             case "1.3.14.3.2.26": // SHA-1
    //                 jcaName = "SHA-1";
    //                 break;
    //             case "2.16.840.1.101.3.4.2.1": // SHA-256
    //                 jcaName = "SHA-256";
    //                 break;
    //             case "2.16.840.1.101.3.4.2.2": // SHA-384
    //                 jcaName = "SHA-384";
    //                 break;
    //             case "2.16.840.1.101.3.4.2.3": // SHA-512
    //                 jcaName = "SHA-512";
    //                 break;
    //             default:
    //                 // для задачі достатньо SHA-1/SHA-256, але на всякий випадок:
    //                 throw new RuntimeException("Unsupported hash algorithm OID in timestamp: " + algorithmOid);
    //         }

    //         // 3) Spočítaj digest z ds:SignatureValue
    //         MessageDigest md = MessageDigest.getInstance(jcaName);
    //         byte[] computedDigest = md.digest(signatureValue);

    //         // 4) MessageImprintDigest z TST
    //         byte[] imprintDigest = tsToken.getTimeStampInfo().getMessageImprintDigest();

    //         // 5) Porovnaj
    //         if (!java.util.Arrays.equals(computedDigest, imprintDigest)) {
    //             throw new RuntimeException(
    //                     "4b: MessageImprint does NOT match digest(ds:SignatureValue)."
    //             );
    //         }

    //         // System.out.println("[OK] 4b: MessageImprint matches digest(SignatureValue).");

    //     } catch (Exception e) {
    //         throw new RuntimeException("4b: Cannot verify MessageImprint: " + e.getMessage(), e);
    //     }
    // }

    // --- helpers pre CRL z certifikátu (4a) ---

    private String extractCRL_URL(X509Certificate cert) {
        try {
            byte[] extVal = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (extVal == null) return null;

            byte[] octets = ASN1OctetString.getInstance(extVal).getOctets();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(octets);

            for (DistributionPoint dp : distPoint.getDistributionPoints()) {

                if (dp.getDistributionPoint() == null) continue;
                if (!(dp.getDistributionPoint().getName() instanceof org.bouncycastle.asn1.x509.GeneralNames gns))
                    continue;

                for (org.bouncycastle.asn1.x509.GeneralName gn : gns.getNames()) {

                    if (gn.getTagNo() == org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier) {

                        String url = gn.getName().toString().trim();

                        if (url.startsWith("URI:")) url = url.substring(4);

                        if (url.startsWith("http://") || url.startsWith("https://")) {
                            return url;
                        }
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public TimeStampToken parseTimestamp(String base64Timestamp) {
        try {
            // очистка Base64 – дуже важливо!
            String clean = base64Timestamp.replaceAll("[^A-Za-z0-9+/=]", "");

            byte[] tsBytes = Base64.getDecoder().decode(clean);
            CMSSignedData cms = new CMSSignedData(tsBytes);
            return new TimeStampToken(cms);

        } catch (Exception e) {
            throw new VerificationException(
                    Errors.TIMESTAMP_INVALID,
                    "4: Cannot parse TimeStampToken: " + e.getMessage()
            );
        }
    }


    private X509CRL downloadCRL(String crlUrl) throws Exception {
        URL url = new URL(crlUrl);
        try (InputStream in = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(in);
        }
    }
}

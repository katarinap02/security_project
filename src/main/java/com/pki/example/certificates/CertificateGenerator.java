package com.pki.example.certificates;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.model.CertificateType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class CertificateGenerator {
    public CertificateGenerator() {
        Security.addProvider(new BouncyCastleProvider());
    }
/*
    public static X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber) {
        try {
            //Posto klasa za generisanje sertifiakta ne moze da primi direktno privatni kljuc pravi se builder za objekat
            //Ovaj objekat sadrzi privatni kljuc izdavaoca sertifikata i koristiti se za potpisivanje sertifikata
            //Parametar koji se prosledjuje je algoritam koji se koristi za potpisivanje sertifiakta
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            //Takodje se navodi koji provider se koristi, u ovom slucaju Bouncy Castle
            builder = builder.setProvider("BC");

            //Formira se objekat koji ce sadrzati privatni kljuc i koji ce se koristiti za potpisivanje sertifikata
            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());

            //Postavljaju se podaci za generisanje sertifiakta
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer.getX500Name(),
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),
                    subject.getPublicKey());

            //Generise se sertifikat
            X509CertificateHolder certHolder = certGen.build(contentSigner);

            //Builder generise sertifikat kao objekat klase X509CertificateHolder
            //Nakon toga je potrebno certHolder konvertovati u sertifikat, za sta se koristi certConverter
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");

            //Konvertuje objekat u sertifikat
            return certConverter.getCertificate(certHolder);

        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }*/

    public X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, CertificateType type, List<String> keyUsageList, List<String> extendedKeyUsageList, List<String> subjectAlternativeNames) {
        try {
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder = builder.setProvider("BC");

            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());

            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    issuer.getX500Name(),
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),
                    subject.getPublicKey());

            // ********** DODAVANJE EKSTENZIJA *********

            // BasicConstraints: Govori da li je sertifikat CA (može da potpisuje druge) ili ne.
            if (type == CertificateType.ROOT || type == CertificateType.INTERMEDIATE) {
                // Ovo je CA sertifikat, može da potpisuje druge sertifikate. `true` je ključno.
                certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            } else {
                // Ovo je End-Entity sertifikat, ne može da potpisuje druge.
                certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            }

            if (keyUsageList != null && !keyUsageList.isEmpty()) {
                int keyUsageValue = buildKeyUsageValue(keyUsageList);
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageValue));
            } else {
                // Fallback: default vrednosti po tipu (ako nisu prosleđene)
                if (type == CertificateType.ROOT || type == CertificateType.INTERMEDIATE) {
                    certGen.addExtension(Extension.keyUsage, true,
                            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
                } else {
                    certGen.addExtension(Extension.keyUsage, true,
                            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
                }
            }

            // ========== 3. EXTENDED KEY USAGE (dinamički) ==========
            if (extendedKeyUsageList != null && !extendedKeyUsageList.isEmpty()) {
                KeyPurposeId[] purposes = buildExtendedKeyUsage(extendedKeyUsageList);
                certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
            }

            if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
                GeneralName[] generalNames = buildSubjectAlternativeNames(subjectAlternativeNames);
                certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames));
            }

            //  CRL Distribution Point: Gde preuzeti CRL listu
            // Ovo se dodaje SVIM sertifikatima koji imaju issuer-a (ROOT ne treba jer je self-signed)
            if (type != CertificateType.ROOT) {
                // URL gde će biti dostupna CRL lista za ovog issuer-a
                String issuerSerialNumber = issuer.getSerialNumber();
                String crlUrl = "http://localhost:8081/api/crl/" + issuerSerialNumber + ".crl";

                // Kreira GeneralName sa URL-om
                GeneralName generalName = new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        crlUrl
                );

                // Kreira DistributionPointName sa GeneralNames
                GeneralNames generalNames = new GeneralNames(generalName);
                DistributionPointName distributionPointName = new DistributionPointName(generalNames);

                // Kreira DistributionPoint
                DistributionPoint distributionPoint = new DistributionPoint(
                        distributionPointName,
                        null,  // reasons (null = svi razlozi)
                        null   // cRLIssuer (null = isti issuer kao i za sertifikat)
                );

                // Dodaje u CRLDistPoint ekstenziju
                CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { distributionPoint });

                certGen.addExtension(
                        Extension.cRLDistributionPoints,
                        false,  // non-critical (aplikacije mogu da ignorišu ako ne razumeju)
                        crlDistPoint
                );

                System.out.println("✅ Added CRL Distribution Point: " + crlUrl);
            }

            // 4. ✅ Authority Key Identifier: ID javnog ključa issuer-a (olakšava proveru lanca)
            if (type != CertificateType.ROOT) {
                JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
                AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(issuer.getPublicKey());
                certGen.addExtension(Extension.authorityKeyIdentifier, false, aki);
            }

            // 5. ✅ Subject Key Identifier: ID javnog ključa subject-a
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(subject.getPublicKey());
            certGen.addExtension(Extension.subjectKeyIdentifier, false, ski);

            X509CertificateHolder certHolder = certGen.build(contentSigner);

            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");

            return certConverter.getCertificate(certHolder);

        } catch (Exception e) {
            throw new RuntimeException("Error while generating certificate", e);
        }
    }

    private int buildKeyUsageValue(List<String> keyUsageList) {
        int value = 0;

        for (String usage : keyUsageList) {
            switch (usage.toLowerCase().trim()) {
                case "digitalsignature":
                    value |= KeyUsage.digitalSignature;
                    break;
                case "nonrepudiation":
                case "contentcommitment":
                    value |= KeyUsage.nonRepudiation;
                    break;
                case "keyencipherment":
                    value |= KeyUsage.keyEncipherment;
                    break;
                case "dataencipherment":
                    value |= KeyUsage.dataEncipherment;
                    break;
                case "keyagreement":
                    value |= KeyUsage.keyAgreement;
                    break;
                case "keycertsign":
                    value |= KeyUsage.keyCertSign;
                    break;
                case "crlsign":
                    value |= KeyUsage.cRLSign;
                    break;
                case "encipheronly":
                    value |= KeyUsage.encipherOnly;
                    break;
                case "decipheronly":
                    value |= KeyUsage.decipherOnly;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown Key Usage: " + usage);
            }
        }

        return value;
    }

    private KeyPurposeId[] buildExtendedKeyUsage(List<String> ekuList) {
        List<KeyPurposeId> purposes = new ArrayList<>();

        for (String eku : ekuList) {
            KeyPurposeId purposeId;

            switch (eku.toLowerCase().trim()) {
                case "serverauth":
                    purposeId = KeyPurposeId.id_kp_serverAuth;
                    break;
                case "clientauth":
                    purposeId = KeyPurposeId.id_kp_clientAuth;
                    break;
                case "codesigning":
                    purposeId = KeyPurposeId.id_kp_codeSigning;
                    break;
                case "emailprotection":
                    purposeId = KeyPurposeId.id_kp_emailProtection;
                    break;
                case "timestamping":
                    purposeId = KeyPurposeId.id_kp_timeStamping;
                    break;
                case "ocspsigning":
                    purposeId = KeyPurposeId.id_kp_OCSPSigning;
                    break;
                default:
                    // Pokušaj da parsiraš kao OID
                    try {
                        purposeId = KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku));
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Unknown Extended Key Usage: " + eku);
                    }
            }

            purposes.add(purposeId);
        }

        return purposes.toArray(new KeyPurposeId[0]);
    }

    private GeneralName[] buildSubjectAlternativeNames(List<String> sanList) {
        List<GeneralName> generalNames = new ArrayList<>();

        for (String san : sanList) {
            String[] parts = san.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid SAN format: " + san + ". Expected format: 'TYPE:value'");
            }

            String type = parts[0].toUpperCase().trim();
            String value = parts[1].trim();

            GeneralName generalName;

            switch (type) {
                case "DNS":
                    generalName = new GeneralName(GeneralName.dNSName, value);
                    break;
                case "IP":
                    generalName = new GeneralName(GeneralName.iPAddress, value);
                    break;
                case "EMAIL":
                    generalName = new GeneralName(GeneralName.rfc822Name, value);
                    break;
                case "URI":
                    generalName = new GeneralName(GeneralName.uniformResourceIdentifier, value);
                    break;
                case "DIRNAME":
                    generalName = new GeneralName(GeneralName.directoryName, value);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported SAN type: " + type);
            }

            generalNames.add(generalName);
        }

        return generalNames.toArray(new GeneralName[0]);
    }
}

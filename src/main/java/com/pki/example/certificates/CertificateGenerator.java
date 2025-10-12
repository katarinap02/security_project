package com.pki.example.certificates;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.model.CertificateType;
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
import java.util.Date;

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

    public X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, CertificateType type) {
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

            // ********** NOVO: DODAVANJE EKSTENZIJA *********

            // BasicConstraints: Govori da li je sertifikat CA (može da potpisuje druge) ili ne.
            if (type == CertificateType.ROOT || type == CertificateType.INTERMEDIATE) {
                // Ovo je CA sertifikat, može da potpisuje druge sertifikate. `true` je ključno.
                certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            } else {
                // Ovo je End-Entity sertifikat, ne može da potpisuje druge.
                certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            }

            // KeyUsage: Definiše za šta se ključ sme koristiti.
            if (type == CertificateType.ROOT || type == CertificateType.INTERMEDIATE) {
                // CA ključevi se koriste za potpisivanje drugih sertifikata i CRL lista.
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            } else {
                // End-Entity ključevi se tipično koriste za digitalni potpis i enkripciju.
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
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
}

package com.pki.example.service;

import com.pki.example.model.Certificate;
import com.pki.example.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.security.cert.CertificateFactory;

@Service
public class CRLService {
    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;

    @Autowired
    public CRLService(CertificateRepository certificateRepository, KeystoreService keystoreService) {
        this.certificateRepository = certificateRepository;
        this.keystoreService = keystoreService;
    }

    public void regenerateCRL(Certificate issuer) {
        try {
            // 1. Učitaj privatni ključ i sertifikat issuer-a
            String decryptedUserKey = keystoreService.decryptUserSymmetricKey(
                    issuer.getOwner().getEncryptedUserSymmetricKey()
            );
            char[] keystorePassword = keystoreService.decryptPassword(
                    issuer.getEncryptedKeystorePassword(),
                    decryptedUserKey
            );

            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(
                    issuer.getKeystoreFileName(),
                    keystorePassword,
                    issuer.getSerialNumber()
            );

            X509Certificate issuerCert = keystoreService.readCertificate(
                    issuer.getKeystoreFileName(),
                    keystorePassword,
                    issuer.getSerialNumber()
            );

            X500Name issuerX500Name = new X500Name(issuerCert.getSubjectX500Principal().getName());

            // 2. Pronađi sve povučene sertifikate koje je izdao ovaj issuer
            List<Certificate> revokedCertificates = certificateRepository.findByIssuerAndRevokedTrue(issuer);

            // 3. Napravi CRL builder
            Date now = new Date();
            Date nextUpdate = new Date(now.getTime() + (7L * 24 * 60 * 60 * 1000)); // 7 dana

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerX500Name, now);
            crlBuilder.setNextUpdate(nextUpdate);

            // 4. Dodaj sve povučene sertifikate u CRL
            for (Certificate revokedCert : revokedCertificates) {
                BigInteger serialNumber = new BigInteger(revokedCert.getSerialNumber());
                Date revocationDate = revokedCert.getRevocationDate();
                int reasonCode = revokedCert.getRevocationReason().getCode();

                crlBuilder.addCRLEntry(serialNumber, revocationDate, reasonCode);
            }

            // 5. Potpiši CRL privatnim ključem issuer-a
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC")
                    .build(issuerPrivateKey);

            X509CRLHolder crlHolder = crlBuilder.build(signer);
            X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

            // 6. Sačuvaj CRL u fajl
            String crlFileName = "crl_" + issuer.getSerialNumber() + ".crl";
            try (FileOutputStream fos = new FileOutputStream("keystores/" + crlFileName)) {
                fos.write(crl.getEncoded());
            }

            System.out.println("CRL generated successfully: " + crlFileName);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CRL", e);
        }
    }

    public byte[] getCRLBytes(String issuerSerialNumber) {
        try {
            String crlFileName = "crl_" + issuerSerialNumber + ".crl";
            Path crlPath = Paths.get("keystores/" + crlFileName);

            // Ako CRL fajl ne postoji, generiši ga
            if (!Files.exists(crlPath)) {
                System.out.println("CRL file not found, generating new one for issuer: " + issuerSerialNumber);

                Certificate issuer = certificateRepository.findBySerialNumber(issuerSerialNumber)
                        .orElseThrow(() -> new RuntimeException("Issuer certificate not found: " + issuerSerialNumber));

                regenerateCRL(issuer);
            }

            // Učitaj i vrati bajtove
            return Files.readAllBytes(crlPath);

        } catch (Exception e) {
            throw new RuntimeException("Failed to read CRL file for issuer: " + issuerSerialNumber, e);
        }
    }

    public boolean isCertificateRevokedInCRL(String certificateSerialNumber, String issuerSerialNumber) {
        try {
            String crlFileName = "crl_" + issuerSerialNumber + ".crl";
            Path crlPath = Paths.get("keystores/" + crlFileName);

            // Ako CRL ne postoji, sertifikat nije povučen
            if (!Files.exists(crlPath)) {
                System.out.println("⚠️ CRL file does not exist for issuer: " + issuerSerialNumber);
                return false;
            }

            X509CRL crl = loadCRLFromFile(crlPath);

            // Proveri da li je CRL istekao
            Date now = new Date();
            if (crl.getNextUpdate() != null && now.after(crl.getNextUpdate())) {
                System.out.println("⚠️ CRL is expired for issuer: " + issuerSerialNumber);
            }

            // Proveri da li se sertifikat nalazi u CRL listi
            BigInteger serialNumber = new BigInteger(certificateSerialNumber);
            X509CRLEntry crlEntry = crl.getRevokedCertificate(serialNumber);

            if (crlEntry != null) {
                System.out.println("❌ Certificate " + certificateSerialNumber + " is REVOKED in CRL");
                System.out.println("   Revocation date: " + crlEntry.getRevocationDate());
                if (crlEntry.getRevocationReason() != null) {
                    System.out.println("   Reason: " + crlEntry.getRevocationReason());
                }
                return true;
            }

            System.out.println("✅ Certificate " + certificateSerialNumber + " is NOT revoked in CRL");
            return false;

        } catch (Exception e) {
            System.err.println("⚠️ Error checking CRL: " + e.getMessage());
            // U slučaju greške, možete odlučiti da li da vratite true (sigurniji pristup)
            // ili false (optimističniji pristup)
            throw new RuntimeException("Failed to check CRL for certificate: " + certificateSerialNumber, e);
        }
    }

    private X509CRL loadCRLFromFile(Path crlPath) throws Exception {
        try (FileInputStream fis = new FileInputStream(crlPath.toFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            return (X509CRL) cf.generateCRL(fis);
        }
    }



}

package com.pki.example.service;

import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.UserRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final CertificateFactory certificateFactory;
    private final KeystoreService keystoreService; // Pretpostavimo da smo napravili i ovaj servis
    private final CertificateGenerator certificateGenerator;
    private final UserRepository userRepository;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository,CertificateFactory certificateFactory, KeystoreService keystoreService) {
        this.certificateRepository = certificateRepository;
        this.certificateFactory = certificateFactory;
        this.keystoreService = keystoreService;
        this.certificateGenerator = new CertificateGenerator();
        this.userRepository = userRepository;
    }

    public Certificate issueCertificate(IssuerCertificateDTO dto, User ulogovaniKorisnik) {

        if (ulogovaniKorisnik == null) {
            throw new SecurityException("Pristup odbijen. Nema informacija o ulogovanom korisniku.");
        }

        // ***************DEO GDE PRIPREMAMO ISSUERA******************//
        Issuer issuerData;
        Certificate issuerRecord = null; //izdavalac u obliku sertifikata

        CertificateType type = CertificateType.fromString(dto.getType());
        User owner = userRepository.findByEmail(dto.getOwnerEmail());

        if (type == CertificateType.ROOT) {

            //prava pristupa
            if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                throw new SecurityException("Samo administratori mogu da izdaju ROOT sertifikate.");
            }

            // Za ROOT, kreiramo novog, samopotpisanog izdavaoca
            KeyPair rootKeyPair = certificateFactory.generateKeyPair();
            Subject selfSignedSubject = certificateFactory.createSubject(dto, rootKeyPair.getPublic());
            issuerData = certificateFactory.createIssuer(rootKeyPair.getPrivate(), rootKeyPair.getPublic(), selfSignedSubject.getX500Name());
        } else {
            // Za INTERMEDIATE pronalazimo postojećeg izdavaoca u našoj bazi
            issuerRecord = validateAndGetIssuerRecord(dto.getIssuerSerialNumber());

            if (ulogovaniKorisnik.hasRole("ROLE_CA_USER")) {
                // Logika ostaje ista: proveravamo da li je on vlasnik izdavačkog sertifikata.
                if (!issuerRecord.getOwner().getId().equals(ulogovaniKorisnik.getId())) {
                    throw new SecurityException("Nemate dozvolu da koristite ovaj sertifikat kao izdavaoca.");
                }
            }
            else if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                // Ako korisnik NIJE CA_USER i NIJE ADMIN, onda nema pravo da izdaje non-root sertifikate.
                throw new SecurityException("Nemate dovoljna prava za izdavanje ovog tipa sertifikata.");
            }

            User issuerOwner = issuerRecord.getOwner();
            if (issuerOwner == null) {
                throw new InvalidIssuerException("Issuer certificate does not have a valid owner.");
            }
            String encryptedUserKey = issuerOwner.getEncryptedUserSymmetricKey();
            //pomocu naseg kljuca u recources dekriptuje za svakog korisnika njegov kljuc
            String decryptedUserKey = keystoreService.decryptUserSymmetricKey(encryptedUserKey);

            // Učitavamo privatni ključ izdavaoca iz njegovog keystore-a
            char[] issuerKeystorePassword = keystoreService.decryptPassword(
                    issuerRecord.getEncryptedKeystorePassword(), // Enkriptovana lozinka za fajl
                    decryptedUserKey                           // Ključ kojim je zaključana
            );
            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(
                    issuerRecord.getKeystoreFileName(),
                    issuerKeystorePassword,
                    issuerRecord.getSerialNumber() // Alias je serijski broj
            );

            // Učitavamo i X509 sertifikat izdavaoca da bismo dobili njegov Public Key i X500Name
            X509Certificate issuerX509Cert = keystoreService.readCertificate(issuerRecord.getKeystoreFileName(), issuerKeystorePassword, issuerRecord.getSerialNumber());
            X500Name issuerX500Name = new X500Name(issuerX509Cert.getSubjectX500Principal().getName());

            issuerData = certificateFactory.createIssuer(issuerPrivateKey, issuerX509Cert.getPublicKey(), issuerX500Name);

        }
        //************** PRIPREMA SUBJECT-A *************//
        KeyPair subjectKeyPair = certificateFactory.generateKeyPair();
        Subject subjectData = certificateFactory.createSubject(dto, subjectKeyPair.getPublic());



        // ************** GENERISANJE X.509 SERTIFIKATA i ekstenzija ***************//
        String serialNumber = String.valueOf(System.currentTimeMillis());
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subjectData,
                issuerData,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                type // Prosleđujemo tip da bi generator znao koje ekstenzije da doda
        );


        //*********** CUVANJE POMOCU KEYSTORE U FAJL**************//
        char[] newKeystorePassword = keystoreService.generateRandomPassword();
        String keystoreFileName = serialNumber + ".jks";

        if (type == CertificateType.END_ENTITY) {
            // Po specifikaciji, za EE sertifikate NE ČUVAMO privatni ključ.
            keystoreService.writeTrustedCertificate(keystoreFileName, newKeystorePassword, serialNumber, x509Cert);
        } else {
            // Za ROOT i INTERMEDIATE, čuvamo i privatni ključ da bismo mogli da potpisujemo druge.
            keystoreService.writeKeyPairAndCertificate(keystoreFileName, newKeystorePassword, serialNumber, subjectKeyPair.getPrivate(), x509Cert);
        }

        // ************* KORAK: ČUVANJE METAPODATAKA U BAZU **********//
        String decryptedOwnerKey = keystoreService.decryptUserSymmetricKey(owner.getEncryptedUserSymmetricKey());
        String encryptedPassword = keystoreService.encryptPassword(newKeystorePassword, decryptedOwnerKey);

        Certificate newCertificate = new Certificate();
        newCertificate.setSerialNumber(serialNumber);
        newCertificate.setValidFrom(dto.getValidFrom());
        newCertificate.setValidTo(dto.getValidTo());
        newCertificate.setType(type);
        newCertificate.setIssuer(issuerRecord);
        newCertificate.setOwner(owner);
        newCertificate.setRevoked(false);
        newCertificate.setKeystoreFileName(keystoreFileName);
        newCertificate.setEncryptedKeystorePassword(encryptedPassword);

        // Specijalan slučaj za ROOT: njegov issuer je on sam.
        if (type == CertificateType.ROOT) {
            newCertificate.setIssuer(newCertificate);
        }

        return certificateRepository.save(newCertificate);
    }






    private Certificate validateAndGetIssuerRecord(String issuerSerialNumber) {
        if (issuerSerialNumber == null || issuerSerialNumber.isEmpty()) {
            throw new InvalidIssuerException("Issuer serial number must be provided for non-root certificates.");
        }

        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer with serial number " + issuerSerialNumber + " not found."));

        if (issuer.isRevoked()) {
            throw new InvalidIssuerException("Issuer certificate is revoked.");
        }
        if (issuer.getValidTo().before(new Date())) {
            throw new InvalidIssuerException("Issuer certificate has expired.");
        }
        if (issuer.getType() == CertificateType.END_ENTITY) {
            throw new InvalidIssuerException("End-Entity certificates cannot be used as issuers.");
        }

        return issuer;
    }


}

package com.pki.example.service;

import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CertificateResponseDTO;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

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

    public CertificateResponseDTO issueCertificate(IssuerCertificateDTO dto, User ulogovaniKorisnik) {

        if (ulogovaniKorisnik == null) {
            throw new SecurityException("Access denied. No information about the logged-in user.");
        }

        // *** DEO GDE POSTAVLJAMO PRAVILNO OWNER ****
        User owner;
        if (dto.getOwnerEmail() == null || dto.getOwnerEmail().isBlank() || dto.getOwnerEmail().equals(ulogovaniKorisnik.getEmail())) {
            owner = ulogovaniKorisnik;
        } else {
            if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                throw new SecurityException("Only administrators can issue certificates for other users.");
            }

            // Ako jeste admin, pronalazimo korisnika po unetom emailu.
            owner = userRepository.findByEmail(dto.getOwnerEmail());
            if (owner == null) {throw new SecurityException("No user exists with this email address.");
            }

        }

        // ***************DEO GDE PRIPREMAMO ISSUERA******************//
        Issuer issuerData;
        Certificate issuerRecord = null; //izdavalac u obliku sertifikata

        CertificateType type = CertificateType.fromString(dto.getType());


        if (type == CertificateType.ROOT) {

            //prava pristupa
            if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                throw new SecurityException("Only administrators can issue ROOT certificates.");
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
                    throw new SecurityException("You do not have permission to use this certificate as an issuer.");
                }
            }
            else if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                // Ako korisnik NIJE CA_USER i NIJE ADMIN, onda nema pravo da izdaje non-root sertifikate.
                throw new SecurityException("You do not have sufficient privileges to issue this type of certificate.");

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
        String decryptedOwnerKey = keystoreService.decryptUserSymmetricKey(owner.getEncryptedUserSymmetricKey());
        String encryptedPassword = keystoreService.encryptPassword(newKeystorePassword, decryptedOwnerKey);

        if (type == CertificateType.END_ENTITY) {
            keystoreService.writeTrustedCertificate(keystoreFileName, newKeystorePassword, serialNumber, x509Cert);
        } else {
            List<X509Certificate> chainList = new ArrayList<>();
            chainList.add(x509Cert);

            if (issuerRecord != null) {
                X509Certificate[] issuerChain = buildCertificateChain(issuerRecord);
                chainList.addAll(Arrays.asList(issuerChain));
            }

            // 3. Čuvamo privatni ključ i kompletan lanac u keystore
            keystoreService.writeKeyPairAndChain(
                    keystoreFileName,
                    newKeystorePassword,
                    serialNumber,
                    subjectKeyPair.getPrivate(),
                    chainList.toArray(new X509Certificate[0])
            );
        }

        Certificate newCertificateRecord = new Certificate();
        newCertificateRecord.setSerialNumber(serialNumber);
        newCertificateRecord.setValidFrom(dto.getValidFrom());
        newCertificateRecord.setValidTo(dto.getValidTo());
        newCertificateRecord.setType(type);
        newCertificateRecord.setOwner(owner);
        newCertificateRecord.setRevoked(false);
        newCertificateRecord.setKeystoreFileName(keystoreFileName);
        newCertificateRecord.setEncryptedKeystorePassword(encryptedPassword);

        if (type == CertificateType.ROOT) {
            newCertificateRecord.setIssuer(null);
            newCertificateRecord = certificateRepository.saveAndFlush(newCertificateRecord);
            newCertificateRecord.setIssuer(newCertificateRecord); // Postavljamo samoreferencu
        } else {
            newCertificateRecord.setIssuer(issuerRecord);
        }

        Certificate savedCertificateRecord = certificateRepository.save(newCertificateRecord);

        return new CertificateResponseDTO(savedCertificateRecord);
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

    // REKONSTRUKCIJA LANCA SERTIFIKATA

    private X509Certificate[] buildCertificateChain(Certificate certificate) {
        List<X509Certificate> chain = new ArrayList<>();

        // Počinjemo od izdavaoca i pratimo lanac unazad
        Certificate current = certificate;
        while (current != null) {
            // Učitavamo X509 sertifikat za trenutnog issuer-a
            char[] password = keystoreService.decryptPassword(
                    current.getEncryptedKeystorePassword(),
                    keystoreService.decryptUserSymmetricKey(current.getOwner().getEncryptedUserSymmetricKey())
            );
            X509Certificate cert = keystoreService.readCertificate(
                    current.getKeystoreFileName(),
                    password,
                    current.getSerialNumber()
            );
            chain.add(cert);

            // Prekidamo ako smo stigli do ROOT-a
            if (current.getIssuer() != null && current.getIssuer().getId().equals(current.getId())) {
                break;
            }

            current = current.getIssuer(); // Idemo na sledećeg u lancu
        }

        return chain.toArray(new X509Certificate[0]);
    }


}

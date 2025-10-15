package com.pki.example.service;

import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.Role;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.UserRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

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

            owner = userRepository.findByEmail(dto.getOwnerEmail());
            if (owner == null) {
                throw new SecurityException("No user exists with this email address.");
            }
        }

        // ***************DEO GDE PRIPREMAMO ISSUERA******************//
        Issuer issuerData;
        Certificate issuerRecord = null;
        X509Certificate issuerX509Cert = null; // *** DODATO: Čuvamo učitani issuer sertifikat ***

        CertificateType type = CertificateType.fromString(dto.getType());
        String serialNumber = String.valueOf(System.currentTimeMillis());

        if (type == CertificateType.ROOT) {

            if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                throw new SecurityException("Only administrators can issue ROOT certificates.");
            }

            KeyPair rootKeyPair = certificateFactory.generateKeyPair();
            Subject selfSignedSubject = certificateFactory.createSubject(dto, rootKeyPair.getPublic());
            issuerData = certificateFactory.createIssuer(rootKeyPair.getPrivate(), rootKeyPair.getPublic(), selfSignedSubject.getX500Name(), serialNumber);

        } else {
            issuerRecord = validateAndGetIssuerRecord(dto.getIssuerSerialNumber());
            validateCertificateDates(dto.getValidFrom(), dto.getValidTo(), issuerRecord);

            if (ulogovaniKorisnik.hasRole("ROLE_CA_USER")) {
                if (!issuerRecord.getOwner().getId().equals(ulogovaniKorisnik.getId())) {
                    throw new SecurityException("You do not have permission to use this certificate as an issuer.");
                }
            }
            else if (!ulogovaniKorisnik.hasRole("ROLE_ADMIN")) {
                throw new SecurityException("You do not have sufficient privileges to issue this type of certificate.");
            }

            User issuerOwner = issuerRecord.getOwner();
            if (issuerOwner == null) {
                throw new InvalidIssuerException("Issuer certificate does not have a valid owner.");
            }

            String encryptedUserKey = issuerOwner.getEncryptedUserSymmetricKey();
            String decryptedUserKey = keystoreService.decryptUserSymmetricKey(encryptedUserKey);

            char[] issuerKeystorePassword = keystoreService.decryptPassword(
                    issuerRecord.getEncryptedKeystorePassword(),
                    decryptedUserKey
            );

            PrivateKey issuerPrivateKey = keystoreService.readPrivateKey(
                    issuerRecord.getKeystoreFileName(),
                    issuerKeystorePassword,
                    issuerRecord.getSerialNumber()
            );

            // *** UČITAVAMO issuer X509 sertifikat JOŠ OVDE i ČUVAMO GA ***
            issuerX509Cert = keystoreService.readCertificate(
                    issuerRecord.getKeystoreFileName(),
                    issuerKeystorePassword,
                    issuerRecord.getSerialNumber()
            );
            X500Name issuerX500Name = new X500Name(issuerX509Cert.getSubjectX500Principal().getName());

            issuerData = certificateFactory.createIssuer(
                    issuerPrivateKey,
                    issuerX509Cert.getPublicKey(),
                    issuerX500Name,
                    issuerRecord.getSerialNumber()
            );
        }

        //************** PRIPREMA SUBJECT-A *************//
        KeyPair subjectKeyPair = certificateFactory.generateKeyPair();
        Subject subjectData = certificateFactory.createSubject(dto, subjectKeyPair.getPublic());

        // ************** GENERISANJE X.509 SERTIFIKATA i ekstenzija ***************//
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subjectData,
                issuerData,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                type
        );

        //*********** CUVANJE POMOCU KEYSTORE U FAJL**************//

        char[] keystorePassword;
        String keystoreFileName;
        String encryptedPassword;

        if (type == CertificateType.ROOT) {
            // ROOT: Napravi NOVI keystore fajl
            keystorePassword = keystoreService.generateRandomPassword();
            keystoreFileName = serialNumber + ".jks";
            String decryptedOwnerKey = keystoreService.decryptUserSymmetricKey(owner.getEncryptedUserSymmetricKey());
            encryptedPassword = keystoreService.encryptPassword(keystorePassword, decryptedOwnerKey);

            keystoreService.writeKeyPairAndChain(
                    keystoreFileName,
                    keystorePassword,
                    serialNumber,
                    subjectKeyPair.getPrivate(),
                    new X509Certificate[]{x509Cert}
            );

        } else {
            // INTERMEDIATE ili END_ENTITY: Dodaj u ISSUER-ov postojeći keystore
            keystoreFileName = issuerRecord.getKeystoreFileName();

            String decryptedIssuerUserKey = keystoreService.decryptUserSymmetricKey(
                    issuerRecord.getOwner().getEncryptedUserSymmetricKey()
            );
            keystorePassword = keystoreService.decryptPassword(
                    issuerRecord.getEncryptedKeystorePassword(),
                    decryptedIssuerUserKey
            );

            String decryptedOwnerKey = keystoreService.decryptUserSymmetricKey(owner.getEncryptedUserSymmetricKey());
            encryptedPassword = keystoreService.encryptPassword(keystorePassword, decryptedOwnerKey);

            // Gradimo lanac koristeći već učitani issuerX509Cert
            List<X509Certificate> chainList = new ArrayList<>();
            chainList.add(x509Cert); // Novi sertifikat na vrhu lanca

            // Dodajemo issuer lanac (koristimo pomoćnu metodu sa već učitanim sertifikatom)
            X509Certificate[] issuerChain = buildCertificateChainFromCert(issuerRecord, issuerX509Cert);
            chainList.addAll(Arrays.asList(issuerChain));

            if (type == CertificateType.END_ENTITY) {
                keystoreService.appendTrustedCertificate(
                        keystoreFileName,
                        keystorePassword,
                        serialNumber,
                        x509Cert
                );
            } else {
                keystoreService.appendKeyPairAndChain(
                        keystoreFileName,
                        keystorePassword,
                        serialNumber,
                        subjectKeyPair.getPrivate(),
                        chainList.toArray(new X509Certificate[0])
                );
            }
        }

        // ************** ČUVANJE U BAZU **************
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
            newCertificateRecord.setIssuer(newCertificateRecord);
        } else {
            newCertificateRecord.setIssuer(issuerRecord);
        }

        Certificate savedCertificateRecord = certificateRepository.save(newCertificateRecord);

        return new CertificateResponseDTO(savedCertificateRecord);
    }


    //Prima već učitani issuer sertifikat 
    private X509Certificate[] buildCertificateChainFromCert(Certificate certificateRecord, X509Certificate x509Cert) {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(x509Cert); // Dodaj trenutni sertifikat u lanac

        // Ako nije root (self-signed), nastavi rekurzivno
        if (certificateRecord.getIssuer() != null &&
                !certificateRecord.getIssuer().getId().equals(certificateRecord.getId())) {

            Certificate parent = certificateRecord.getIssuer();

            // Učitaj parent sertifikat
            char[] password = keystoreService.decryptPassword(
                    parent.getEncryptedKeystorePassword(),
                    keystoreService.decryptUserSymmetricKey(parent.getOwner().getEncryptedUserSymmetricKey())
            );
            X509Certificate parentCert = keystoreService.readCertificate(
                    parent.getKeystoreFileName(),
                    password,
                    parent.getSerialNumber()
            );

            // Rekurzivno dodaj ostatak lanca
            X509Certificate[] parentChain = buildCertificateChainFromCert(parent, parentCert);
            chain.addAll(Arrays.asList(parentChain));
        }

        return chain.toArray(new X509Certificate[0]);
    }


    private Certificate validateAndGetIssuerRecord(String issuerSerialNumber) {
        if (issuerSerialNumber == null || issuerSerialNumber.isEmpty()) {
            throw new InvalidIssuerException("Issuer serial number must be provided for non-root certificates.");
        }

        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer with serial number " + issuerSerialNumber + " not found."));

        if (issuer.isRevoked()) {
            throw new InvalidIssuerException(
                    "Issuer certificate is revoked. Reason: " + issuer.getRevocationReason().getDescription()
            );
        }
        if (issuer.getValidTo().before(new Date())) {
            throw new InvalidIssuerException("Issuer certificate has expired.");
        }
        if (issuer.getType() == CertificateType.END_ENTITY) {
            throw new InvalidIssuerException("End-Entity certificates cannot be used as issuers.");
        }

        return issuer;
    }

    private void validateCertificateDates(Date validFrom, Date validTo, Certificate issuerRecord) {
        if (validFrom == null || validTo == null) {
            throw new IllegalArgumentException("Valid From and Valid To dates must be provided.");
        }

        if (validFrom.after(validTo)) {
            throw new IllegalArgumentException("Valid From date must be before Valid To date.");
        }
        Date today = new Date();
        if (validFrom.before(removeTime(today))) {
            throw new IllegalArgumentException("Valid From date cannot be in the past. It must be today or later.");
        }

        Date issuerValidFrom = issuerRecord.getValidFrom();
        Date issuerValidTo = issuerRecord.getValidTo();

        // Provera da li je validFrom novog sertifikata pre issuer-ovog validFrom
        if (validFrom.before(issuerValidFrom)) {
            throw new InvalidIssuerException(
                    String.format("Certificate cannot be valid before issuer's validity period. " +
                                    "Issuer valid from: %s, requested valid from: %s",
                            issuerValidFrom, validFrom)
            );
        }

        // Provera da li je validTo novog sertifikata posle issuer-ovog validTo
        if (validTo.after(issuerValidTo)) {
            throw new InvalidIssuerException(
                    String.format("Certificate cannot be valid after issuer's validity period. " +
                                    "Issuer valid to: %s, requested valid to: %s",
                            issuerValidTo, validTo)
            );
        }
    }

    private Date removeTime(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTime();
    }

}

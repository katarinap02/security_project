package com.pki.example.service;

import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.*;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.util.TokenUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final CertificateFactory certificateFactory;
    private final KeystoreService keystoreService; // Pretpostavimo da smo napravili i ovaj servis
    private final CertificateGenerator certificateGenerator;
    private final UserRepository userRepository;
    private final CertificateTemplateService certificateTemplateService;

    @Autowired
    private HttpServletRequest request;
    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository,CertificateFactory certificateFactory, KeystoreService keystoreService, CertificateTemplateService certificateTemplateService) {
        this.certificateRepository = certificateRepository;
        this.certificateFactory = certificateFactory;
        this.keystoreService = keystoreService;
        this.certificateGenerator = new CertificateGenerator();
        this.userRepository = userRepository;
        this.certificateTemplateService = certificateTemplateService;
    }

    public CertificateResponseDTO issueCertificate(IssuerCertificateDTO dto, User ulogovaniKorisnik) {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;

        String token = authHeader.substring(7);
        String email = tokenUtils.getEmailFromToken(token);
        ulogovaniKorisnik = userRepository.findByEmail(email);

        if (ulogovaniKorisnik == null) {
            throw new SecurityException("Access denied. No information about the logged-in user.");
        }
        CertificateTemplate template = null;
        if (dto.getTemplateId() != null) {
            template = certificateTemplateService.getTemplateById(dto.getTemplateId());
        }

        validateCertificateTemplate(dto);


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
            validateExtensionsAgainstIssuerPolicy(dto, issuerRecord);

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
        List<String> keyUsage = dto.getKeyUsage();
        List<String> extendedKeyUsage = dto.getExtendedKeyUsage();
        List<String> san = dto.getSubjectAlternativeNames();

        if (template != null) {
            if (keyUsage == null || keyUsage.isEmpty()) {
                keyUsage = template.getKeyUsage();
            }
            if (extendedKeyUsage == null || extendedKeyUsage.isEmpty()) {
                extendedKeyUsage = template.getExtendedKeyUsage();
            }
        }

        // ************** GENERISANJE X.509 SERTIFIKATA i ekstenzija ***************//
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subjectData,
                issuerData,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                type,
                keyUsage,
                extendedKeyUsage,
                san
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
        if (dto.getKeyUsage() != null && !dto.getKeyUsage().isEmpty()) {
            newCertificateRecord.setAllowedKeyUsages(String.join(",", dto.getKeyUsage()));
        }

        if (dto.getExtendedKeyUsage() != null && !dto.getExtendedKeyUsage().isEmpty()) {
            newCertificateRecord.setAllowedExtendedKeyUsages(String.join(",", dto.getExtendedKeyUsage()));
        }

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

    private void validateExtensionsAgainstIssuerPolicy(IssuerCertificateDTO dto, Certificate issuer) {
        // 1. Validacija Key Usage
        if (dto.getKeyUsage() != null && !dto.getKeyUsage().isEmpty()) {
            if (issuer.getAllowedKeyUsages() == null || issuer.getAllowedKeyUsages().isEmpty()) {
                throw new SecurityException(
                        "Issuer does not allow any Key Usage extensions. Cannot issue certificate with Key Usage."
                );
            }

            List<String> issuerAllowedKU = Arrays.asList(issuer.getAllowedKeyUsages().split(","));
            List<String> normalizedIssuerKU = issuerAllowedKU.stream()
                    .map(String::trim)
                    .map(String::toLowerCase)
                    .collect(Collectors.toList());

            for (String requestedKU : dto.getKeyUsage()) {
                String normalizedRequested = requestedKU.trim().toLowerCase();

                if (!normalizedIssuerKU.contains(normalizedRequested)) {
                    throw new SecurityException(
                            String.format("Key Usage '%s' is not allowed by issuer policy. Issuer allows: %s",
                                    requestedKU, issuer.getAllowedKeyUsages())
                    );
                }
            }

            System.out.println("✅ Key Usage validation passed");
        }

        // 2. Validacija Extended Key Usage
        if (dto.getExtendedKeyUsage() != null && !dto.getExtendedKeyUsage().isEmpty()) {
            if (issuer.getAllowedExtendedKeyUsages() == null || issuer.getAllowedExtendedKeyUsages().isEmpty()) {
                throw new SecurityException(
                        "Issuer does not allow any Extended Key Usage extensions. Cannot issue certificate with Extended Key Usage."
                );
            }

            List<String> issuerAllowedEKU = Arrays.asList(issuer.getAllowedExtendedKeyUsages().split(","));
            List<String> normalizedIssuerEKU = issuerAllowedEKU.stream()
                    .map(String::trim)
                    .map(String::toLowerCase)
                    .collect(Collectors.toList());

            for (String requestedEKU : dto.getExtendedKeyUsage()) {
                String normalizedRequested = requestedEKU.trim().toLowerCase();

                if (!normalizedIssuerEKU.contains(normalizedRequested)) {
                    throw new SecurityException(
                            String.format("Extended Key Usage '%s' is not allowed by issuer policy. Issuer allows: %s",
                                    requestedEKU, issuer.getAllowedExtendedKeyUsages())
                    );
                }
            }

            System.out.println("✅ Extended Key Usage validation passed");
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

    private void validateCertificateTemplate(IssuerCertificateDTO dto) {
        CertificateTemplate template = null;
        if (dto.getTemplateId() != null) {
            template = certificateTemplateService.getTemplateById(dto.getTemplateId());

            // Validacija da template pripada odabranom issueru
            if (!template.getIssuerCertificate().getSerialNumber().equals(dto.getIssuerSerialNumber())) {
                throw new IllegalArgumentException(
                        "Selected template is not associated with the chosen issuer certificate."
                );
            }

            // Validacija Common Name
            if (!certificateTemplateService.validateCommonName(dto.getCommonName(), template)) {
                throw new IllegalArgumentException(
                        "Common Name '" + dto.getCommonName() + "' does not match template pattern: " +
                                template.getCommonNameRegex()
                );
            }

            // Validacija Subject Alternative Names
            if (dto.getSubjectAlternativeNames() != null && !dto.getSubjectAlternativeNames().isEmpty()) {
                for (String san : dto.getSubjectAlternativeNames()) {
                    if (!certificateTemplateService.validateSAN(san, template)) {
                        throw new IllegalArgumentException(
                                "Subject Alternative Name '" + san + "' does not match template pattern: " +
                                        template.getSanRegex()
                        );
                    }
                }
            }

            // Validacija perioda važenja
            long requestedDays = (dto.getValidTo().getTime() - dto.getValidFrom().getTime())
                    / (1000 * 60 * 60 * 24);
            if (!certificateTemplateService.validateValidityPeriod((int) requestedDays, template)) {
                throw new IllegalArgumentException(
                        "Requested validity period (" + requestedDays + " days) exceeds template maximum of " +
                                template.getMaxValidityDays() + " days."
                );
            }

            // Primeni predefinisane ekstenzije iz šablona (ako korisnik nije već postavio)
            if (dto.getKeyUsage() == null || dto.getKeyUsage().isEmpty()) {
                dto.setKeyUsage(new ArrayList<>(template.getKeyUsage()));
            } else {
                // Korisnik je postavio svoje Key Usage - validuj da su subset ili jednaki šablonu
                validateExtensionsAgainstTemplate(dto.getKeyUsage(), template.getKeyUsage(), "Key Usage");
            }

            if (dto.getExtendedKeyUsage() == null || dto.getExtendedKeyUsage().isEmpty()) {
                dto.setExtendedKeyUsage(new ArrayList<>(template.getExtendedKeyUsage()));
            } else {
                // Korisnik je postavio svoje EKU - validuj
                validateExtensionsAgainstTemplate(dto.getExtendedKeyUsage(),
                        template.getExtendedKeyUsage(),
                        "Extended Key Usage");
            }


        }
    }

    private void validateExtensionsAgainstTemplate(List<String> requestedExtensions,
                                                   List<String> templateExtensions,
                                                   String extensionName) {
        if (templateExtensions == null || templateExtensions.isEmpty()) {
            return; // Šablon nema ograničenja za ovu ekstenziju
        }

        for (String requested : requestedExtensions) {
            if (!templateExtensions.contains(requested)) {
                throw new IllegalArgumentException(
                        extensionName + " value '" + requested + "' is not allowed by the template. " +
                                "Allowed values: " + String.join(", ", templateExtensions)
                );
            }
        }
    }




}

package com.pki.example.service;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CSRDTO;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.dto.SignCSRRequest;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.model.*;
import com.pki.example.repository.CSRRepository;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.UserRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.keycloak.KeycloakPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.persistence.EntityNotFoundException;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com. pki. example. model. Certificate;

@Service
public class CSRService {

    @Autowired
    CSRRepository csrRepository;

    @Autowired
    private KeyStoreReader keyStoreReader;

    @Autowired
    private KeyStoreWriter keyStoreWriter;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private UserService userService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeystoreService keystoreService;

    @Autowired
    private UserRepository userRepository;

    public List<CSR> getAll() {
        return csrRepository.findAll();
    }

    public CSR getCSRById(Long csrId) {
        return csrRepository.findById(csrId).orElseThrow(() -> new EntityNotFoundException("CSR sa ID " + csrId + " ne postoji"));
    }

    public CSRDTO uploadCSR(MultipartFile csrFile, User currentUser) throws Exception {
        // Parsiranje CSR-a, ekstraktovanje subject i public key
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(csrFile.getInputStream()))) {
            Object object = pemParser.readObject();
            if (!(object instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException("Nije validan CSR fajl");
            }
            csr = (PKCS10CertificationRequest) object;
        }

        X500Name x500Name = csr.getSubject();
        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
        PublicKey publicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(pkInfo);
        String subject = x500Name.toString();

        // Kreiranje CSR entiteta
        CSR csrEntity = new CSR();
        csrEntity.setSubject(subject);
        csrEntity.setCsrPem(new String(csrFile.getBytes(), StandardCharsets.UTF_8));
        csrEntity.setStatus(CSRStatus.PENDING);
        csrEntity.setCreatedAt(LocalDateTime.now());
        csrEntity.setPublicKey(publicKey.getEncoded());
        csrEntity.setUser(currentUser);

        // Čuvanje u bazi
        csrRepository.save(csrEntity);

        return new CSRDTO(csrEntity);
    }


    public List<CSR> getPendingRequestsForCa(Long caId) {
        return csrRepository.findByCaIdAndStatus(caId, CSRStatus.PENDING);
    }


    public CSRDTO approveRequest(Long csrId, int approvedValidityDays) {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR not found"));

        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new RuntimeException("CSR already processed");
        }

        csr.setStatus(CSRStatus.APPROVED);
        csr.setRequestedValidityDays(approvedValidityDays);

        try {
            java.security.cert.Certificate caCert = null;
            Certificate issuerRecord = null;

            if (!csr.getCa().isRoot()) {
                issuerRecord = certificateRepository.findBySerialNumber(csr.getCa().getSerialNumber())
                        .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));

                caCert = keyStoreReader.readCertificate(
                        csr.getCa().getKeystoreFileName(),
                        csr.getCa().getKeystorePassword(),
                        csr.getCa().getSerialNumber()
                );

                if (caCert == null || !(caCert instanceof X509Certificate)) {
                    throw new RuntimeException("CA certificate is invalid");
                }
            }

            Subject subject = new Subject();
            subject.setPublicKey(csr.getPublicKey() != null ?
                    KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(csr.getPublicKey()))
                    : null);
            subject.setX500Name(new X500Name(csr.getSubject()));

            IssuerCertificateDTO dto = new IssuerCertificateDTO();
            dto.setCommonName(csr.getSubject());
            dto.setValidFrom(new Date());
            dto.setValidTo(new Date(System.currentTimeMillis() + approvedValidityDays * 24L * 60 * 60 * 1000));
            dto.setOwnerEmail(csr.getUser().getEmail());

            CertificateType type;
            if (csr.getCa().isRoot() && csr.getType() == CSRType.CA) {
                type = CertificateType.ROOT; // samopotpisan root CA
            } else if (!csr.getCa().isRoot() && csr.getType() == CSRType.CA) {
                type = CertificateType.INTERMEDIATE; // intermediate CA
            } else {
                type = CertificateType.END_ENTITY; // krajnji korisnik
            }
            dto.setType(type.name());

            dto.setSurname("");
            dto.setGivenName("");
            dto.setOrganization("");
            dto.setOrganizationalUnit("");
            dto.setCountry("");
            dto.setEmail("");

            if (type != CertificateType.ROOT) {
                dto.setIssuerSerialNumber(csr.getCa().getSerialNumber());
            }

            // Izdaj sertifikat
            certificateService.issueCertificate(dto, csr.getUser());

        } catch (Exception e) {
            throw new RuntimeException("Greška pri generisanju sertifikata: " + e.getMessage(), e);
        }

        csrRepository.save(csr);
        return new CSRDTO(csr);
    }


    public CSR rejectRequest(Long csrId) {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR not found"));
        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new RuntimeException("CSR already processed");
        }

        csr.setStatus(CSRStatus.REJECTED);

        return csrRepository.save(csr);
    }

    public List<CSR> getUserRequests(Integer userId) {
        return csrRepository.findByUserId(userId);
    }


    public Certificate issueCertificateFromCSR(Long csrId, String issuerSerialNumber, Date validTo) throws Exception {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR not found"));

        // Validacija issuer-a
        Certificate issuerCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new RuntimeException("Issuer not found"));
        if (issuerCert.isRevoked() || issuerCert.getValidTo().before(new Date())) {
            throw new IllegalArgumentException("Izabrani issuer nije validan");
        }

        if (validTo.after(issuerCert.getValidTo()) || validTo.before(new Date())) {
            throw new IllegalArgumentException("Datum isteka mora biti unutar validnosti izabranog sertifikata");
        }

        // Kreiramo Subject iz CSR-a
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(csr.getPublicKey()));
        Subject subject = new Subject(publicKey, new org.bouncycastle.asn1.x500.X500Name(csr.getSubject()));

        // Pozivamo CertificateService da izda end-entity sertifikat
        Certificate newCert = certificateService.issueCertificateFromCSR(subject, issuerCert, csr.getUser(), validTo);

        certificateRepository.save(newCert);

        // Čuvamo CSR kao “obradjeni” (opciono)
        csr.setStatus(CSRStatus.APPROVED);
        csrRepository.save(csr);

        return newCert;
    }

    @Transactional(readOnly = true)
    public List<CSR> getCsrsByUsername(String email) {
        User user = userRepository.findByEmail(email);
        return csrRepository.findAllByUser(user);
    }

    public CertificateResponseDTO signCSR(Long csrId, Integer caId, String email, SignCSRRequest request) {
        // 1. Učitaj CSR
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR not found"));

        if (!csr.getStatus().equals(CSRStatus.PENDING)) {
            throw new RuntimeException("CSR is not in PENDING state");
        }

        // 2. Učitaj issuer (CA)
        Certificate issuerRecord = certificateRepository.findById(caId)
                .orElseThrow(() -> new RuntimeException("CA certificate not found"));

        // 3. Dohvati ulogovanog korisnika
        User loggedUser = userRepository.findByEmail(email);
        if (loggedUser == null) {
            throw new RuntimeException("Logged-in user not found");
        }

        // 4. Kreiraj X500Name iz polja sa fronta
        X500NameBuilder x500Builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (request.getCommonName() != null) x500Builder.addRDN(BCStyle.CN, request.getCommonName());
        if (request.getSurname() != null) x500Builder.addRDN(BCStyle.SN, request.getSurname());
        if (request.getGivenName() != null) x500Builder.addRDN(BCStyle.GIVENNAME, request.getGivenName());
        if (request.getOrganization() != null) x500Builder.addRDN(BCStyle.O, request.getOrganization());
        if (request.getOrganizationalUnit() != null) x500Builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        if (request.getCountry() != null) x500Builder.addRDN(BCStyle.C, request.getCountry());
        if (request.getEmail() != null) x500Builder.addRDN(BCStyle.E, request.getEmail());
        X500Name subjectX500Name = x500Builder.build();

        // 5. Parsiraj CSR iz baze i kreiraj Subject
        Subject subjectFromCSR;
        try (PEMParser pemParser = new PEMParser(new StringReader(csr.getCsrPem()))) {
            PKCS10CertificationRequest pkcs10 = (PKCS10CertificationRequest) pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PublicKey publicKey = converter.getPublicKey(pkcs10.getSubjectPublicKeyInfo());

            subjectFromCSR = new Subject();
            subjectFromCSR.setPublicKey(publicKey);
            subjectFromCSR.setX500Name(subjectX500Name);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CSR PEM: " + e.getMessage(), e);
        }

        // 6. Odredi validTo datum
        Date validTo = new Date(System.currentTimeMillis() +
                (csr.getRequestedValidityDays() != null ? csr.getRequestedValidityDays() * 24L * 60 * 60 * 1000
                        : 365L * 24 * 60 * 60 * 1000));

        // 7. Potpiši CSR
        Certificate signedCert = certificateService.issueCertificateFromCSR(
                subjectFromCSR,
                issuerRecord,
                loggedUser,
                validTo
        );

        // 8. Ažuriraj status CSR-a
        csr.setStatus(CSRStatus.APPROVED);
        csrRepository.save(csr);

        return new CertificateResponseDTO(signedCert);
    }



    public Subject parseCSR(String csrPem, X500Name x500FromForm) throws Exception {
        PEMParser pemParser = new PEMParser(new StringReader(csrPem));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PublicKey publicKey = converter.getPublicKey(csr.getSubjectPublicKeyInfo());

        Subject subject = new Subject();
        subject.setPublicKey(publicKey);
        subject.setX500Name(x500FromForm); // uzmi X500Name iz forme
        return subject;
    }
}

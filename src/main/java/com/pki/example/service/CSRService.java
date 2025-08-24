package com.pki.example.service;

import com.pki.example.data.Subject;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.model.CA;
import com.pki.example.model.CSR;
import com.pki.example.model.CSRStatus;
import com.pki.example.repository.CSRRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.persistence.EntityNotFoundException;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class CSRService {

    @Autowired
    CSRRepository csrRepository;

    @Autowired
    private KeyStoreReader keyStoreReader;

    @Autowired
    private KeyStoreWriter keyStoreWriter;



    public List<CSR> getAll(){
        return csrRepository.findAll();
    }

    public CSR getCSRById(Long csrId){
        return csrRepository.findById(csrId).orElseThrow(() -> new EntityNotFoundException("CSR sa ID " + csrId + " ne postoji"));
    }

    public CSR uploadCSR(MultipartFile csrFile, CA ca, int requestedDuration) throws Exception {
        PKCS10CertificationRequest csr;
        try(PEMParser pemParser = new PEMParser(new InputStreamReader(csrFile.getInputStream()))) {
            Object object = pemParser.readObject();
            if(!(object instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException("Nije validan CSR fajl");
            }
            csr = (PKCS10CertificationRequest) object;
        }
        X500Name x500Name = csr.getSubject();
        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
        PublicKey publicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(pkInfo);
        String subject = x500Name.toString();

        CSR csrEntity = new CSR();
        csrEntity.setSubject(subject);
        csrEntity.setCsrPem(new String(csrFile.getBytes(), StandardCharsets.UTF_8));
        csrEntity.setRequestedValidityDays(requestedDuration);
        csrEntity.setCa(ca);
        csrEntity.setStatus(CSRStatus.PENDING);
        csrEntity.setCreatedAt(LocalDateTime.now());

        if (requestedDuration > ca.getMaxCertificateDuration()) {
            throw new IllegalArgumentException("Trazeni broj dana prekoracuje maksimalno dozvoljeno trajanje sertifikata za ovu CA");
        }

        return csrRepository.save(csrEntity);
    }

    public List<CSR> getPendingRequestsForCa(Long caId) {
        return csrRepository.findByCaIdAndStatus(caId, CSRStatus.PENDING);
    }

    public CSR approveRequest(Long csrId, int approvedValidityDays){
        CSR csr = csrRepository.findById(csrId).orElseThrow(() -> new RuntimeException("CSR not found"));
        if(csr.getStatus() != CSRStatus.PENDING) {
            throw new RuntimeException("CSR already processed");
        }

        csr.setStatus(CSRStatus.APPROVED);
        // TODO: GENERISANJE SERTIFIKATA
        csr.setRequestedValidityDays(approvedValidityDays);

        return csrRepository.save(csr);
    }

    public CSR rejectRequest(Long csrId, String reason) {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new RuntimeException("CSR not found"));
        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new RuntimeException("CSR already processed");
        }

        csr.setStatus(CSRStatus.REJECTED);
        // dodaj razlog odbijanja

        return csrRepository.save(csr);
    }

    public List<CSR> getUserRequests(Integer userId) {
        return csrRepository.findByUserId(userId);
    }


}

package com.pki.example.service;

import com.pki.example.dto.RevokeCertificateDTO;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.RevocationReason;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

@Service
public class RevocationService {
    private final CertificateRepository certificateRepository;
    private final CRLService crlService;

    @Autowired
    public RevocationService(CertificateRepository certificateRepository, CRLService crlService) {
        this.certificateRepository = certificateRepository;
        this.crlService = crlService;
    }


     // Povlači sertifikat sa proverom prava pristupa
    @Transactional
    public void revokeCertificate(RevokeCertificateDTO dto, User currentUser) {
        //Pronađi sertifikat
        Certificate certificate = certificateRepository.findBySerialNumber(dto.getSerialNumber())
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found: " + dto.getSerialNumber()));

        if (certificate.isRevoked()) {
            throw new IllegalStateException("Certificate is already revoked.");
        }

        // Prava pristupa
        if (!currentUser.hasRole("ROLE_ADMIN") && !certificate.getOwner().getId().equals(currentUser.getId())) {
            throw new SecurityException("You can only revoke your own certificates.");
        }

        certificate.setRevoked(true);
        certificate.setRevocationDate(new Date());
        certificate.setRevocationReason(dto.getReason());

        certificateRepository.save(certificate);

        // Azuriranje liste
        crlService.regenerateCRL(certificate.getIssuer());

        // Rekurzivno povuci sve sertifikate izdane ovim sertifikatom
        if (certificate.getType() != CertificateType.END_ENTITY) {
            revokeChildCertificates(certificate);
        }
    }


     //Rekurzivno povlači sve sertifikate koje je izdao povučeni sertifikat
    private void revokeChildCertificates(Certificate revokedIssuer) {
        List<Certificate> childCertificates = certificateRepository.findByIssuerAndRevokedFalse(revokedIssuer);

        for (Certificate child : childCertificates) {
            if (!child.isRevoked()) {
                child.setRevoked(true);
                child.setRevocationDate(new Date());
                child.setRevocationReason(RevocationReason.CA_COMPROMISE);
                certificateRepository.save(child);

                // Rekurzivno povuci i njegove "decu"
                if (child.getType() != CertificateType.END_ENTITY) {
                    revokeChildCertificates(child);
                }
            }
        }
    }


     //Provera da li je sertifikat povučen (za validaciju pre izdavanja novog)
    public boolean isCertificateRevoked(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber)
                .map(Certificate::isRevoked)
                .orElse(false);
    }

     // Dobavi sve povučene sertifikate za određenog issuer-a (za CRL)
    public List<Certificate> getRevokedCertificatesByIssuer(Certificate issuer) {
        return certificateRepository.findByIssuerAndRevokedTrue(issuer);
    }
}

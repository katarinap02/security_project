package com.pki.example.service;

import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DownloadService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;

    @Autowired
    public DownloadService(CertificateRepository certificateRepository, KeystoreService keystoreService) {
        this.certificateRepository = certificateRepository;
        this.keystoreService = keystoreService;
    }

    public byte[] downloadCertificate(String serialNumber, User currentUser) {
        //  Pronađi sertifikat u bazi
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found: " + serialNumber));

        //  Proveri prava pristupa
        if (!canUserDownloadCertificate(certificate, currentUser)) {
            throw new SecurityException("You do not have permission to download this certificate.");
        }

        //  Dekriptuj keystore password
        String decryptedUserKey = keystoreService.decryptUserSymmetricKey(
                certificate.getOwner().getEncryptedUserSymmetricKey()
        );
        char[] keystorePassword = keystoreService.decryptPassword(
                certificate.getEncryptedKeystorePassword(),
                decryptedUserKey
        );

        // 4. Učitaj i vrati sertifikat kao byte array
        byte[] certBytes = keystoreService.exportCertificateAsBytes(
                certificate.getKeystoreFileName(),
                keystorePassword,
                certificate.getSerialNumber()
        );

        return certBytes;
    }

    private boolean canUserDownloadCertificate(Certificate cert, User user) {
        // Admin može sve
        if (user.hasRole("ROLE_ADMIN")) {
            return true;
        }

        // Vlasnik može svoj sertifikat
        if (cert.getOwner().getId().equals(user.getId())) {
            return true;
        }

        // CA_USER može sertifikate iz svog lanca
        if (user.hasRole("ROLE_CA_USER")) {
            return isInUserChain(cert, user);
        }

        return false;
    }

    private boolean isInUserChain(Certificate cert, User caUser) {
        // Ako je korisnik owner, sigurno je u njegovom lancu
        if (cert.getOwner().getId().equals(caUser.getId())) {
            return true;
        }

        // Proveri da li je bilo koji parent u njegovom vlasništvu
        Certificate current = cert;
        while (current.getIssuer() != null) {
            if (current.getIssuer().getOwner().getId().equals(caUser.getId())) {
                return true;
            }

            // Zaustavi se ako si stigao do ROOT-a (self-signed)
            if (current.getIssuer().getId().equals(current.getId())) {
                break;
            }

            current = current.getIssuer();
        }

        return false;
    }
}

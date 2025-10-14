package com.pki.example.service;

import com.pki.example.dto.CertificateViewDTO;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class CertificateViewService {

    private final CertificateRepository certificateRepository;

    @Autowired
    public CertificateViewService(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Transactional(readOnly = true)
    public List<CertificateViewDTO> getCertificatesForUser(User user) {
        List<Certificate> certificates;

        if (user.hasRole("ROLE_ADMIN")) {
            certificates = certificateRepository.findAll();
            System.out.println("👑 ADMIN access: Returning all certificates");

        } else if (user.hasRole("ROLE_CA_USER")) {
            certificates = getCertificateChainForCAUser(user);
            System.out.println("🔐 CA_USER access: Returning chain certificates for " + user.getEmail());

        } else {
            certificates = certificateRepository.findAllByOwnerAndType(user, CertificateType.END_ENTITY);
            System.out.println("👤 USER access: Returning end-entity certificates for " + user.getEmail());
        }

        // Konvertuj u DTO
        return certificates.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Pronalazi sve sertifikate u lancu za CA korisnika
     * Koristi Set sa visited ID-jevima da spreči beskonačnu rekurziju
     */
    private List<Certificate> getCertificateChainForCAUser(User caUser) {
        try {
            // 1. Pronađi sve sertifikate gde je CA_USER owner
            List<Certificate> ownedCertificates = certificateRepository.findByOwner(caUser);
            System.out.println("🔍 Found " + ownedCertificates.size() + " owned certificates");

            // 2. Za svaki sertifikat, pronađi sve child sertifikate
            Set<Integer> processedIds = new HashSet<>();
            Set<Certificate> allCertificates = new HashSet<>(ownedCertificates);

            for (Certificate cert : ownedCertificates) {
                System.out.println("🔗 Processing chain for: " + cert.getSerialNumber());
                allCertificates.addAll(findAllChildCertificates(cert, processedIds));
            }

            System.out.println("✅ Total certificates in chain: " + allCertificates.size());
            return new ArrayList<>(allCertificates);

        } catch (Exception e) {
            System.err.println("❌ Error getting certificate chain: " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    /**
     * Rekurzivno pronalazi sve child sertifikate
     * Koristi Set visited ID-jeva da spreči cikluse
     */
    private List<Certificate> findAllChildCertificates(Certificate parent, Set<Integer> processedIds) {
        // Spreči ponovnu obradu istog sertifikata (zaštita od ciklusa)
        if (parent == null || parent.getId() == null || processedIds.contains(parent.getId())) {
            return Collections.emptyList();
        }

        // Označi da je ovaj sertifikat obrađen
        processedIds.add(parent.getId());

        try {
            // Pronađi sve child sertifikate
            List<Certificate> children = certificateRepository.findByIssuer(parent);
            List<Certificate> allChildren = new ArrayList<>(children);

            System.out.println("  ↳ Found " + children.size() + " children for " + parent.getSerialNumber());

            // Rekurzivno pronađi child-ove za svako dete
            for (Certificate child : children) {
                allChildren.addAll(findAllChildCertificates(child, processedIds));
            }

            return allChildren;

        } catch (Exception e) {
            System.err.println("⚠️ Error processing children for " + parent.getSerialNumber() + ": " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Konvertuje Certificate u CertificateViewDTO
     * Sve relacije se učitavaju unutar @Transactional konteksta
     */
    private CertificateViewDTO convertToDTO(Certificate cert) {
        CertificateViewDTO dto = new CertificateViewDTO();

        try {
            // Osnovne informacije
            dto.setSerialNumber(cert.getSerialNumber());
            dto.setType(cert.getType() != null ? cert.getType().toString() : "UNKNOWN");
            dto.setValidFrom(cert.getValidFrom());
            dto.setValidTo(cert.getValidTo());
            dto.setRevoked(cert.isRevoked());

            // Revocation informacije
            if (cert.getRevocationReason() != null) {
                dto.setRevocationReason(cert.getRevocationReason().getDescription());
            }
            dto.setRevocationDate(cert.getRevocationDate());

            // Owner informacije - pristupamo u @Transactional kontekstu
            if (cert.getOwner() != null) {
                dto.setOwnerEmail(cert.getOwner().getEmail());
            } else {
                dto.setOwnerEmail("Unknown");
                System.err.println("⚠️ Certificate " + cert.getSerialNumber() + " has no owner!");
            }

            // Issuer informacije - pristupamo u @Transactional kontekstu
            if (cert.getIssuer() != null && cert.getId() != null) {
                // Proveri da li je self-signed
                if (cert.getIssuer().getId().equals(cert.getId())) {
                    dto.setIssuerSerialNumber("Self-signed");
                } else {
                    dto.setIssuerSerialNumber(cert.getIssuer().getSerialNumber());
                }
            } else {
                dto.setIssuerSerialNumber("Self-signed");
            }

            // Provera ekspirisanja
            dto.setExpired(cert.getValidTo() != null && cert.getValidTo().before(new Date()));

        } catch (Exception e) {
            System.err.println("❌ Error converting certificate " + cert.getSerialNumber() + " to DTO: " + e.getMessage());
            e.printStackTrace();
            // VratiDTO sa osnovnim podacima
            dto.setSerialNumber(cert.getSerialNumber());
            dto.setOwnerEmail("Error loading data");
            dto.setIssuerSerialNumber("Error loading data");
        }

        return dto;
    }
}
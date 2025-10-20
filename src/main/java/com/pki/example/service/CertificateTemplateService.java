package com.pki.example.service;

import com.pki.example.dto.CertificateTemplateDTO;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateTemplate;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.CertificateTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

@Service
public class CertificateTemplateService {
    private final CertificateTemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;

    @Autowired
    public CertificateTemplateService(CertificateTemplateRepository templateRepository,
                                      CertificateRepository certificateRepository) {
        this.templateRepository = templateRepository;
        this.certificateRepository = certificateRepository;
    }

    public CertificateTemplate createTemplate(CertificateTemplateDTO dto, User currentUser) {
        // 1. Pronađi issuer sertifikat
        Certificate issuer = certificateRepository.findBySerialNumber(dto.getIssuerSerialNumber())
                .orElseThrow(() -> new ResourceNotFoundException("Issuer certificate not found"));

        // 2. Proveri da li je korisnik owner issuer sertifikata
        if (!issuer.getOwner().getId().equals(currentUser.getId())) {
            throw new SecurityException("You can only create templates for certificates you own.");
        }

        // 3. Validacija regex izraza
        validateRegex(dto.getCommonNameRegex(), "Common Name regex");
        validateRegex(dto.getSanRegex(), "SAN regex");

        // 4. Kreiraj template
        CertificateTemplate template = new CertificateTemplate();
        template.setName(dto.getName());
        template.setIssuerCertificate(issuer);
        template.setOwner(currentUser);
        template.setDescription(dto.getDescription());
        template.setCommonNameRegex(dto.getCommonNameRegex());
        template.setSanRegex(dto.getSanRegex());
        template.setMaxValidityDays(dto.getMaxValidityDays());
        template.setKeyUsage(dto.getKeyUsage());
        template.setExtendedKeyUsage(dto.getExtendedKeyUsage());

        CertificateTemplate saved = templateRepository.save(template);

        return saved;
    }

    public List<CertificateTemplateDTO> getTemplatesForUser(User user) {
        List<CertificateTemplate> templates;

        if (user.hasRole("ROLE_ADMIN")) {
            templates = templateRepository.findAll();
        } else {
            templates = templateRepository.findByOwner(user);
        }

        return templates.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    private CertificateTemplateDTO convertToDTO(CertificateTemplate template) {
        CertificateTemplateDTO dto = new CertificateTemplateDTO();
        dto.setId(template.getId());
        dto.setName(template.getName());
        dto.setIssuerSerialNumber(template.getIssuerCertificate().getSerialNumber());
        dto.setDescription(template.getDescription());
        dto.setCommonNameRegex(template.getCommonNameRegex());
        dto.setSanRegex(template.getSanRegex());
        dto.setMaxValidityDays(template.getMaxValidityDays());
        dto.setKeyUsage(template.getKeyUsage());
        dto.setExtendedKeyUsage(template.getExtendedKeyUsage());
        return dto;
    }

    private void validateRegex(String regex, String fieldName) {
        if (regex != null && !regex.isEmpty()) {
            try {
                Pattern.compile(regex);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(fieldName + " contains invalid regex: " + e.getMessage());
            }
        }
    }

    public boolean validateCommonName(String commonName, CertificateTemplate template) {
        if (template.getCommonNameRegex() == null) {
            return true;
        }
        return Pattern.matches(template.getCommonNameRegex(), commonName);
    }

    public boolean validateSAN(String san, CertificateTemplate template) {
        if (template.getSanRegex() == null) {
            return true;
        }
        return Pattern.matches(template.getSanRegex(), san);
    }

    public boolean validateValidityPeriod(int requestedDays, CertificateTemplate template) {
        return requestedDays <= template.getMaxValidityDays();
    }
    public CertificateTemplate getTemplateById(Integer id) {
        return templateRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Template not found"));
    }

    public List<CertificateTemplate> getTemplateByIssuer(String issuerSerialNumber) {
        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Issuer certificate not found with serial number " + issuerSerialNumber));

        return templateRepository.findByIssuerCertificate(issuer);
    }



}

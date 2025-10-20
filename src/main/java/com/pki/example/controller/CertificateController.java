package com.pki.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pki.example.dto.*;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateTemplate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.User;
import com.pki.example.repository.CertificateRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/certificates", produces = MediaType.APPLICATION_JSON_VALUE)

public class CertificateController {
    private final CertificateService certificateService;
    private final UserService userService;
    private final RevocationService revocationService;
    private final CertificateViewService certificateViewService;
    private final DownloadService downloadService;
    private final CertificateTemplateService certificateTemplateService;
    private final CertificateRepository certificateRepository;


    @Autowired
    public CertificateController(CertificateService certificateService, UserService userService, RevocationService revocationService, CertificateViewService certificateViewService, DownloadService downloadService, CertificateTemplateService certificateTemplateService, CertificateRepository certificateRepository) {
        this.certificateService = certificateService;
        this.userService = userService;
        this.revocationService = revocationService;
        this.certificateViewService = certificateViewService;
        this.downloadService = downloadService;
        this.certificateTemplateService = certificateTemplateService;
        this.certificateRepository = certificateRepository;
    }

    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_CA_USER')")
    public ResponseEntity<?> issueCertificate(
            @RequestBody IssuerCertificateDTO dto,
            Authentication authentication) {
        try {
            // Uzmi email iz JWT tokena
            String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");

            User ulogovaniKorisnik = userService.loadUserByUsername(email);
            if (ulogovaniKorisnik == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not authenticated"));
            }

            CertificateResponseDTO noviSertifikatDTO = certificateService.issueCertificate(dto, ulogovaniKorisnik);

            return new ResponseEntity<>(noviSertifikatDTO, HttpStatus.CREATED);

        } catch (ResourceNotFoundException | InvalidIssuerException |
                 IllegalArgumentException | SecurityException e) {

            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(Map.of("error", "An unexpected error occurred on the server."),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/revoke")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER','ROLE_CA_USER')")
    public ResponseEntity<?> revokeCertificate(
            @RequestBody RevokeCertificateDTO dto,
            Authentication authentication) {
        try {
            String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");

            User currentUser = userService.loadUserByUsername(email);
            if (currentUser == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not authenticated"));
            }

            revocationService.revokeCertificate(dto, currentUser);

            return ResponseEntity.ok(Map.of(
                    "message", "Certificate revoked successfully",
                    "serialNumber", dto.getSerialNumber(),
                    "reason", dto.getReason().getDescription(),
                    "revokedBy", email
            ));

        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error: " + e.getMessage()));
        }
    }


    @GetMapping("/{serialNumber}/status")
    public ResponseEntity<?> checkCertificateStatus(@PathVariable String serialNumber) {
        boolean isRevoked = revocationService.isCertificateRevoked(serialNumber);

        return ResponseEntity.ok(Map.of(
                "serialNumber", serialNumber,
                "revoked", isRevoked
        ));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER','ROLE_CA_USER')")
    public ResponseEntity<List<CertificateViewDTO>> getCertificatesForCurrentUser(Authentication authentication) {
        String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        User user = userService.loadUserByUsername(email);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        List<CertificateViewDTO> certificates = certificateViewService.getCertificatesForUser(user);
        return ResponseEntity.ok(certificates);
    }

    @GetMapping("/download/{serialNumber}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER','ROLE_CA_USER')")
    public ResponseEntity<byte[]> downloadCertificate(
            @PathVariable String serialNumber,
            Authentication authentication) {

        // Uzimanje korisnika iz tokena
        String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        User user = userService.loadUserByUsername(email);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Poziv servisa
        byte[] certificateData = downloadService.downloadCertificate(serialNumber, user);

        if (certificateData == null || certificateData.length == 0) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        // Vraćanje fajla kao .cer
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + ".cer\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(certificateData);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> createTemplate(@RequestBody CertificateTemplateDTO dto,
                                            Authentication authentication) {
        try {

            String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
            User user = userService.loadUserByUsername(email);

            CertificateTemplate template = certificateTemplateService.createTemplate(dto, user);

            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "Template created successfully",
                    "templateId", template.getId(),
                    "templateName", template.getName()
            ));

        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Failed to create template: " + e.getMessage()));
        }
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> getAllTemplates(Authentication authentication) {
        try {
            String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
            User user = userService.loadUserByUsername(email);
            List<CertificateTemplateDTO> templates = certificateTemplateService.getTemplatesForUser(user);

            return ResponseEntity.ok(templates);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Failed to retrieve templates: " + e.getMessage()));
        }
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> getTemplateById(@PathVariable Integer id) {
        try {
            CertificateTemplate template = certificateTemplateService.getTemplateById(id);
            return ResponseEntity.ok(template);

        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("error", "Template not found"));
        }
    }

    @GetMapping("/by-issuer/{issuerSerialNumber}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> getTemplatesByIssuer(@PathVariable String issuerSerialNumber) {
        try {
            List<CertificateTemplate> templates = certificateTemplateService.getTemplateByIssuer(issuerSerialNumber);
            return ResponseEntity.ok(templates);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to retrieve templates for issuer: " + e.getMessage()));
        }
    }



    @PostMapping("/upload")
    public ResponseEntity<String> uploadCertificate(@RequestParam("file") MultipartFile file) {
        try {
            // 1️⃣ Učitaj sertifikat iz fajla
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(file.getInputStream());

            // 2️⃣ Kreiraj entitet
            Certificate entity = new Certificate();
            entity.setEncryptedKeystorePassword(null);
            entity.setRevoked(false);
            entity.setKeystoreFileName(file.getOriginalFilename());
            entity.setRevocationReason(null);
            entity.setSerialNumber(certificate.getSerialNumber().toString());
            entity.setType(CertificateType.INTERMEDIATE);
            entity.setValidFrom(certificate.getNotBefore());
            entity.setValidTo(certificate.getNotAfter());
            entity.setIssuer(null);
            entity.setOwner(null);
            entity.setRevocationDate(null);

            // Extended i key usages (može biti null)
            try {
                List<String> extUsages = certificate.getExtendedKeyUsage();
                if (extUsages != null) {
                    entity.setAllowedExtendedKeyUsages(String.join(",", extUsages));
                }
            } catch (CertificateParsingException ignored) {}

            boolean[] keyUsages = certificate.getKeyUsage();
            if (keyUsages != null) {
                entity.setAllowedKeyUsages(Arrays.toString(keyUsages));
            }

            // 3️⃣ Sačuvaj u bazu
            certificateRepository.save(entity);

            return ResponseEntity.ok("Sertifikat uspešno ubačen u bazu.");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Greška pri učitavanju sertifikata: " + e.getMessage());
        }
    }



}


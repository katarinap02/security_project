package com.pki.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.CertificateViewDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.dto.RevokeCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.User;
import com.pki.example.service.CertificateService;
import com.pki.example.service.CertificateViewService;
import com.pki.example.service.RevocationService;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/certificates", produces = MediaType.APPLICATION_JSON_VALUE)

public class CertificateController {
    private final CertificateService certificateService;
    private final UserService userService;
    private final RevocationService revocationService;
    private final CertificateViewService certificateViewService;

    @Autowired
    public CertificateController(CertificateService certificateService, UserService userService, RevocationService revocationService, CertificateViewService certificateViewService) {
        this.certificateService = certificateService;
        this.userService = userService;
        this.revocationService = revocationService;
        this.certificateViewService = certificateViewService;

    }

    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> issueCertificate(@RequestBody Map<String, Object> body)  {
        try {
            IssuerCertificateDTO dto = new ObjectMapper()
                    .convertValue(body.get("dto"), IssuerCertificateDTO.class);

            String email = (String) body.get("email");

            User ulogovaniKorisnik = userService.loadUserByUsername(email);

            CertificateResponseDTO noviSertifikatDTO = certificateService.issueCertificate(dto, ulogovaniKorisnik);

            return new ResponseEntity<>(noviSertifikatDTO, HttpStatus.CREATED);

        } catch (ResourceNotFoundException | InvalidIssuerException | IllegalArgumentException | SecurityException e) {

            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);

        } catch (Exception e) {

            return new ResponseEntity<>("An unexpected error occurred on the server.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/revoke")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> revokeCertificate(@RequestBody Map<String, Object> body) {
        try {
            // Izvuci DTO iz body-ja
            RevokeCertificateDTO dto = new ObjectMapper()
                    .convertValue(body.get("dto"), RevokeCertificateDTO.class);

            // Izvuci email iz body-ja
            String email = (String) body.get("email");

            if (email == null || email.isBlank()) {
                return ResponseEntity.status(400).body(Map.of("error", "Email is required"));
            }

            // Pronađi korisnika
            User currentUser = userService.loadUserByUsername(email);

            if (currentUser == null) {
                return ResponseEntity.status(401).body(Map.of("error", "User not authenticated"));
            }

            // Povuci sertifikat
            revocationService.revokeCertificate(dto, currentUser);

            return ResponseEntity.ok(Map.of(
                    "message", "Certificate revoked successfully",
                    "serialNumber", dto.getSerialNumber(),
                    "reason", dto.getReason().getDescription(),
                    "revokedBy", email
            ));

        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error: " + e.getMessage()));
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




}


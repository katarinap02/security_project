package com.pki.example.controller;

import com.pki.example.dto.CSRDTO;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.model.CA;
import com.pki.example.model.CSR;
import com.pki.example.model.Certificate;
import com.pki.example.model.User;
import com.pki.example.repository.CARepository;
import com.pki.example.repository.CSRRepository;
import com.pki.example.service.CSRService;
import com.pki.example.service.KeystoreService;
import com.pki.example.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/csr")
public class CSRController {
    @Autowired
    private CSRService csrService;
    @Autowired
    private CARepository caRepository;
    private static final Logger logger = LoggerFactory.getLogger(CSRController.class);

    @Autowired
    private UserService userService;

    @Value("${app.keystore.encryption-key}")
    private String globalKey;

    @GetMapping()
    public ResponseEntity<List<CSR>> getAllCSRs() {
        return ResponseEntity.ok(csrService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<CSR> getCSR(@PathVariable Long id) {
        return ResponseEntity.ok(csrService.getCSRById(id));
    }

    @PostMapping("/upload")
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")
    public ResponseEntity<CSRDTO> uploadCSR(@RequestParam("file") MultipartFile csrFile,
                                            Authentication authentication) {
        try {
            // Uzmi email iz JWT tokena
            String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");

            // Učitaj korisnika
            User user = userService.loadUserByUsername(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Poziv servisa
            CSRDTO csr = csrService.uploadCSR(csrFile, user);

            return ResponseEntity.ok(csr);

        } catch (Exception e) {
            logger.error("Greška prilikom upload-a CSR fajla", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    // CA pregleda sve PENDING CSR-ove
    @GetMapping("/ca/{caId}/pending")
    public List<CSR> getPendingForCa(@PathVariable Long caId) {
        return csrService.getPendingRequestsForCa(caId);
    }

    // korisnik vidi svoje CSR-ove
    @GetMapping("/user/{userId}")
    public List<CSR> getUserRequests(@PathVariable Integer userId) {
        return csrService.getUserRequests(userId);
    }

    // CSRController.java (nastavak)

    @PostMapping("/generate")
    public ResponseEntity<CertificateResponseDTO> generateCertificateFromCSR(
            @RequestParam("csrId") Long csrId,
            @RequestParam("issuerSerial") String issuerSerial,
            @RequestParam("validTo") long validToTimestamp
    ) {
        try {
            Date validTo = new Date(validToTimestamp);

            // Pozivamo servis da izda sertifikat
            Certificate newCert = csrService.issueCertificateFromCSR(csrId, issuerSerial, validTo);

            // Formiramo DTO za frontend
            CertificateResponseDTO response = new CertificateResponseDTO(newCert);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(null);
        }
    }

}

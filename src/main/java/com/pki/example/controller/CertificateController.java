package com.pki.example.controller;

import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.User;
import com.pki.example.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/certificates", produces = MediaType.APPLICATION_JSON_VALUE)

public class CertificateController {
    private final CertificateService certificateService;

    @Autowired
    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    // ISPRAVKA #1: Promenjen povratni tip u ResponseEntity<CertificateResponseDTO>
    public ResponseEntity<?> issueCertificate(
            @RequestBody IssuerCertificateDTO dto,
            @AuthenticationPrincipal User ulogovaniKorisnik) {
        try {
            CertificateResponseDTO noviSertifikatDTO = certificateService.issueCertificate(dto, ulogovaniKorisnik);

            return new ResponseEntity<>(noviSertifikatDTO, HttpStatus.CREATED);

        } catch (ResourceNotFoundException | InvalidIssuerException | IllegalArgumentException | SecurityException e) {

            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);

        } catch (Exception e) {

            return new ResponseEntity<>("An unexpected error occurred on the server.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}


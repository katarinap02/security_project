package com.pki.example.controller;

import com.pki.example.dto.IssuerCertificateDTO;
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
    public ResponseEntity<Certificate> issueCertificate(@RequestBody IssuerCertificateDTO dto, @AuthenticationPrincipal User ulogovaniKorisnik) {
        try {
            Certificate noviSertifikat = certificateService.issueCertificate(dto, ulogovaniKorisnik);
            return new ResponseEntity<>(noviSertifikat, HttpStatus.CREATED);

        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }
}

package com.pki.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pki.example.dto.CertificateResponseDTO;
import com.pki.example.dto.IssuerCertificateDTO;
import com.pki.example.exception.InvalidIssuerException;
import com.pki.example.exception.ResourceNotFoundException;
import com.pki.example.model.Certificate;
import com.pki.example.model.User;
import com.pki.example.service.CertificateService;
import com.pki.example.service.UserService;
import io.jsonwebtoken.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/certificates", produces = MediaType.APPLICATION_JSON_VALUE)

public class CertificateController {
    private final CertificateService certificateService;
    private final UserService userService;

    @Autowired
    public CertificateController(CertificateService certificateService, UserService userService) {
        this.certificateService = certificateService;
        this.userService = userService;
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
}


package com.pki.example.controller;

import com.pki.example.dto.PasswordRequestDTO;
import com.pki.example.model.PasswordEntry;
import com.pki.example.service.PasswordEntryService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api/passwords")
public class PasswordEntryController {

    private final PasswordEntryService service;

    public PasswordEntryController(PasswordEntryService service) {
        this.service = service;
    }

    @PostMapping
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<PasswordEntry> addPassword(
            @RequestBody PasswordRequestDTO request,
            Authentication authentication) {

        String ownerEmail;
        if (authentication.getPrincipal() instanceof Jwt) {
            ownerEmail = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        } else {
            ownerEmail = authentication.getName();
        }

        PasswordEntry saved = service.saveEncryptedPassword(
                ownerEmail,
                request.getSiteName(),
                request.getUsername(),
                request.getEncryptedPassword(),
                request.getEncryptedAesKey(),
                request.getIv()
        );
        return ResponseEntity.ok(saved);
    }


    @GetMapping
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<List<PasswordEntry>> getUserPasswords(Authentication authentication) {
        String ownerEmail;
        if (authentication.getPrincipal() instanceof Jwt) {
            ownerEmail = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        } else {
            ownerEmail = authentication.getName();
        }

        List<PasswordEntry> entries = service.getAllByOwner(ownerEmail);
        return ResponseEntity.ok(entries);
    }


    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<Void> deletePassword(@PathVariable Long id, Authentication authentication) {
        String ownerEmail;
        if (authentication.getPrincipal() instanceof Jwt) {
            ownerEmail = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        } else {
            ownerEmail = authentication.getName();
        }

        // Opcionalno možeš proveriti da li taj korisnik zaista ima pravo da obriše ovu lozinku
        service.deleteById(id);

        return ResponseEntity.noContent().build();
    }

}

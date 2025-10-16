package com.pki.example.controller;

import com.pki.example.dto.PasswordRequestDTO;
import com.pki.example.model.PasswordEntry;
import com.pki.example.service.KeystoreService;
import com.pki.example.service.PasswordEntryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value="/api/passwords", produces = MediaType.APPLICATION_JSON_VALUE)
public class PasswordEntryController {

    private final PasswordEntryService service;
    private final KeystoreService keystoreService;

    public PasswordEntryController(PasswordEntryService service, KeystoreService keystoreService) {
        this.service = service;
        this.keystoreService = keystoreService;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")

    public ResponseEntity<PasswordEntry> addPassword(@RequestBody PasswordEntry entry) {
        PasswordEntry saved = service.save(entry);
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/{email}")
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")

    public ResponseEntity<List<PasswordEntry>> getPasswords(@PathVariable String email) {
        List<PasswordEntry> entries = service.getByOwnerEmail(email);
        return ResponseEntity.ok(entries);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")

    public ResponseEntity<Void> deletePassword(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/secure")
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")

    public ResponseEntity<PasswordEntry> addSecurePassword(@RequestBody PasswordRequestDTO request) throws Exception {
        PasswordEntry saved = service.savePassword(
                request.getOwnerEmail(),
                request.getSiteName(),
                request.getUsername(),
                request.getPassword(),
                request.getPublicKeyPem()
        );
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/register-public-key")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER', 'ROLE_CA_USER')")
    public ResponseEntity<String> registerPublicKey(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String publicKeyPem = request.get("publicKeyPem");

            keystoreService.registerUserPublicKey(email, publicKeyPem);

            return ResponseEntity.ok("Public key registered and symmetric key encrypted for user.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }
}

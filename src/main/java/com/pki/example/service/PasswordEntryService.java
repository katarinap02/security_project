package com.pki.example.service;

import com.pki.example.model.PasswordEntry;
import com.pki.example.repository.PasswordEntryRepository;
import com.pki.example.util.EncryptionUtil;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PasswordEntryService {

    private final PasswordEntryRepository repository;

    public PasswordEntryService(PasswordEntryRepository repository) {
        this.repository = repository;
    }

    public PasswordEntry save(PasswordEntry entry) {
        return repository.save(entry);
    }

    public List<PasswordEntry> getByOwnerEmail(String ownerEmail) {
        return repository.findByOwnerEmail(ownerEmail);
    }

    public Optional<PasswordEntry> getById(Long id) {
        return repository.findById(id);
    }

    public void delete(Long id) {
        repository.deleteById(id);
    }

    public PasswordEntry savePassword(String ownerEmail, String siteName, String username, String password, String publicKeyPem) throws Exception {
        PasswordEntry entry = new PasswordEntry();
        entry.setOwnerEmail(ownerEmail);
        entry.setSiteName(siteName);
        entry.setUsername(username);

        String encrypted = EncryptionUtil.encryptPassword(password, publicKeyPem);
        entry.setEncryptedPassword(encrypted);

        return repository.save(entry);
    }

}

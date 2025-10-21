package com.pki.example.service;

import com.pki.example.model.PasswordEntry;
import com.pki.example.repository.PasswordEntryRepository;
import com.pki.example.util.EncryptionUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class PasswordEntryService {

    private final PasswordEntryRepository repository;

    public PasswordEntryService(PasswordEntryRepository repository) {
        this.repository = repository;
    }

    public PasswordEntry saveEncryptedPassword(String ownerEmail,
                                               String siteName,
                                               String username,
                                               String encryptedPassword,
                                               String encryptedAesKey,
                                               String iv) {

        PasswordEntry entry = new PasswordEntry();
        entry.setOwnerEmail(ownerEmail);
        entry.setSiteName(siteName);
        entry.setUsername(username);
        entry.setEncryptedPassword(encryptedPassword); // AES šifrovana lozinka
        entry.setEncryptedAesKey(encryptedAesKey);     // RSA šifrovani AES ključ
        entry.setIv(iv);

        return repository.save(entry);
    }

    @Transactional
    public List<PasswordEntry> getAllByOwner(String ownerEmail) {
        return repository.findByOwnerEmail(ownerEmail);
    }

    public void deleteById(Long id) {
        repository.deleteById(id);
    }

    public Optional<PasswordEntry> getById(Long id) {
        return repository.findById(id);
    }

    public String decryptPassword(PasswordEntry entry, PrivateKey privateKey) throws Exception {
        // 1. Dešifruj AES ključ RSA privatnim ključem
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(entry.getEncryptedAesKey()));

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 2. Dešifruj lozinku AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = Base64.getDecoder().decode(entry.getIv());
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        byte[] decrypted = aesCipher.doFinal(Base64.getDecoder().decode(entry.getEncryptedPassword()));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

}

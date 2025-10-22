package com.pki.example.service;

import com.pki.example.dto.PasswordShareRequestDTO;
import com.pki.example.model.PasswordEntry;
import com.pki.example.model.PasswordShare;
import com.pki.example.repository.PasswordEntryRepository;
import com.pki.example.repository.PasswordShareRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class PasswordShareService {

    private final PasswordShareRepository shareRepo;
    private final PasswordEntryRepository entryRepo;

    public PasswordShareService(PasswordShareRepository shareRepo, PasswordEntryRepository entryRepo) {
        this.shareRepo = shareRepo;
        this.entryRepo = entryRepo;
    }

    public PasswordShare sharePassword(PasswordShareRequestDTO dto, String currentUserEmail) {
        PasswordEntry entry = entryRepo.findById(dto.getPasswordEntryId())
                .orElseThrow(() -> new RuntimeException("Password entry not found"));

        if (!entry.getOwnerEmail().equals(currentUserEmail)) {
            throw new RuntimeException("Only owner can share this password");
        }

        PasswordShare share = new PasswordShare();
        share.setPasswordEntry(entry);
        share.setUserId(dto.getTargetUserId());
        share.setEncryptedAesKey(dto.getEncryptedAesKey());
        share.setCreatedBy(currentUserEmail);
        share.setIv(dto.getIv());

        return shareRepo.save(share);
    }

    @Transactional(readOnly = true)
    public List<PasswordShare> getSharesForUser(Long userId) {
        return shareRepo.findByUserId(userId);
    }
}


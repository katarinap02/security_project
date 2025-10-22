package com.pki.example.repository;

import com.pki.example.model.PasswordShare;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PasswordShareRepository extends JpaRepository<PasswordShare, Long> {
    List<PasswordShare> findByUserId(Long userId);
    List<PasswordShare> findByPasswordEntryId(Long passwordEntryId);
}


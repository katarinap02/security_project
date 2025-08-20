package com.pki.example.service;

import com.pki.example.model.PasswordResetToken;
import com.pki.example.model.User;
import com.pki.example.repository.PasswordResetTokenRepository;
import com.pki.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
public class PasswordResetTokenService {

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetTokenService.class);


    public void saveToken(User user, String token) {
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        tokenRepository.save(resetToken);
        logger.info("Password reset token created for user {} with token {}", user.getEmail(), token);
    }

    public User validateToken(String token) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElse(null);

        if (resetToken == null || resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            logger.warn("Attempt to validate expired password reset token for user {}: {}", resetToken.getUser().getEmail(), token);
            return null;
        }

        logger.info("Password reset token validated successfully for user {}", resetToken.getUser().getEmail());
        return resetToken.getUser();
    }

    @Transactional
    public void invalidateToken(String token) {
        tokenRepository.deleteByToken(token);
    }
}

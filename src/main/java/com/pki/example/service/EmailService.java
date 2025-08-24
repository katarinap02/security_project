package com.pki.example.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);


    public void sendActivationEmail(String email, String token) {
        String activationLink = "http://localhost:8080/api/users/activate/" + token;

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Aktivacija naloga");
            message.setText("Da biste aktivirali svoj nalog, molimo vas da kliknete na sledeći link: " + activationLink);

            mailSender.send(message);
            logger.info("Activation email sent successfully to {}", email);
        } catch (Exception e) {
            logger.error("Failed to send activation email to {}: {}", email, e.getMessage(), e);
        }
    }

    public void sendPasswordResetEmail(String email, String token) {
        String resetLink = "http://localhost:4200/reset-password?token=" + token;

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Password Reset Request");
            message.setText("Click the link below to reset your password:\n" + resetLink);

            mailSender.send(message);
            logger.info("Password reset email sent successfully to {}", email);
        } catch (Exception e) {
            logger.error("Failed to send password reset email to {}: {}", email, e.getMessage(), e);
        }
    }


}

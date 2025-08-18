package com.pki.example.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendActivationEmail(String email, String token) {
        String activationLink = "http://localhost:8080/api/users/activate/" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Aktivacija naloga");
        message.setText("Da biste aktivirali svoj nalog, molimo vas da kliknete na sledeći link: " + activationLink);
        mailSender.send(message);
        System.out.println("Email sent USPESNOOOOOO");
    }
}

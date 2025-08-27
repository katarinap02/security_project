package com.pki.example.controller;

import com.pki.example.config.KeycloakSecurityConfig;
import com.pki.example.dto.LoginRequest;
import com.pki.example.dto.TokenInfoDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.model.User;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.EmailService;
import com.pki.example.service.PasswordResetTokenService;
import com.pki.example.service.RecaptchaService;
import com.pki.example.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.List;
import java.util.Map;


@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/users", produces = MediaType.APPLICATION_JSON_VALUE)

public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private RecaptchaService recaptchaService;

    @Autowired
    private PasswordResetTokenService passwordResetTokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private KeycloakSecurityConfig securityConfig;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserDTO userDto) {
        return userService.register(userDto);
    }

//    @PostMapping("/login")
//    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
//        return userService.login(request.getEmail(), request.getPassword());
//    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Prosleđuje email, password i recaptcha token servisu
        return userService.login(
                loginRequest.getEmail(),
                loginRequest.getPassword(),
                loginRequest.getRecaptchaToken(),
                loginRequest.getTwoFactorCode()
        );
    }



    @GetMapping("/activate/{token}")
    public ResponseEntity<?> activateUser(@PathVariable String token) {
        return userService.activateUser(token);
    }


    @GetMapping("/role/{id}")
    public Integer getRole(@PathVariable Integer id){
        Integer role = userService.getRole(id);
        return role;
    }

    @GetMapping("/sessions")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER','ROLE_CA_USER')")
    public ResponseEntity<List<TokenInfoDTO>> getActiveSessions(Authentication authentication) {
        String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        return ResponseEntity.ok(userService.getActiveTokensForUser(email));
    }


    @PostMapping("/sessions/revoke")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_END_USER', 'ROLE_CA_USER')")
    public ResponseEntity<?> revokeToken(@RequestParam String jti, @RequestParam String sub) {
        boolean revoked = userService.revokeToken(jti, sub);
        if (revoked) {
            return ResponseEntity.ok(Map.of("message", "Token revoked successfully"));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid token or insufficient permissions."));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            User user = userRepository.findByEmail(email);
            if (user == null) {
                throw new RuntimeException("User not found");
            }

            String token = UUID.randomUUID().toString(); // generiši token
            passwordResetTokenService.saveToken(user, token); // upiši token u bazu

            //emailService.sendPasswordResetEmail(user.getEmail(), token);
            try {
                emailService.sendPasswordResetEmail(user.getEmail(), token);
            } catch (Exception e) {
                e.printStackTrace(); // vidi tačan uzrok greške slanja maila
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Failed to send email: " + e.getMessage()));

            }

            return ResponseEntity.ok(Map.of("message", "Password reset link has been sent to your email."));

        } catch (Exception e) {
            e.printStackTrace();  // ovo će ispisati stack trace u konzoli
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to send email: " + e.getMessage()));

        }
    }


    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("password");

        User user = passwordResetTokenService.validateToken(token);
        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenService.invalidateToken(token);

        return ResponseEntity.ok(Map.of("message", "Password has been successfully reset."));
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enable2FA(@RequestBody Map<String, String> request) {
        String email = request.get("sub"); // stiže iz Angular-a
        String qrUrl = userService.enable2FA(email);
        return ResponseEntity.ok(Map.of("qrUrl", qrUrl));
    }

}

package com.pki.example.service;

import com.pki.example.dto.JwtResponse;
import com.pki.example.dto.TokenInfoDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.model.Role;
import com.pki.example.model.TokenInfo;
import com.pki.example.model.User;
import com.pki.example.repository.UserRepository;
import com.pki.example.util.TokenUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class UserService implements UserDetailsService {


    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private HttpServletRequest request; // Autowired HttpServletRequest

    public Map<String, TokenInfo> activeTokens = new ConcurrentHashMap<>();
    private Map<String, String> jtiToJwtMap = new ConcurrentHashMap<>();

    @Autowired
    private RoleService roleService;

    @Autowired
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);


    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, TokenUtils tokenUtils, AuthenticationManager authenticationManager) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenUtils = tokenUtils;
        this.authenticationManager = authenticationManager;


    }

    @Autowired
    private EmailService emailService;

    @Transactional
    public synchronized ResponseEntity<?> register(UserDTO userDto) {
        logger.info("Registration attempt for email: {}", userDto.getEmail());

        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            logger.warn("Password mismatch for email: {}", userDto.getEmail());
            return ResponseEntity.badRequest().body("Passwords do not match!");
        }

        if (userDto.getEmail() == null || userDto.getEmail().isEmpty()) {
            logger.warn("Missing email during registration attempt");
            return ResponseEntity.badRequest().body("Email address is required!");
        }
        if (userDto.getPassword() == null || userDto.getPassword().isEmpty()) {
            logger.warn("Email already exists: {}", userDto.getEmail());
            return ResponseEntity.badRequest().body("Password is required!");
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.badRequest().body("Email address already exists!");
        }


        User user = new User();

        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        // Sanitizujemo unos da uklonimo HTML/JS tagove
        user.setName(StringEscapeUtils.escapeHtml4(userDto.getName()));
        user.setSurname(StringEscapeUtils.escapeHtml4(userDto.getSurname()));
        user.setOrganization(StringEscapeUtils.escapeHtml4(userDto.getOrganization()));

        user.setActivated(false);
        user.setEnabled(true);
        user.setCreationTime(LocalDateTime.now());

        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);


        List<Role> roles = roleService.findByName("ROLE_END_USER");
        user.setRoles(roles);

        userRepository.save(user);


        emailService.sendActivationEmail(user.getEmail(), activationToken);

        logger.info("User registered successfully: {}", user.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(user));
    }

public ResponseEntity<?> login(String email, String password) {
    logger.info("Login attempt for email: {}", email);
        try {
        // Autentifikacija korisnika
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generisanje JWT
        String jwt = tokenUtils.generateToken(email);
        int expiresIn = tokenUtils.getExpiredIn();
        // Kreiranje JTI (jedinstveni ID tokena)
        String jti = UUID.randomUUID().toString();

        // Kreiranje TokenInfo objekta
        TokenInfo tokenInfo = new TokenInfo(
                jti,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                LocalDateTime.now()
        );
    // Dodaj u mapu aktivnih tokena
        activeTokens.put(jti, tokenInfo);

        jtiToJwtMap.put(jti, jwt);

            logger.info("Login successful for email: {}, IP: {}, User-Agent: {}", email,
                    request.getRemoteAddr(), request.getHeader("User-Agent"));

        return ResponseEntity.ok(new JwtResponse(jwt, expiresIn, jti));
    } catch (Exception e) {
            logger.warn("Login failed for email: {}. Reason: {}", email, e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Pogrešan email ili lozinka!");
    }
}

    public ResponseEntity<?> activateUser(String token) {
        Optional<User> userOptional = userRepository.findByActivationToken(token);
        if (!userOptional.isPresent()) {
            logger.warn("Activation attempt with invalid token: {}", token);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Nevažeći aktivacioni token.");
        }

        User user = userOptional.get();
        user.setActivated(true);
        user.setActivationToken(null);

        userRepository.save(user);

        logger.info("User activated successfully: {}", user.getEmail());
        return ResponseEntity.ok("Korisnik je uspešno aktiviran.");
    }

    public User loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email); // <-- koristi findByEmail
        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with email '%s'.", email));
        } else {
            return user;
        }
    }



    public Integer getRole(Integer userId){
        return userRepository.findRoleIdByUserId(userId);
    }

    public List<TokenInfoDTO> getActiveTokensForUser(String email) {
        List<TokenInfoDTO> tokensForUser = new ArrayList<>();
        for (Map.Entry<String, TokenInfo> entry : activeTokens.entrySet()) {
            String jti = entry.getKey();
            TokenInfo tokenInfo = entry.getValue();
            String tokenEmail = getEmailFromTokenByJti(jti);
            if (email.equals(tokenEmail)) {
                tokensForUser.add(new TokenInfoDTO(tokenInfo));
            }
        }
        return tokensForUser;
    }


    public String getEmailFromTokenByJti(String jti) {
        String token = jtiToJwtMap.get(jti);
        if (token == null) return null;
        return tokenUtils.getEmailFromToken(token);
    }


    public boolean revokeToken(String jti, String email) {
        TokenInfo tokenInfo = activeTokens.get(jti);
        if (tokenInfo != null) {
            String tokenEmail = getEmailFromTokenByJti(jti);
            if (tokenEmail == null || !email.equals(tokenEmail)) {
                logger.warn("Failed attempt to revoke token {} for email {}", jti, email);
                return false;
            }
            activeTokens.remove(jti);
            jtiToJwtMap.remove(jti); // obavezno ukloni i iz mape
            logger.info("Token revoked successfully: {} for email {}", jti, email);
            return true;
        }
        logger.warn("Token not found for revocation: {} by email {}", jti, email);
        return false;
    }



}

package com.pki.example.service;

import com.pki.example.dto.JwtResponse;
import com.pki.example.dto.TokenInfoDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.model.Role;
import com.pki.example.model.TokenInfo;
import com.pki.example.model.User;
import com.pki.example.repository.UserRepository;
import com.pki.example.util.TokenUtils;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
public class UserService implements UserDetailsService {


    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private KeystoreService keystoreService;

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


    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    @Autowired
    private RecaptchaService recaptchaService;


    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, KeystoreService keystoreService, TokenUtils tokenUtils, AuthenticationManager authenticationManager) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenUtils = tokenUtils;
        this.authenticationManager = authenticationManager;
        this.keystoreService = keystoreService;


    }

    @Value("${keycloak.auth-server-url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${app.keycloak.admin.username}")
    private String keycloakAdminUsername;

    @Value("${app.keycloak.admin.password}")
    private String keycloakAdminPassword;




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

        char[] userSymmetricKey = keystoreService.generateRandomPassword();

        String encryptedUserKey = keystoreService.encryptUserSymmetricKey(new String(userSymmetricKey));





        User user = new User();

        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        // Sanitizujemo unos da uklonimo HTML/JS tagove
        user.setName(StringEscapeUtils.escapeHtml4(userDto.getName()));
        user.setSurname(StringEscapeUtils.escapeHtml4(userDto.getSurname()));
        user.setOrganization(StringEscapeUtils.escapeHtml4(userDto.getOrganization()));
        user.setEncryptedUserSymmetricKey(StringEscapeUtils.escapeHtml4((encryptedUserKey)));

        user.setActivated(false);
        user.setEnabled(true);
        user.setCreationTime(LocalDateTime.now());

        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);


        List<Role> roles = roleService.findByName("ROLE_END_USER");
        user.setRoles(roles);

        userRepository.save(user);

        // --- Kreiranje korisnika u Keycloak-u ---
        try {
            createKeycloakUser(userDto.getEmail(), userDto.getPassword(), "ROLE_END_USER");
            logger.info("User also created in Keycloak: {}", userDto.getEmail());
        } catch (Exception e) {
            logger.error("Failed to create user in Keycloak for email: {}", userDto.getEmail(), e);
            // Možeš odlučiti da li rollback-uješ bazu ili nastavljaš
        }

        emailService.sendActivationEmail(user.getEmail(), activationToken);

        logger.info("User registered successfully: {}", user.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(user));
    }

    @Transactional
    public synchronized ResponseEntity<?> registerCAUser(UserDTO userDto) {
        logger.info("Admin creating CA user with email: {}", userDto.getEmail());

        if (userDto.getEmail() == null || userDto.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("Email address is required!");
        }
        if (userRepository.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.badRequest().body("Email already exists!");
        }

        // 1️⃣ Generišemo nasumičnu privremenu lozinku
        String rawPassword = UUID.randomUUID().toString().substring(0, 10); // 10 karaktera
        String encodedPassword = passwordEncoder.encode(rawPassword);

        char[] userSymmetricKey = keystoreService.generateRandomPassword();
        String encryptedUserKey = keystoreService.encryptUserSymmetricKey(new String(userSymmetricKey));

        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setPassword(encodedPassword);
        user.setName(StringEscapeUtils.escapeHtml4(userDto.getName()));
        user.setSurname(StringEscapeUtils.escapeHtml4(userDto.getSurname()));
        user.setOrganization(StringEscapeUtils.escapeHtml4(userDto.getOrganization()));
        user.setEncryptedUserSymmetricKey(encryptedUserKey);
        user.setActivated(true);      // CA user odmah aktivan
        user.setEnabled(true);
        user.setFirstLogin(true);     //  nova kolona u entitetu User
        user.setCreationTime(LocalDateTime.now());

        List<Role> roles = roleService.findByName("ROLE_CA_USER");
        user.setRoles(roles);

        userRepository.save(user);

        try {
            createKeycloakUser(userDto.getEmail(), rawPassword,  "ROLE_CA_USER");
            logger.info("CA user also created in Keycloak: {}", userDto.getEmail());
        } catch (Exception e) {
            logger.error("Failed to create CA user in Keycloak", e);
        }

        // 2️⃣ Pošalji email korisniku sa privremenom lozinkom
        emailService.sendCAUserWelcomeEmail(user.getEmail(), rawPassword);

        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(user));
    }

    private void createKeycloakUser(String email, String password, String roleName) {
        RestTemplate restTemplate = new RestTemplate();

        try {
            ObjectMapper mapper = new ObjectMapper();

            // 1️⃣ Dobijanje admin tokena
            String tokenEndpoint = keycloakUrl + "realms/master/protocol/openid-connect/token";
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "password");
            body.add("client_id", "admin-cli");
            body.add("username", keycloakAdminUsername);
            body.add("password", keycloakAdminPassword);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            logger.info("Requesting admin token from {}", tokenEndpoint);
            ResponseEntity<String> response = restTemplate.postForEntity(tokenEndpoint, new HttpEntity<>(body, headers), String.class);
            logger.info("Admin token response status: {}, body: {}", response.getStatusCode(), response.getBody());

            String adminToken = mapper.readTree(response.getBody()).get("access_token").asText();
            logger.info("Admin token received successfully.");

            HttpHeaders authHeaders = new HttpHeaders();
            authHeaders.setContentType(MediaType.APPLICATION_JSON);
            authHeaders.setBearerAuth(adminToken);

            // 2️⃣ Provera da li korisnik već postoji
            String searchUrl = keycloakUrl + "admin/realms/security-app/users?username=" + email;
            logger.info("Checking if user exists: {}", searchUrl);
            ResponseEntity<String> searchResponse = restTemplate.exchange(searchUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), String.class);
            logger.info("User search response: {}", searchResponse.getBody());

            JsonNode usersNode = mapper.readTree(searchResponse.getBody());

            String userId;
            if (usersNode.isArray() && usersNode.size() > 0) {
                // Korisnik postoji → update lozinke
                userId = usersNode.get(0).get("id").asText();
                logger.info("User {} already exists with ID {}", email, userId);

                Map<String, Object> credUpdate = Map.of(
                        "type", "password",
                        "value", password,
                        "temporary", false
                );
                restTemplate.put(keycloakUrl + "admin/realms/security-app/users/" + userId + "/reset-password",
                        new HttpEntity<>(credUpdate, authHeaders));
                logger.info("Password updated for user {}", userId);

                Map<String, Object> updateStatus = Map.of(
                        "enabled", true,
                        "emailVerified", true
                );
                restTemplate.put(keycloakUrl + "admin/realms/security-app/users/" + userId,
                        new HttpEntity<>(updateStatus, authHeaders));
                logger.info("User {} enabled and email verified.", userId);

            } else {
                // Korisnik ne postoji → kreiraj novog
                logger.info("Creating new user: {}", email);
                Map<String, Object> newUser = new HashMap<>();
                newUser.put("username", email);
                newUser.put("email", email);
                newUser.put("enabled", true);
                newUser.put("firstName", email);
                newUser.put("lastName", email);
                newUser.put("emailVerified", true);
                newUser.put("credentials", List.of(Map.of(
                        "type", "password",
                        "value", password,
                        "temporary", false
                )));

                ResponseEntity<String> createResponse = restTemplate.postForEntity(
                        keycloakUrl + "admin/realms/security-app/users",
                        new HttpEntity<>(newUser, authHeaders),
                        String.class
                );

                logger.info("Create user response status: {}, body: {}", createResponse.getStatusCode(), createResponse.getBody());
                if (!createResponse.getStatusCode().is2xxSuccessful()) {
                    throw new RuntimeException("Failed to create user: " + createResponse.getBody());
                }

                // Preuzmi ID novokreiranog korisnika
                ResponseEntity<String> userResp = restTemplate.exchange(searchUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), String.class);
                userId = mapper.readTree(userResp.getBody()).get(0).get("id").asText();
                logger.info("New user {} created with ID {}", email, userId);
            }

            // 3️⃣ Preuzmi client ID (za client role)
            String clientId = "my-app";
            String clientsUrl = keycloakUrl + "admin/realms/security-app/clients?clientId=" + clientId;
            logger.info("Fetching client UUID from Keycloak: {}", clientsUrl);
            ResponseEntity<String> clientsResp = restTemplate.exchange(clientsUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), String.class);
            logger.info("Client response status: {}, body: {}", clientsResp.getStatusCode(), clientsResp.getBody());

            JsonNode clientNode = mapper.readTree(clientsResp.getBody()).get(0);
            String clientUuid = clientNode.get("id").asText();
            logger.info("Resolved client UUID: {}", clientUuid);

            // 4️⃣ Preuzmi ID role
            String rolesUrl = keycloakUrl + "admin/realms/security-app/clients/" + clientUuid + "/roles";
            logger.info("Fetching roles from Keycloak: {}", rolesUrl);
            ResponseEntity<String> rolesResp = restTemplate.exchange(rolesUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), String.class);
            logger.info("Roles response status: {}, body: {}", rolesResp.getStatusCode(), rolesResp.getBody());

            JsonNode rolesNode = mapper.readTree(rolesResp.getBody());
            String roleId = null;
            for (JsonNode role : rolesNode) {
                if (role.get("name").asText().equals(roleName)) {
                    roleId = role.get("id").asText();
                    logger.info("Found role {} with ID {}", roleName, roleId);
                    break;
                }
            }
            if (roleId == null) {
                logger.error("Role not found in Keycloak: {}", roleName);
                throw new RuntimeException("Role not found in Keycloak: " + roleName);
            }

            // 5️⃣ Dodeli rolu korisniku
            String assignRoleUrl = keycloakUrl + "admin/realms/security-app/users/" + userId + "/role-mappings/clients/" + clientUuid;
            List<Map<String, Object>> rolesToAssign = List.of(Map.of(
                    "id", roleId,
                    "name", roleName
            ));

            logger.info("Assigning role {} (ID: {}) to user {} via {}", roleName, roleId, userId, assignRoleUrl);
            ResponseEntity<String> assignResp = restTemplate.postForEntity(assignRoleUrl, new HttpEntity<>(rolesToAssign, authHeaders), String.class);
            logger.info("Role assignment response status: {}, body: {}", assignResp.getStatusCode(), assignResp.getBody());

        } catch (Exception e) {
            logger.error("Error during Keycloak user creation and role assignment", e);
            throw new RuntimeException(e);
        }
    }


    public ResponseEntity<?> login(String email, String password, String recaptchaToken, Integer twoFactorCode) {
        logger.info("Login attempt for email: {}", email);


        //  Provera reCAPTCHA
        if (!recaptchaService.verify(recaptchaToken)) { // recaptchaService ili emailService, kako si implementirala
            logger.warn("Invalid reCAPTCHA for email: {}", email);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("CAPTCHA nije validna!");
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nepostojeći korisnik");
        }
        if (user.isFirstLogin()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Password change required on first login.");
        }


        // ako korisnik ima uključen 2FA
        if (user.getTwoFaSecret() != null) {
            GoogleAuthenticator gAuth = new GoogleAuthenticator();
            boolean isCodeValid = gAuth.authorize(user.getTwoFaSecret(), twoFactorCode);

            if (!isCodeValid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Pogrešan 2FA kod!");
            }
        }

        try {
            //  Autentifikacija preko Keycloak-a
            String keycloakToken = tokenUtils.loginToKeycloak(email, password);
            if (keycloakToken == null) {
                logger.warn("Login failed via Keycloak for email: {}", email);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Pogrešan email ili lozinka!");
            }


            // Kreiranje JTI i TokenInfo
            String jti = UUID.randomUUID().toString();
            TokenInfo tokenInfo = new TokenInfo(
                    jti,
                    email,
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent"),
                    LocalDateTime.now()
            );

            activeTokens.put(jti, tokenInfo);
            jtiToJwtMap.put(jti, keycloakToken);

            int expiresIn = tokenUtils.getExpiredIn(); // opcionalno: možeš koristiti expiresIn iz Keycloak tokena

            logger.info("Login successful for email: {}, IP: {}, User-Agent: {}", email,
                    request.getRemoteAddr(), request.getHeader("User-Agent"));

            return ResponseEntity.ok(new JwtResponse(keycloakToken, expiresIn, jti));

        } catch (Exception e) {
            logger.warn("Login failed for email: {}. Reason: {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Greška prilikom autentifikacije!");
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
        for (TokenInfo tokenInfo : activeTokens.values()) {
            if (email.equals(tokenInfo.getEmail())) {
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


    public boolean revokeToken(String jti, String sub) {
        TokenInfo token = activeTokens.get(jti);
        if (token != null && sub.equals(token.getSub())) {
            activeTokens.remove(jti);
            jtiToJwtMap.remove(jti);
            return true;
        }
        logger.warn("Failed attempt to revoke token {} for sub {}", jti, sub);
        return false;
    }

    public String enable2FA(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) throw new RuntimeException("User not found");

        // Ako već postoji secret, ne generišemo novi svaki put
        if (user.getTwoFaSecret() != null && !user.getTwoFaSecret().isEmpty()) {
            return GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                    "SecurityApp", email,
                    new GoogleAuthenticatorKey.Builder(user.getTwoFaSecret()).build()
            );
        }

        // Generisanje novog secret-a
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        System.out.println("Issuer: SecurityApp");
        System.out.println("Account: " + email);
        System.out.println("Secret: " + secret);

        user.setTwoFaSecret(secret);
        userRepository.save(user);

        String otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SecurityApp", email, key);
        System.out.println("OTP URL: " + otpAuthURL); // ili Logger
        return otpAuthURL;
        //return GoogleAuthenticatorQRGenerator.getOtpAuthURL("SecurityApp", email, key);
    }


    public void updateKeycloakPassword(String email, String newPassword) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        ObjectMapper mapper = new ObjectMapper();

        // Dobij admin token
        String tokenEndpoint = keycloakUrl + "realms/master/protocol/openid-connect/token";
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", "admin-cli");
        body.add("username", keycloakAdminUsername);
        body.add("password", keycloakAdminPassword);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<String> response = restTemplate.postForEntity(tokenEndpoint, new HttpEntity<>(body, headers), String.class);
        String adminToken = mapper.readTree(response.getBody()).get("access_token").asText();

        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.setContentType(MediaType.APPLICATION_JSON);
        authHeaders.setBearerAuth(adminToken);

        // Nađi userId u Keycloak-u
        String searchUrl = keycloakUrl + "admin/realms/security-app/users?username=" + email;
        ResponseEntity<String> searchResponse = restTemplate.exchange(searchUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), String.class);
        JsonNode usersNode = mapper.readTree(searchResponse.getBody());
        if (!usersNode.isArray() || usersNode.size() == 0) {
            throw new RuntimeException("User not found in Keycloak: " + email);
        }
        String userId = usersNode.get(0).get("id").asText();

        // Reset password
        Map<String, Object> credUpdate = Map.of(
                "type", "password",
                "value", newPassword,
                "temporary", false
        );

        restTemplate.put(
                keycloakUrl + "admin/realms/security-app/users/" + userId + "/reset-password",
                new HttpEntity<>(credUpdate, authHeaders)
        );
    }


}

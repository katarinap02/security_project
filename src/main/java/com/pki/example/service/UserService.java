package com.pki.example.service;

import com.pki.example.dto.JwtResponse;
import com.pki.example.dto.UserDTO;
import com.pki.example.model.Role;
import com.pki.example.model.User;
import com.pki.example.repository.UserRepository;
import com.pki.example.util.TokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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


@Service
public class UserService implements UserDetailsService {

    private final Logger LOG = LoggerFactory.getLogger(UserService.class);

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


    @Autowired
    private RoleService roleService;

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
        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            return ResponseEntity.badRequest().body("Passwords do not match!");
        }

        if (userDto.getEmail() == null || userDto.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("Email address is required!");
        }
        if (userDto.getPassword() == null || userDto.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body("Password is required!");
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.badRequest().body("Email address already exists!");
        }


        User user = new User();

        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setName(userDto.getName());
        user.setSurname(userDto.getSurname());
        user.setOrganization(userDto.getOrganization());
        user.setActivated(false);
        user.setEnabled(true);
        user.setCreationTime(LocalDateTime.now());

        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);


        List<Role> roles = roleService.findByName("ROLE_END_USER");
        user.setRoles(roles);

        userRepository.save(user);


        emailService.sendActivationEmail(user.getEmail(), activationToken);

        return ResponseEntity.status(HttpStatus.CREATED).body(new UserDTO(user));
    }

//public ResponseEntity<UserTokenState> login(
//        @RequestBody JwtAuthenticationRequest authenticationRequest, HttpServletResponse response) {
//    // Ukoliko kredencijali nisu ispravni, logovanje nece biti uspesno, desice se
//    // AuthenticationException
//    Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
//            authenticationRequest.getUsername(), authenticationRequest.getPassword()));
//
//    // Ukoliko je autentifikacija uspesna, ubaci korisnika u trenutni security
//    // kontekst
//    SecurityContextHolder.getContext().setAuthentication(authentication);
//
//    // Kreiraj token za tog korisnika
//    User user = (User) authentication.getPrincipal();
//    String jwt = tokenUtils.generateToken(user.getUsername());
//    int expiresIn = tokenUtils.getExpiredIn();
//
//    // Vrati token kao odgovor na uspesnu autentifikaciju
//    return ResponseEntity.ok(new UserTokenState(jwt, expiresIn, user.getId()));
//}
public ResponseEntity<?> login(String email, String password) {
    try {
        // Autentifikacija korisnika
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generisanje JWT
        String jwt = tokenUtils.generateToken(email);
        int expiresIn = tokenUtils.getExpiredIn();

        return ResponseEntity.ok(new JwtResponse(jwt, expiresIn));
    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Pogrešan email ili lozinka!");
    }
}

    public ResponseEntity<?> activateUser(String token) {
        Optional<User> userOptional = userRepository.findByActivationToken(token);
        if (!userOptional.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Nevažeći aktivacioni token.");
        }

        User user = userOptional.get();
        user.setActivated(true);
        user.setActivationToken(null);

        userRepository.save(user);

        return ResponseEntity.ok("Korisnik je uspešno aktiviran.");
    }

    public UserDTO getUserProfile(Integer userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NoSuchElementException("User not found"));

        return new UserDTO(user);
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


}

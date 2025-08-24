package com.pki.example.service;

import com.pki.example.model.User;
import com.pki.example.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// Ovaj servis je namerno izdvojen kao poseban u ovom primeru.
// U opstem slucaju UserServiceImpl klasa bi mogla da implementira UserDetailService interfejs.
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    // Funkcija koja na osnovu email-a iz baze vraca objekat User-a
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        logger.info("Attempt to load user by email: {}", email);
        User user = userRepository.findByEmail(email);
        if (user == null) {
            logger.warn("User not found with email: {}", email);
            throw new UsernameNotFoundException(String.format("No user found with email '%s'.", email));
        } else {
            logger.info("User loaded successfully: {}", email);
            return user;
        }
    }

}
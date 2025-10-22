package com.pki.example.controller;

import com.pki.example.dto.PasswordShareRequestDTO;
import com.pki.example.dto.SharedPasswordDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.dto.UserLightDTO;
import com.pki.example.model.PasswordShare;
import com.pki.example.model.User;
import com.pki.example.service.PasswordShareService;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/passwords/shares")
public class PasswordShareController {

    @Autowired
    UserService userService;

    private final PasswordShareService shareService;

    public PasswordShareController(PasswordShareService shareService) {
        this.shareService = shareService;
    }

    @PostMapping
    public PasswordShare sharePassword(@RequestBody PasswordShareRequestDTO dto, Authentication authentication) {
        String ownerEmail = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");

        return shareService.sharePassword(dto, ownerEmail);
    }

    @GetMapping
    public List<SharedPasswordDTO> getMyShares(Authentication authentication) {
        String ownerEmail = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        User user = userService.findByEmail(ownerEmail);
        Long userId = user.getId().longValue();

        return shareService.getSharesForUser(userId)
                .stream()
                .map(SharedPasswordDTO::new)
                .collect(Collectors.toList());
    }

    @GetMapping("/end-entities")
    public List<UserLightDTO> getEndEntityUsers() {
        return userService.getEndEntityUsers()
                .stream()
                .map(UserLightDTO::new)
                .collect(Collectors.toList());
    }
}

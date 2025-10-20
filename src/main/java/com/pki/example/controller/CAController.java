package com.pki.example.controller;
import com.pki.example.model.CA;
import com.pki.example.service.CAService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api/ca")
public class CAController {

    @Autowired
    private CAService caService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_END_USER')")
    public List<CA> getAllActiveCAs(Authentication authentication) {
        String email = ((Jwt) authentication.getPrincipal()).getClaim("preferred_username");
        return caService.getAllCAs().stream()
                .map(ca -> {
                    CA dto = new CA();
                    dto.setId(ca.getId());
                    dto.setName(ca.getName());
                    dto.setMaxCertificateDuration(ca.getMaxCertificateDuration());
                    return dto;
                }).collect(Collectors.toList());
    }

}

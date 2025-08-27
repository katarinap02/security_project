package com.pki.example.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null || !resourceAccess.containsKey("my-app")) {
            return List.of();
        }

        Map<String, Object> appRoles = (Map<String, Object>) resourceAccess.get("my-app");
        List<String> roles = (List<String>) appRoles.get("roles");

        return roles.stream()
                .map(SimpleGrantedAuthority::new) // JWT već ima ROLE_ prefiks
                .collect(Collectors.toList());
    }
}

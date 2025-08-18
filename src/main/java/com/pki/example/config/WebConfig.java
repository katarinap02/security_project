package com.pki.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // Dozvoli sve rute
                .allowedOrigins("http://localhost:4200") // Dozvoli frontend
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Dozvoli sve metode
                .allowedHeaders("*") // Dozvoli sve zaglavlja
                .allowCredentials(true); // Omogući slanje kolačića
    }
}

package com.pki.example.controller;
import com.pki.example.model.CA;
import com.pki.example.service.CAService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/ca")
public class CAController {

    @Autowired
    private CAService caService;

    @GetMapping
    public List<CA> getAllCAs() {
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

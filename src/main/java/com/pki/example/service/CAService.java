package com.pki.example.service;

import com.pki.example.model.CA;
import com.pki.example.repository.CARepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CAService {

    private final CARepository caRepository;

    public CAService(CARepository caRepository) {
        this.caRepository = caRepository;
    }

    public List<CA> getAllCAs() {
        return caRepository.findAll();
    }
}

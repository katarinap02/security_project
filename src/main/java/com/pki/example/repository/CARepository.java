package com.pki.example.repository;

import com.pki.example.model.CA;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CARepository extends JpaRepository<CA, Long> {
    CA findByName(String name);
}

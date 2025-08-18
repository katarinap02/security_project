package com.pki.example.repository;

import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    User findByEmail(String email);

    @Query("select u from User u where u.id = ?1")
    Optional<User> findById(Integer id);

    @Query("select count(u) > 0 from User u where u.email = ?1")
    boolean existsByEmail(String email);

    Optional<User> findByActivationToken(String activationToken);

    @Query(value = "SELECT ur.role_id FROM user_role ur WHERE ur.user_id = :userId", nativeQuery = true)
    Integer findRoleIdByUserId(@Param("userId") Integer userId);



}


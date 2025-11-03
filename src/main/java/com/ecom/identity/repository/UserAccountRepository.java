package com.ecom.identity.repository;

import com.ecom.identity.entity.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    Optional<UserAccount> findByEmail(String email);
    Optional<UserAccount> findByPhone(String phoneNumber);
    Optional<UserAccount> findByEmailOrPhone(String email, String phoneNumber);
    
}

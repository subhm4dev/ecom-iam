package com.ecom.identity.repository;

import com.ecom.identity.entity.JwkKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface JwkKeyRepository extends JpaRepository<JwkKey, UUID> {
}

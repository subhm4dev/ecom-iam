package com.ecom.identity.repository;

import com.ecom.identity.entity.RoleGrant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RoleGrantRepository extends JpaRepository<RoleGrant, UUID> {
}

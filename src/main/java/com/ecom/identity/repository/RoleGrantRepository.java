package com.ecom.identity.repository;

import com.ecom.identity.entity.RoleGrant;
import com.ecom.identity.entity.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface RoleGrantRepository extends JpaRepository<RoleGrant, UUID> {
    List<RoleGrant> findAllByUser(UserAccount userAccount);
}

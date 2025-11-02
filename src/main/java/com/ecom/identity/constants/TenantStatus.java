package com.ecom.identity.constants;

public enum TenantStatus {
    ACTIVE,
    INACTIVE;

    public String getValue() {
        return name();
    }
}

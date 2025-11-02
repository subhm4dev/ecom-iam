package com.ecom.identity.constants;

public enum Role {
    CUSTOMER,
    SELLER,
    ADMIN,
    STAFF,
    DRIVER;

    public String getValue() {
        return name();
    }
}

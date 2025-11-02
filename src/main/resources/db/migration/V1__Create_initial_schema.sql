-- Enable UUID extension (PostgreSQL 13+ has gen_random_uuid() built-in, but uuid-ossp provides additional functions)
-- Using gen_random_uuid() which is available in PostgreSQL 13+ without extension

-- Essential enums for MVP
create type tenant_status as enum ('ACTIVE', 'INACTIVE');
create type user_role as enum ('CUSTOMER', 'SELLER', 'ADMIN', 'STAFF', 'DRIVER');

-- Core tables for authentication
create table tenants (
    id uuid primary key default gen_random_uuid(),
    name varchar(255) not null,
    status tenant_status default 'ACTIVE',
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp
);

create table user_accounts (
    id uuid primary key default gen_random_uuid(),
    email varchar(255), -- Tenant-scoped uniqueness (see constraint below)
    phone varchar(20), -- Tenant-scoped uniqueness (see constraint below)
    password_hash varchar(255) not null,
    salt varchar(255) not null, -- Explicit salt for salt+pepper technique
    tenant_id uuid not null references tenants(id) on delete restrict,
    enabled boolean default true,
    email_verified boolean default false,
    phone_verified boolean default false,
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp,
    constraint email_or_phone_required check (email is not null or phone is not null),
    -- Email/phone unique per tenant:
    -- - Customers share default tenant (00000000-0000-0000-0000-000000000000) 
    --   → email/phone effectively globally unique for customers
    -- - Sellers have their own tenants → same email/phone can exist across different seller tenants
    constraint unique_email_tenant unique (email, tenant_id),
    constraint unique_phone_tenant unique (phone, tenant_id)
);

create index idx_user_accounts_email on user_accounts(email);
create index idx_user_accounts_phone on user_accounts(phone);
create index idx_user_accounts_tenant on user_accounts(tenant_id);

create table role_grants (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references user_accounts(id) on delete cascade,
    role user_role not null,
    granted_at timestamp default current_timestamp,
    constraint unique_user_role unique (user_id, role)
);

create index idx_role_grants_user on role_grants(user_id);

create table jwk_keys (
    id uuid primary key default gen_random_uuid(),
    kid varchar(50) unique not null,
    public_key_pem text not null,
    private_key_pem text not null,
    algorithm varchar(50) default 'RS256',
    created_at timestamp default current_timestamp,
    expires_at timestamp
);

create index idx_jwk_keys_kid on jwk_keys(kid);

create table refresh_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references user_accounts(id) on delete cascade,
    token_hash varchar(255) not null,
    expires_at timestamp not null,
    revoked boolean default false,
    created_at timestamp default current_timestamp
);

create index idx_refresh_tokens_user on refresh_tokens(user_id);
create index idx_refresh_tokens_expires on refresh_tokens(expires_at);
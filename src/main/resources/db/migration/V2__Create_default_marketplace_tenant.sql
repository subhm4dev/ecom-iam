-- Create default marketplace tenant (ID: 00000000-0000-0000-0000-000000000000)
-- All customers will belong to this tenant by default
-- Sellers will have their own tenant IDs

insert into tenants (id, name, status, created_at, updated_at)
values (
    '00000000-0000-0000-0000-000000000000'::uuid,
    'Marketplace',
    'ACTIVE',
    current_timestamp,
    current_timestamp
)
on conflict (id) do nothing; -- Safe to run multiple times


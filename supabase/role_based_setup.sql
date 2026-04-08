-- SafeBrowse role-based auth and data access setup
-- Run this in Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  display_name text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.user_profiles add column if not exists email text;
alter table public.user_profiles add column if not exists display_name text;
alter table public.user_profiles add column if not exists role text;
alter table public.user_profiles add column if not exists created_at timestamptz;
alter table public.user_profiles add column if not exists updated_at timestamptz;

update public.user_profiles
set role = coalesce(nullif(role, ''), 'user')
where role is null or role = '';

alter table public.user_profiles alter column role set default 'user';

create table if not exists public.admin_users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  role text not null default 'admin' check (role in ('admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.endpoint_owners (
  endpoint_id text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_name text,
  created_at timestamptz not null default now()
);

alter table public.scan_logs add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.scan_logs add column if not exists created_at timestamptz not null default now();

create index if not exists idx_scan_logs_user_id_created_at on public.scan_logs(user_id, created_at desc);
create index if not exists idx_scan_logs_endpoint_id_created_at on public.scan_logs(endpoint_id, created_at desc);
create index if not exists idx_endpoint_owners_user_id on public.endpoint_owners(user_id);

alter table public.user_profiles enable row level security;
alter table public.admin_users enable row level security;
alter table public.endpoint_owners enable row level security;
alter table public.scan_logs enable row level security;

-- Drop old policies if re-running.
drop policy if exists "profiles_select_own_or_admin" on public.user_profiles;
drop policy if exists "profiles_insert_own" on public.user_profiles;
drop policy if exists "profiles_update_own_or_admin" on public.user_profiles;
drop policy if exists "admin_users_read_own_or_admin" on public.admin_users;
drop policy if exists "endpoint_owners_read_own_or_admin" on public.endpoint_owners;
drop policy if exists "endpoint_owners_manage_own_or_admin" on public.endpoint_owners;
drop policy if exists "scan_logs_insert_authenticated" on public.scan_logs;
drop policy if exists "scan_logs_select_own_or_admin" on public.scan_logs;

-- Profiles: user can see/update own row; admin can manage all.
create policy "profiles_select_own_or_admin"
on public.user_profiles
for select
using (
  auth.uid() = id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

create policy "profiles_insert_own"
on public.user_profiles
for insert
with check (
  auth.uid() = id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

create policy "profiles_update_own_or_admin"
on public.user_profiles
for update
using (
  auth.uid() = id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
)
with check (
  auth.uid() = id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

-- Admin table visibility.
create policy "admin_users_read_own_or_admin"
on public.admin_users
for select
using (
  auth.uid() = id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

-- Endpoint ownership visibility and management.
create policy "endpoint_owners_read_own_or_admin"
on public.endpoint_owners
for select
using (
  auth.uid() = user_id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

create policy "endpoint_owners_manage_own_or_admin"
on public.endpoint_owners
for all
using (
  auth.uid() = user_id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
)
with check (
  auth.uid() = user_id
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

-- Scan logs: authenticated users can insert; users can read their own logs; admins can read all.
create policy "scan_logs_insert_authenticated"
on public.scan_logs
for insert
to anon, authenticated
with check (true);

create policy "scan_logs_select_own_or_admin"
on public.scan_logs
for select
using (
  user_id = auth.uid()
  or exists (
    select 1 from public.endpoint_owners eo
    where eo.endpoint_id = scan_logs.endpoint_id
      and eo.user_id = auth.uid()
  )
  or exists (
    select 1 from public.admin_users a where a.id = auth.uid()
  )
);

-- Optional: make first known account an admin (edit email before running).
-- insert into public.admin_users (id, email)
-- select id, email from auth.users where email = 'admin@safebrowse.com'
-- on conflict (id) do update set email = excluded.email;

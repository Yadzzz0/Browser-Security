-- SafeBrowse role-based auth + endpoint linking + scan log policies
-- Run in Supabase SQL editor for project: Browser Extension for Real-Time Website Security

create extension if not exists pgcrypto;

-- Migrate legacy table names to browser_* to avoid cross-project overlap.
do $$
begin
  if to_regclass('public.browser_user_profiles') is null and to_regclass('public.user_profiles') is not null then
    alter table public.user_profiles rename to browser_user_profiles;
  end if;

  if to_regclass('public.browser_admin_users') is null and to_regclass('public.admin_users') is not null then
    alter table public.admin_users rename to browser_admin_users;
  end if;

  if to_regclass('public.browser_endpoint_owners') is null and to_regclass('public.endpoint_owners') is not null then
    alter table public.endpoint_owners rename to browser_endpoint_owners;
  end if;

  if to_regclass('public.browser_scan_logs') is null and to_regclass('public.scan_logs') is not null then
    alter table public.scan_logs rename to browser_scan_logs;
  end if;
end $$;

-- Core role/profile tables
create table if not exists public.browser_user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  display_name text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.browser_admin_users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  role text not null default 'admin' check (role in ('admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.browser_endpoint_owners (
  id uuid primary key default gen_random_uuid(),
  endpoint_id text unique not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  ip_address text,
  os_type text
);

create table if not exists public.browser_scan_logs (
  id uuid primary key default gen_random_uuid(),
  endpoint_id text,
  user_id uuid references auth.users(id) on delete set null,
  url text,
  status text,
  confidence double precision,
  model_used text,
  action_taken text,
  created_at timestamptz not null default now()
);

-- Safety alters for already-existing databases
alter table public.browser_user_profiles add column if not exists email text;
alter table public.browser_user_profiles add column if not exists display_name text;
alter table public.browser_user_profiles add column if not exists role text;
alter table public.browser_user_profiles add column if not exists created_at timestamptz;
alter table public.browser_user_profiles add column if not exists updated_at timestamptz;
update public.browser_user_profiles set role = coalesce(nullif(role, ''), 'user') where role is null or role = '';
alter table public.browser_user_profiles alter column role set default 'user';

alter table public.browser_endpoint_owners add column if not exists endpoint_id text;
alter table public.browser_endpoint_owners add column if not exists user_id uuid;
alter table public.browser_endpoint_owners add column if not exists device_name text;
alter table public.browser_endpoint_owners add column if not exists created_at timestamptz;
alter table public.browser_endpoint_owners add column if not exists updated_at timestamptz;
alter table public.browser_endpoint_owners add column if not exists ip_address text;
alter table public.browser_endpoint_owners add column if not exists os_type text;
create unique index if not exists endpoint_owners_endpoint_id_key on public.browser_endpoint_owners(endpoint_id);

alter table public.browser_scan_logs add column if not exists user_id uuid references auth.users(id) on delete set null;
alter table public.browser_scan_logs add column if not exists created_at timestamptz not null default now();

create index if not exists idx_scan_logs_user_id_created_at on public.browser_scan_logs(user_id, created_at desc);
create index if not exists idx_scan_logs_endpoint_id_created_at on public.browser_scan_logs(endpoint_id, created_at desc);
create index if not exists idx_endpoint_owners_user_id on public.browser_endpoint_owners(user_id);

-- Browser-specific admin checker helper
create or replace function public.browser_is_admin(check_user uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists(select 1 from public.browser_admin_users a where a.id = check_user)
      or exists(select 1 from public.browser_user_profiles p where p.id = check_user and p.role = 'admin');
$$;

revoke all on function public.browser_is_admin(uuid) from public;
grant execute on function public.browser_is_admin(uuid) to anon, authenticated;

-- Enable RLS
alter table public.browser_user_profiles enable row level security;
alter table public.browser_admin_users enable row level security;
alter table public.browser_endpoint_owners enable row level security;
alter table public.browser_scan_logs enable row level security;

-- Cleanup old policy names
 drop policy if exists "Users can view own endpoint links" on public.browser_endpoint_owners;
 drop policy if exists "Enable insert for all users" on public.browser_scan_logs;
 drop policy if exists "Enable select for all users" on public.browser_scan_logs;
 drop policy if exists "Admins can view all profiles" on public.browser_user_profiles;
 drop policy if exists "Users can view own profile" on public.browser_user_profiles;
 drop policy if exists "profiles_select_own_or_admin" on public.browser_user_profiles;
 drop policy if exists "profiles_insert_own" on public.browser_user_profiles;
 drop policy if exists "profiles_insert_own_or_admin" on public.browser_user_profiles;
 drop policy if exists "profiles_update_own_or_admin" on public.browser_user_profiles;
 drop policy if exists "admin_users_read_own_or_admin" on public.browser_admin_users;
 drop policy if exists "admin_users_select_own_or_admin" on public.browser_admin_users;
 drop policy if exists "endpoint_owners_read_own_or_admin" on public.browser_endpoint_owners;
 drop policy if exists "endpoint_owners_manage_own_or_admin" on public.browser_endpoint_owners;
 drop policy if exists "endpoint_owners_select_own_or_admin" on public.browser_endpoint_owners;
 drop policy if exists "endpoint_owners_insert_own_or_admin" on public.browser_endpoint_owners;
 drop policy if exists "endpoint_owners_update_own_or_admin" on public.browser_endpoint_owners;
 drop policy if exists "scan_logs_insert_authenticated" on public.browser_scan_logs;
 drop policy if exists "scan_logs_insert_authenticated_or_anon" on public.browser_scan_logs;
 drop policy if exists "scan_logs_select_own_or_admin" on public.browser_scan_logs;
 drop policy if exists "scan_logs_update_link_own_or_admin" on public.browser_scan_logs;

-- user_profiles policies
create policy "profiles_select_own_or_admin"
on public.browser_user_profiles
for select
using (auth.uid() = id or public.browser_is_admin(auth.uid()));

create policy "profiles_insert_own_or_admin"
on public.browser_user_profiles
for insert
to authenticated
with check (auth.uid() = id or public.browser_is_admin(auth.uid()));

create policy "profiles_update_own_or_admin"
on public.browser_user_profiles
for update
to authenticated
using (auth.uid() = id or public.browser_is_admin(auth.uid()))
with check (auth.uid() = id or public.browser_is_admin(auth.uid()));

-- admin_users policies
create policy "admin_users_select_own_or_admin"
on public.browser_admin_users
for select
to authenticated
using (auth.uid() = id or public.browser_is_admin(auth.uid()));

-- endpoint_owners policies
create policy "endpoint_owners_select_own_or_admin"
on public.browser_endpoint_owners
for select
to authenticated
using (auth.uid() = user_id or public.browser_is_admin(auth.uid()));

create policy "endpoint_owners_insert_own_or_admin"
on public.browser_endpoint_owners
for insert
to authenticated
with check (auth.uid() = user_id or public.browser_is_admin(auth.uid()));

create policy "endpoint_owners_update_own_or_admin"
on public.browser_endpoint_owners
for update
to authenticated
using (auth.uid() = user_id or public.browser_is_admin(auth.uid()))
with check (auth.uid() = user_id or public.browser_is_admin(auth.uid()));

-- scan_logs policies
create policy "scan_logs_insert_authenticated_or_anon"
on public.browser_scan_logs
for insert
to anon, authenticated
with check (true);

create policy "scan_logs_select_own_or_admin"
on public.browser_scan_logs
for select
to authenticated
using (
  user_id = auth.uid()
  or exists (
    select 1 from public.browser_endpoint_owners eo
    where eo.endpoint_id = browser_scan_logs.endpoint_id
      and eo.user_id = auth.uid()
  )
  or public.browser_is_admin(auth.uid())
);

create policy "scan_logs_update_link_own_or_admin"
on public.browser_scan_logs
for update
to authenticated
using (
  user_id is null
  or user_id = auth.uid()
  or public.browser_is_admin(auth.uid())
)
with check (
  user_id = auth.uid()
  or public.browser_is_admin(auth.uid())
);

-- Optional: bootstrap an admin account (edit email first).
-- insert into public.browser_admin_users (id, email)
-- select id, email from auth.users where email = 'admin@safebrowse.com'
-- on conflict (id) do update set email = excluded.email;

-- Refresh PostgREST schema cache after rename and policy changes.
notify pgrst, 'reload schema';

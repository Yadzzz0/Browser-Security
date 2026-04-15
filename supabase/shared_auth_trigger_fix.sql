-- Shared auth trigger safety fix for multi-project Supabase setup.
-- Purpose:
-- 1) Remove duplicate DDoS trigger on auth.users.
-- 2) Ensure handle_new_ddos_profile only writes allowed ddos role values.
-- 3) Prevent Browser signup metadata (role='user') from breaking auth signup.

drop trigger if exists on_auth_user_created_ddos on auth.users;

create or replace function public.handle_new_ddos_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role text;
begin
  v_role := lower(coalesce(new.raw_user_meta_data ->> 'role', ''));
  if v_role not in ('superadmin', 'analyst', 'viewer') then
    v_role := 'viewer';
  end if;

  insert into public.ddos_profiles (id, full_name, role, created_at, updated_at)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', split_part(new.email, '@', 1)),
    v_role,
    now(),
    now()
  )
  on conflict (id)
  do update set
    full_name = coalesce(excluded.full_name, public.ddos_profiles.full_name),
    updated_at = now();

  return new;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_trigger
    where tgname = 'on_auth_user_created_ddos_profile'
      and tgrelid = 'auth.users'::regclass
  ) then
    create trigger on_auth_user_created_ddos_profile
    after insert on auth.users
    for each row execute function public.handle_new_ddos_profile();
  end if;
end $$;

notify pgrst, 'reload schema';

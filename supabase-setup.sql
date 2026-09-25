-- CA PrepX — database setup
-- Paste this whole file into Supabase → SQL Editor → New query → Run.

-- 1. Tables ---------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users on delete cascade,
  email       text,
  name        text,
  level       text,
  is_guest    boolean not null default false,
  created_at  timestamptz not null default now(),
  last_login  timestamptz,
  login_count integer not null default 0
);

create table if not exists public.logins (
  id        bigint generated always as identity primary key,
  user_id   uuid not null references auth.users on delete cascade,
  is_guest  boolean not null default false,
  at        timestamptz not null default now()
);
create index if not exists logins_at_idx on public.logins (at desc);

create table if not exists public.progress (
  user_id    uuid primary key references auth.users on delete cascade,
  state      jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.admins (
  user_id uuid primary key references auth.users on delete cascade
);

-- 2. Helpers --------------------------------------------------------------
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- Called by the website every time a student signs in or opens the site.
create or replace function public.record_login(p_name text default null, p_level text default null)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_uid   uuid    := auth.uid();
  v_guest boolean := coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false);
  v_email text    := nullif(auth.jwt() ->> 'email', '');
begin
  if v_uid is null then return; end if;
  insert into public.logins (user_id, is_guest) values (v_uid, v_guest);
  insert into public.profiles as p (id, email, name, level, is_guest, last_login, login_count)
  values (v_uid, v_email, nullif(p_name, ''), p_level, v_guest, now(), 1)
  on conflict (id) do update set
    email       = coalesce(excluded.email, p.email),
    name        = coalesce(excluded.name, p.name),
    level       = coalesce(excluded.level, p.level),
    is_guest    = excluded.is_guest,
    last_login  = now(),
    login_count = p.login_count + 1;
end;
$$;

-- 3. Security (row-level) -------------------------------------------------
alter table public.profiles enable row level security;
alter table public.logins   enable row level security;
alter table public.progress enable row level security;
alter table public.admins   enable row level security;

drop policy if exists "own or admin reads profile" on public.profiles;
create policy "own or admin reads profile" on public.profiles
  for select using (id = auth.uid() or public.is_admin());

drop policy if exists "admin reads logins" on public.logins;
create policy "admin reads logins" on public.logins
  for select using (public.is_admin());

drop policy if exists "own progress" on public.progress;
create policy "own progress" on public.progress
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

grant execute on function public.record_login(text, text) to authenticated;
grant execute on function public.is_admin() to authenticated;

-- 4. Make yourself admin --------------------------------------------------
-- Run this ONLY after you have created your own account on the website
-- (Sign in → Create account). Replace the email if you used a different one.
--
-- insert into public.admins (user_id)
-- select id from auth.users where email = 'sandeepnegi7227@gmail.com';

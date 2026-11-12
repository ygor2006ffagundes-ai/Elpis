-- Elpis 002: social foundation (verified accounts, follows, blocks, reports, who-can-message)
-- Run AFTER setup.sql: Supabase → SQL Editor → New query → paste this whole file → Run.
-- Safe to run again. If you ever run setup.sql again, run this file again afterwards
-- (it replaces the profiles and posts read rules from setup.sql).

-- ─────────────────────────────────────────────────────────────
-- 1. Helpers
-- ─────────────────────────────────────────────────────────────

-- Age in whole years from "MM/YYYY" (the format the app saves). Null when unknown.
create or replace function public.age_from_birth(b text)
returns integer
language sql
stable
set search_path = ''
as $$
  select case when b ~ '^[0-9]{2}/[0-9]{4}$' then
    extract(year from current_date)::int - split_part(b, '/', 2)::int
    - case when extract(month from current_date)::int < split_part(b, '/', 1)::int then 1 else 0 end
  end;
$$;

-- Shared spam limit: true when `who` already has `max_rows` rows in `tbl` newer than `since`.
create or replace function public.rate_limited(tbl text, who_col text, who uuid, since interval, max_rows integer)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare n integer;
begin
  execute format('select count(*) from public.%I where %I = $1 and created_at > now() - $2', tbl, who_col)
    into n using who, since;
  return n >= max_rows;
end;
$$;
revoke all on function public.rate_limited(text, text, uuid, interval, integer) from public, anon, authenticated;

-- ─────────────────────────────────────────────────────────────
-- 2. Tables
-- ─────────────────────────────────────────────────────────────

-- Verified institutions and the official Elpis account. Only Ygor adds rows (Table Editor).
create table if not exists public.verified_accounts (
  id uuid primary key references public.profiles (id) on delete cascade,
  account_type text not null check (account_type in ('institution', 'elpis')),
  label text not null default '' check (char_length(label) <= 80),
  verified_at timestamptz not null default now()
);

create table if not exists public.follows (
  follower_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  following_id uuid not null references public.profiles (id) on delete cascade,
  status text not null default 'pending' check (status in ('active', 'pending')),
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),
  check (follower_id <> following_id)
);
create index if not exists follows_following_idx on public.follows (following_id, status);

create table if not exists public.blocks (
  blocker_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  blocked_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
create index if not exists blocks_blocked_idx on public.blocks (blocked_id);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  target_type text not null check (target_type in ('post', 'comment', 'message', 'user')),
  target_id text not null check (char_length(target_id) between 1 and 64),
  reason text not null check (char_length(reason) between 1 and 60),
  details text not null default '' check (char_length(details) <= 500),
  created_at timestamptz not null default now()
);

-- Who can message me: 'following' (default) or 'everyone'. Under 18 is always 'following'.
alter table public.private_profiles add column if not exists dm_policy text not null default 'following';
alter table public.private_profiles drop constraint if exists private_profiles_dm_policy_check;
alter table public.private_profiles add constraint private_profiles_dm_policy_check check (dm_policy in ('following', 'everyone'));

-- ─────────────────────────────────────────────────────────────
-- 3. Relationship helpers (security definer, so rules don't loop through each other)
-- ─────────────────────────────────────────────────────────────
create or replace function public.blocked_between(a uuid, b uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.blocks where (blocker_id = a and blocked_id = b) or (blocker_id = b and blocked_id = a));
$$;

create or replace function public.follows_active(follower uuid, target uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.follows where follower_id = follower and following_id = target and status = 'active');
$$;

-- Can the signed-in user see this person's profile?
create or replace function public.can_see_profile(target uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select target = auth.uid() or (
    auth.uid() is not null
    and not public.blocked_between(auth.uid(), target)
    and exists (
      select 1 from public.profiles p
      where p.id = target
        and (
          p.is_minor = false
          -- a minor is visible to people they follow (or asked to follow) and to followers they approved
          or exists (select 1 from public.follows f where f.follower_id = target and f.following_id = auth.uid())
          or public.follows_active(auth.uid(), target)
        )
    )
  );
$$;

-- Followers / following counts for a profile you can see (active follows only).
create or replace function public.follow_counts(target uuid)
returns table (followers integer, following integer)
language sql stable security definer set search_path = ''
as $$
  select
    (select count(*)::int from public.follows where following_id = target and status = 'active'),
    (select count(*)::int from public.follows where follower_id = target and status = 'active')
  where public.can_see_profile(target);
$$;

-- The people you blocked (their profiles are hidden from you, so this returns just names for the Blocked list).
create or replace function public.my_blocks()
returns table (id uuid, name text, username text, blocked_at timestamptz)
language sql stable security definer set search_path = ''
as $$
  select p.id, p.name, p.username, b.created_at
  from public.blocks b join public.profiles p on p.id = b.blocked_id
  where b.blocker_id = auth.uid()
  order by b.created_at desc;
$$;
revoke all on function public.my_blocks() from public, anon;
grant execute on function public.my_blocks() to authenticated;

revoke all on function public.blocked_between(uuid, uuid), public.follows_active(uuid, uuid), public.can_see_profile(uuid), public.follow_counts(uuid) from public, anon;
grant execute on function public.blocked_between(uuid, uuid), public.follows_active(uuid, uuid), public.can_see_profile(uuid), public.follow_counts(uuid) to authenticated;
revoke all on function public.age_from_birth(text) from public, anon;
grant execute on function public.age_from_birth(text) to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 4. Triggers: the database decides, not the app
-- ─────────────────────────────────────────────────────────────

-- Under 18 is worked out from the saved birth date and always private.
create or replace function public.profiles_guard()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare age integer;
begin
  select public.age_from_birth(birth) into age from public.private_profiles where id = new.id;
  if age is not null then new.is_minor := age < 18; end if;
  if new.is_minor then new.is_private := true; end if;
  return new;
end;
$$;
drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before insert or update on public.profiles
  for each row execute function public.profiles_guard();

-- Minors can't choose 'everyone' for who can message them.
create or replace function public.private_profiles_guard()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare age integer;
begin
  age := public.age_from_birth(new.birth);
  if new.dm_policy = 'everyone' and (age < 18 or exists (select 1 from public.profiles where id = new.id and is_minor)) then
    raise exception 'Under 18, only people you follow and verified institutions can message you.';
  end if;
  return new;
end;
$$;
drop trigger if exists private_profiles_guard on public.private_profiles;
create trigger private_profiles_guard before insert or update on public.private_profiles
  for each row execute function public.private_profiles_guard();

-- When the birth date changes, refresh the public "under 18" flag (profiles_guard recomputes it).
create or replace function public.private_profiles_sync_age()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if public.age_from_birth(new.birth) is not null then
    update public.profiles set updated_at = now() where id = new.id;
  end if;
  return new;
end;
$$;
drop trigger if exists private_profiles_sync_age on public.private_profiles;
create trigger private_profiles_sync_age after insert or update of birth on public.private_profiles
  for each row execute function public.private_profiles_sync_age();

-- New follows: blocked → refused; rate-limited; status decided by the database.
create or replace function public.follows_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare target_locked boolean;
begin
  if new.follower_id is distinct from auth.uid() then raise exception 'You can only follow as yourself.'; end if;
  if public.blocked_between(new.follower_id, new.following_id) then raise exception 'You can’t follow this account.'; end if;
  if public.rate_limited('follows', 'follower_id', new.follower_id, interval '1 hour', 60) then
    raise exception 'You’re following too fast. Try again in a little while.';
  end if;
  select (p.is_minor or p.is_private) into target_locked from public.profiles p where p.id = new.following_id;
  if target_locked is null then raise exception 'Account not found.'; end if;
  new.status := case when target_locked then 'pending' else 'active' end;
  new.created_at := now();
  return new;
end;
$$;
drop trigger if exists follows_before_insert on public.follows;
create trigger follows_before_insert before insert on public.follows
  for each row execute function public.follows_before_insert();

-- Approving: only the person being followed, only pending → active, nothing else changes.
create or replace function public.follows_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if new.follower_id <> old.follower_id or new.following_id <> old.following_id or new.created_at <> old.created_at then
    raise exception 'Only the request status can change.';
  end if;
  if auth.uid() is not null and auth.uid() <> old.following_id then raise exception 'Only the person being followed can approve.'; end if;
  if new.status <> 'active' then raise exception 'A request can only be approved.'; end if;
  return new;
end;
$$;
drop trigger if exists follows_before_update on public.follows;
create trigger follows_before_update before update on public.follows
  for each row execute function public.follows_before_update();

-- Blocking removes follows both ways.
create or replace function public.blocks_after_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  delete from public.follows
  where (follower_id = new.blocker_id and following_id = new.blocked_id)
     or (follower_id = new.blocked_id and following_id = new.blocker_id);
  return new;
end;
$$;
drop trigger if exists blocks_after_insert on public.blocks;
create trigger blocks_after_insert after insert on public.blocks
  for each row execute function public.blocks_after_insert();

create or replace function public.blocks_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if public.rate_limited('blocks', 'blocker_id', new.blocker_id, interval '1 hour', 60) then
    raise exception 'Too many blocks at once. Try again in a little while.';
  end if;
  new.created_at := now();
  return new;
end;
$$;
drop trigger if exists blocks_before_insert on public.blocks;
create trigger blocks_before_insert before insert on public.blocks
  for each row execute function public.blocks_before_insert();

create or replace function public.reports_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if public.rate_limited('reports', 'reporter_id', new.reporter_id, interval '1 hour', 20) then
    raise exception 'You’ve sent a lot of reports. Try again in a little while.';
  end if;
  new.created_at := now();
  return new;
end;
$$;
drop trigger if exists reports_before_insert on public.reports;
create trigger reports_before_insert before insert on public.reports
  for each row execute function public.reports_before_insert();

-- Turning "Private account" off approves everyone who asked to follow.
create or replace function public.profiles_after_unprivate()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if old.is_private and not new.is_private and not new.is_minor then
    update public.follows set status = 'active' where following_id = new.id and status = 'pending';
  end if;
  return new;
end;
$$;
drop trigger if exists profiles_after_unprivate on public.profiles;
create trigger profiles_after_unprivate after update of is_private on public.profiles
  for each row execute function public.profiles_after_unprivate();

revoke all on function public.profiles_guard(), public.private_profiles_guard(), public.private_profiles_sync_age(), public.follows_before_insert(), public.follows_before_update(), public.blocks_after_insert(), public.blocks_before_insert(), public.reports_before_insert(), public.profiles_after_unprivate() from public, anon, authenticated;

-- ─────────────────────────────────────────────────────────────
-- 5. Row-level security
-- ─────────────────────────────────────────────────────────────
alter table public.verified_accounts enable row level security;
alter table public.follows enable row level security;
alter table public.blocks enable row level security;
alter table public.reports enable row level security;

-- Profiles (replaces the rule from setup.sql): adults to everyone signed in, minors only to the
-- people they follow and the followers they approved; never between people who blocked each other.
drop policy if exists "profiles: read" on public.profiles;
create policy "profiles: read" on public.profiles
  for select to authenticated
  using (public.can_see_profile(id));

-- Posts (replaces the rule from setup.sql).
drop policy if exists "posts: read" on public.posts;
create policy "posts: read" on public.posts
  for select to authenticated
  using (
    author_id = (select auth.uid())
    or (
      not public.blocked_between((select auth.uid()), author_id)
      and (
        -- active followers (approved for private and under-18 accounts) see every audience
        public.follows_active((select auth.uid()), author_id)
        or (
          exists (select 1 from public.profiles a where a.id = author_id and a.is_minor = false and a.is_private = false)
          and (audience = 'Everyone' or (audience = 'My college' and public.same_school(author_id)))
        )
      )
    )
  );

drop policy if exists "verified: read" on public.verified_accounts;
create policy "verified: read" on public.verified_accounts
  for select to authenticated
  using (true);

drop policy if exists "follows: read own" on public.follows;
create policy "follows: read own" on public.follows
  for select to authenticated
  using (follower_id = (select auth.uid()) or following_id = (select auth.uid()));
drop policy if exists "follows: follow as yourself" on public.follows;
create policy "follows: follow as yourself" on public.follows
  for insert to authenticated
  with check (follower_id = (select auth.uid()));
drop policy if exists "follows: approve requests to you" on public.follows;
create policy "follows: approve requests to you" on public.follows
  for update to authenticated
  using (following_id = (select auth.uid()))
  with check (following_id = (select auth.uid()));
drop policy if exists "follows: unfollow or decline" on public.follows;
create policy "follows: unfollow or decline" on public.follows
  for delete to authenticated
  using (follower_id = (select auth.uid()) or following_id = (select auth.uid()));

drop policy if exists "blocks: read own" on public.blocks;
create policy "blocks: read own" on public.blocks
  for select to authenticated
  using (blocker_id = (select auth.uid()));
drop policy if exists "blocks: add own" on public.blocks;
create policy "blocks: add own" on public.blocks
  for insert to authenticated
  with check (blocker_id = (select auth.uid()));
drop policy if exists "blocks: remove own" on public.blocks;
create policy "blocks: remove own" on public.blocks
  for delete to authenticated
  using (blocker_id = (select auth.uid()));

-- Reports: insert only. Nobody reads them through the app (Ygor uses the Table Editor).
drop policy if exists "reports: send as yourself" on public.reports;
create policy "reports: send as yourself" on public.reports
  for insert to authenticated
  with check (reporter_id = (select auth.uid()));

revoke all on public.verified_accounts, public.follows, public.blocks, public.reports from anon, authenticated;
grant select on public.verified_accounts to authenticated;
grant select, insert, delete on public.follows to authenticated;
grant update (status) on public.follows to authenticated;
grant select, insert, delete on public.blocks to authenticated;
grant insert on public.reports to authenticated;

-- Done. You should see "Success. No rows returned."

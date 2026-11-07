-- Elpis database setup
-- Paste this whole file into Supabase → SQL Editor → New query, then click Run.
-- Safe to run again: it only creates what is missing and refreshes the security rules.

-- ─────────────────────────────────────────────────────────────
-- 1. Public profile: what other signed-in students can see
-- ─────────────────────────────────────────────────────────────
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  name text not null default '' check (char_length(name) <= 60),
  username text unique check (username ~ '^[a-z0-9._]{2,24}$'),
  bio text not null default '' check (char_length(bio) <= 160),
  status text not null default 'New to Elpis' check (char_length(status) <= 60),
  role text not null default '' check (char_length(role) <= 60),
  school text not null default '' check (char_length(school) <= 80),
  major text not null default '' check (char_length(major) <= 60),
  goal text not null default '' check (char_length(goal) <= 60),
  term text not null default '' check (char_length(term) <= 40),
  targets text not null default '' check (char_length(targets) <= 120),
  languages text not null default '' check (char_length(languages) <= 120),
  interests jsonb not null default '{}'::jsonb,
  looking jsonb not null default '{}'::jsonb,
  is_minor boolean not null default false,
  is_private boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.profiles add column if not exists is_private boolean not null default true;

-- ─────────────────────────────────────────────────────────────
-- 2. Private info: only the owner can read or change it
-- ─────────────────────────────────────────────────────────────
create table if not exists public.private_profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null default '' check (char_length(email) <= 120),
  phone text not null default '' check (char_length(phone) <= 30),
  birth text not null default '' check (char_length(birth) <= 10),
  residency text not null default 'Prefer not to say' check (char_length(residency) <= 60),
  financial text not null default 'Prefer not to say' check (char_length(financial) <= 60),
  settings jsonb not null default '{}'::jsonb,
  plan jsonb not null default '{}'::jsonb,
  saved_colleges jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

-- ─────────────────────────────────────────────────────────────
-- 3. Community posts and likes
-- ─────────────────────────────────────────────────────────────
create table if not exists public.posts (
  id text primary key default gen_random_uuid()::text check (char_length(id) between 1 and 64),
  author_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  text text not null default '' check (char_length(text) <= 2000),
  topic text not null default 'General' check (char_length(topic) <= 40),
  audience text not null default 'Everyone' check (audience in ('Everyone', 'My college', 'Followers')),
  media jsonb not null default '[]'::jsonb check (jsonb_typeof(media) = 'array' and jsonb_array_length(media) <= 6),
  created_at timestamptz not null default now()
);
create index if not exists posts_created_at_idx on public.posts (created_at desc);

create table if not exists public.likes (
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  post_id text not null references public.posts (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, post_id)
);
create index if not exists likes_post_id_idx on public.likes (post_id);

-- ─────────────────────────────────────────────────────────────
-- 4. New accounts get an empty profile automatically
-- ─────────────────────────────────────────────────────────────
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  base text;
begin
  base := lower(regexp_replace(split_part(coalesce(new.email, ''), '@', 1), '[^a-zA-Z0-9._]', '', 'g'));
  if char_length(base) < 2 then base := 'student'; end if;
  base := left(base, 18) || substr(md5(random()::text), 1, 4);
  insert into public.profiles (id, name, username)
  values (new.id, left(coalesce(new.raw_user_meta_data ->> 'name', ''), 60), base)
  on conflict (id) do nothing;
  insert into public.private_profiles (id, email)
  values (new.id, left(coalesce(new.email, ''), 120))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Helper for "My college" posts: true when you and the author list the same school.
create or replace function public.same_school(other uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles me, public.profiles them
    where me.id = auth.uid()
      and them.id = other
      and me.school <> ''
      and lower(me.school) = lower(them.school)
  );
$$;
revoke all on function public.same_school(uuid) from public, anon;
grant execute on function public.same_school(uuid) to authenticated;

-- "Delete account" in Settings: removes the signed-in user and everything linked to them.
-- (The app deletes their uploaded files first.)
create or replace function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Not signed in';
  end if;
  delete from auth.users where id = auth.uid();
end;
$$;
revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 5. Row-level security: who can see and change what
-- ─────────────────────────────────────────────────────────────
alter table public.profiles enable row level security;
alter table public.private_profiles enable row level security;
alter table public.posts enable row level security;
alter table public.likes enable row level security;

-- Profiles: signed-in users see adults' profiles; under-18 profiles stay private to their owner.
drop policy if exists "profiles: read" on public.profiles;
create policy "profiles: read" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or is_minor = false);
drop policy if exists "profiles: create own" on public.profiles;
create policy "profiles: create own" on public.profiles
  for insert to authenticated
  with check (id = (select auth.uid()));
drop policy if exists "profiles: update own" on public.profiles;
create policy "profiles: update own" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- Private info: owner only.
drop policy if exists "private: read own" on public.private_profiles;
create policy "private: read own" on public.private_profiles
  for select to authenticated
  using (id = (select auth.uid()));
drop policy if exists "private: create own" on public.private_profiles;
create policy "private: create own" on public.private_profiles
  for insert to authenticated
  with check (id = (select auth.uid()));
drop policy if exists "private: update own" on public.private_profiles;
create policy "private: update own" on public.private_profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- Posts: you always see your own. Other people's posts show only when the author is 18+ and has
-- "Private account" off: Everyone posts to all signed-in users, My college posts to the same school.
-- Followers posts stay with the author until following exists. You can only write and delete your own.
drop policy if exists "posts: read" on public.posts;
create policy "posts: read" on public.posts
  for select to authenticated
  using (
    author_id = (select auth.uid())
    or (
      exists (
        select 1 from public.profiles a
        where a.id = author_id and a.is_minor = false and a.is_private = false
      )
      and (
        audience = 'Everyone'
        or (audience = 'My college' and public.same_school(author_id))
      )
    )
  );
drop policy if exists "posts: create own" on public.posts;
create policy "posts: create own" on public.posts
  for insert to authenticated
  with check (author_id = (select auth.uid()));
drop policy if exists "posts: update own" on public.posts;
create policy "posts: update own" on public.posts
  for update to authenticated
  using (author_id = (select auth.uid()))
  with check (author_id = (select auth.uid()));
drop policy if exists "posts: delete own" on public.posts;
create policy "posts: delete own" on public.posts
  for delete to authenticated
  using (author_id = (select auth.uid()));

-- Likes: see likes on posts you can see; add or remove only your own.
drop policy if exists "likes: read" on public.likes;
create policy "likes: read" on public.likes
  for select to authenticated
  using (exists (select 1 from public.posts p where p.id = post_id));
drop policy if exists "likes: add own" on public.likes;
create policy "likes: add own" on public.likes
  for insert to authenticated
  with check (user_id = (select auth.uid()) and exists (select 1 from public.posts p where p.id = post_id));
drop policy if exists "likes: remove own" on public.likes;
create policy "likes: remove own" on public.likes
  for delete to authenticated
  using (user_id = (select auth.uid()));

-- Only signed-in users can reach these tables at all (nothing for anonymous visitors).
revoke all on public.profiles, public.private_profiles, public.posts, public.likes from anon, authenticated;
grant usage on schema public to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update on public.private_profiles to authenticated;
grant select, insert, update, delete on public.posts to authenticated;
grant select, insert, delete on public.likes to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 6. Uploads: a private bucket; each user writes only to their own folder
-- ─────────────────────────────────────────────────────────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'post-media', 'post-media', false, 52428800,
  array[
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif',
    'video/mp4', 'video/quicktime', 'video/webm',
    'application/pdf', 'text/plain',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ]
)
on conflict (id) do nothing;

drop policy if exists "Elpis media: upload to own folder" on storage.objects;
create policy "Elpis media: upload to own folder" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'post-media' and (storage.foldername(name))[1] = (select auth.uid())::text);
drop policy if exists "Elpis media: signed-in users can view" on storage.objects;
create policy "Elpis media: signed-in users can view" on storage.objects
  for select to authenticated
  using (bucket_id = 'post-media');
drop policy if exists "Elpis media: delete own" on storage.objects;
create policy "Elpis media: delete own" on storage.objects
  for delete to authenticated
  using (bucket_id = 'post-media' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- Done. You should see "Success. No rows returned."

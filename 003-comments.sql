-- Elpis 003: comments on posts (replies, comment likes, turning comments off)
-- Run AFTER setup.sql and 002-social.sql: Supabase → SQL Editor → New query → paste → Run.
-- Safe to run again.

-- ─────────────────────────────────────────────────────────────
-- 1. Tables
-- ─────────────────────────────────────────────────────────────
alter table public.posts add column if not exists comments_off boolean not null default false;

create table if not exists public.comments (
  id text primary key check (char_length(id) between 1 and 64),
  post_id text not null references public.posts (id) on delete cascade,
  author_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  parent_id text references public.comments (id) on delete cascade,
  text text not null check (char_length(text) between 1 and 1000),
  created_at timestamptz not null default now(),
  edited_at timestamptz
);
create index if not exists comments_post_idx on public.comments (post_id, created_at);
create index if not exists comments_author_idx on public.comments (author_id, created_at);
create index if not exists comments_parent_idx on public.comments (parent_id);

create table if not exists public.comment_likes (
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  comment_id text not null references public.comments (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, comment_id)
);
create index if not exists comment_likes_comment_idx on public.comment_likes (comment_id);

-- ─────────────────────────────────────────────────────────────
-- 2. Who may comment on a post (security definer: reads profiles and follows directly)
-- ─────────────────────────────────────────────────────────────
create or replace function public.can_comment_on(p_post text)
returns boolean
language plpgsql stable security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  author uuid;
  author_minor boolean;
  off boolean;
  i_am_minor boolean;
begin
  if me is null then return false; end if;
  select p.author_id, p.comments_off into author, off from public.posts p where p.id = p_post;
  if author is null or off then return false; end if;
  if public.blocked_between(me, author) then return false; end if;
  if author = me then return true; end if;
  -- You must be able to see the post (same rule as "posts: read" in 002-social.sql).
  if not (
    public.follows_active(me, author)
    or exists (
      select 1 from public.posts p join public.profiles a on a.id = p.author_id
      where p.id = p_post and a.is_minor = false and a.is_private = false
        and (p.audience = 'Everyone' or (p.audience = 'My college' and public.same_school(p.author_id)))
    )
  ) then return false; end if;
  select a.is_minor into author_minor from public.profiles a where a.id = author;
  if author_minor then
    -- Under 18: only approved followers; adults also need the minor to follow them.
    if not public.follows_active(me, author) then return false; end if;
    select m.is_minor into i_am_minor from public.profiles m where m.id = me;
    if not coalesce(i_am_minor, false) and not public.follows_active(author, me) then return false; end if;
  end if;
  return true;
end;
$$;
revoke all on function public.can_comment_on(text) from public, anon;
grant execute on function public.can_comment_on(text) to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 3. Triggers
-- ─────────────────────────────────────────────────────────────
create or replace function public.comments_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare parent_post text; parent_parent text;
begin
  if new.author_id is distinct from auth.uid() then raise exception 'You can only comment as yourself.'; end if;
  if (select comments_off from public.posts where id = new.post_id) then raise exception 'Comments are turned off for this post.'; end if;
  if not public.can_comment_on(new.post_id) then raise exception 'You can’t comment on this post.'; end if;
  if public.rate_limited('comments', 'author_id', new.author_id, interval '1 minute', 10)
     or public.rate_limited('comments', 'author_id', new.author_id, interval '1 day', 200) then
    raise exception 'You’re commenting too fast. Try again in a minute.';
  end if;
  if new.parent_id is not null then
    select post_id, parent_id into parent_post, parent_parent from public.comments where id = new.parent_id;
    if parent_post is distinct from new.post_id then raise exception 'Replies must be on the same post.'; end if;
    -- one level only: a reply to a reply joins the same thread
    if parent_parent is not null then new.parent_id := parent_parent; end if;
  end if;
  new.created_at := now();
  new.edited_at := null;
  return new;
end;
$$;
drop trigger if exists comments_before_insert on public.comments;
create trigger comments_before_insert before insert on public.comments
  for each row execute function public.comments_before_insert();

-- Edits: only the text, only by the author, only within 15 minutes.
create or replace function public.comments_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if new.id <> old.id or new.post_id <> old.post_id or new.author_id <> old.author_id
     or new.parent_id is distinct from old.parent_id or new.created_at <> old.created_at then
    raise exception 'Only the comment text can change.';
  end if;
  if auth.uid() is distinct from old.author_id then raise exception 'You can only edit your own comments.'; end if;
  if now() - old.created_at > interval '15 minutes' then raise exception 'Comments can only be edited for 15 minutes.'; end if;
  new.edited_at := now();
  return new;
end;
$$;
drop trigger if exists comments_before_update on public.comments;
create trigger comments_before_update before update on public.comments
  for each row execute function public.comments_before_update();

create or replace function public.comment_likes_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if public.rate_limited('comment_likes', 'user_id', new.user_id, interval '1 minute', 60) then
    raise exception 'Slow down a little and try again.';
  end if;
  new.created_at := now();
  return new;
end;
$$;
drop trigger if exists comment_likes_before_insert on public.comment_likes;
create trigger comment_likes_before_insert before insert on public.comment_likes
  for each row execute function public.comment_likes_before_insert();

revoke all on function public.comments_before_insert(), public.comments_before_update(), public.comment_likes_before_insert() from public, anon, authenticated;

-- ─────────────────────────────────────────────────────────────
-- 4. Row-level security
-- ─────────────────────────────────────────────────────────────
alter table public.comments enable row level security;
alter table public.comment_likes enable row level security;

-- Read a comment only if you can read its post, and never between people who blocked each other.
drop policy if exists "comments: read" on public.comments;
create policy "comments: read" on public.comments
  for select to authenticated
  using (
    exists (select 1 from public.posts p where p.id = post_id)
    and not public.blocked_between((select auth.uid()), author_id)
  );
drop policy if exists "comments: add" on public.comments;
create policy "comments: add" on public.comments
  for insert to authenticated
  with check (author_id = (select auth.uid()) and public.can_comment_on(post_id));
drop policy if exists "comments: edit own" on public.comments;
create policy "comments: edit own" on public.comments
  for update to authenticated
  using (author_id = (select auth.uid()))
  with check (author_id = (select auth.uid()));
-- The comment's author or the post's author can delete it.
drop policy if exists "comments: delete" on public.comments;
create policy "comments: delete" on public.comments
  for delete to authenticated
  using (
    author_id = (select auth.uid())
    or exists (select 1 from public.posts p where p.id = post_id and p.author_id = (select auth.uid()))
  );

drop policy if exists "comment likes: read" on public.comment_likes;
create policy "comment likes: read" on public.comment_likes
  for select to authenticated
  using (exists (select 1 from public.comments c where c.id = comment_id));
drop policy if exists "comment likes: add own" on public.comment_likes;
create policy "comment likes: add own" on public.comment_likes
  for insert to authenticated
  with check (user_id = (select auth.uid()) and exists (select 1 from public.comments c where c.id = comment_id));
drop policy if exists "comment likes: remove own" on public.comment_likes;
create policy "comment likes: remove own" on public.comment_likes
  for delete to authenticated
  using (user_id = (select auth.uid()));

revoke all on public.comments, public.comment_likes from anon, authenticated;
grant select, insert, delete on public.comments to authenticated;
grant update (text) on public.comments to authenticated;
grant select, insert, delete on public.comment_likes to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 5. Reading helpers (run with your own permissions, so all rules above still apply)
-- ─────────────────────────────────────────────────────────────
-- Comment counts for many posts in one request.
create or replace function public.comment_counts(ids text[])
returns table (post_id text, n integer)
language sql stable security invoker set search_path = ''
as $$
  select c.post_id, count(*)::int from public.comments c where c.post_id = any(ids) group by c.post_id;
$$;

-- "Ana commented on your post", "Ben replied to your comment", "Ana liked your comment".
create or replace function public.comment_activity(since timestamptz default now() - interval '30 days')
returns table (kind text, actor_id uuid, actor_name text, post_id text, comment_id text, at timestamptz)
language sql stable security invoker set search_path = ''
as $$
  select 'comment', c.author_id, coalesce(a.name, ''), c.post_id, c.id, c.created_at
  from public.comments c join public.posts p on p.id = c.post_id left join public.profiles a on a.id = c.author_id
  where p.author_id = auth.uid() and c.author_id <> auth.uid() and c.parent_id is null and c.created_at > since
  union all
  select 'reply', r.author_id, coalesce(a.name, ''), r.post_id, r.id, r.created_at
  from public.comments r join public.comments mine on mine.id = r.parent_id left join public.profiles a on a.id = r.author_id
  where mine.author_id = auth.uid() and r.author_id <> auth.uid() and r.created_at > since
  union all
  select 'like', l.user_id, coalesce(a.name, ''), c.post_id, c.id, l.created_at
  from public.comment_likes l join public.comments c on c.id = l.comment_id left join public.profiles a on a.id = l.user_id
  where c.author_id = auth.uid() and l.user_id <> auth.uid() and l.created_at > since
  order by 6 desc
  limit 50;
$$;
revoke all on function public.comment_counts(text[]), public.comment_activity(timestamptz) from public, anon;
grant execute on function public.comment_counts(text[]), public.comment_activity(timestamptz) to authenticated;

-- Done. You should see "Success. No rows returned."

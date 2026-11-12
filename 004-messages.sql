-- Elpis 004: direct messages (one-to-one chats, message requests, photos and documents)
-- Run AFTER setup.sql, 002-social.sql and 003-comments.sql: Supabase → SQL Editor → New query → paste → Run.
-- Safe to run again. Messages are private between the two people and stored by Elpis (not end-to-end encrypted).

-- ─────────────────────────────────────────────────────────────
-- 1. Tables
-- ─────────────────────────────────────────────────────────────
create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  created_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  last_message_at timestamptz not null default now()
);
create index if not exists conversations_created_by_idx on public.conversations (created_by, created_at);

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  state text not null default 'active' check (state in ('active', 'request')),
  last_read_at timestamptz not null default now(),
  muted boolean not null default false,
  hidden boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index if not exists conversation_members_user_idx on public.conversation_members (user_id);

create table if not exists public.messages (
  id text primary key check (char_length(id) between 1 and 64),
  conversation_id uuid not null references public.conversations (id) on delete cascade,
  sender_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  text text not null default '' check (char_length(text) <= 2000),
  media jsonb not null default '[]'::jsonb check (jsonb_typeof(media) = 'array' and jsonb_array_length(media) <= 4),
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (deleted_at is not null or char_length(text) > 0 or jsonb_array_length(media) > 0)
);
create index if not exists messages_conversation_idx on public.messages (conversation_id, created_at desc);
create index if not exists messages_sender_idx on public.messages (sender_id, created_at);

-- ─────────────────────────────────────────────────────────────
-- 2. Helpers (security definer so the rules can look across tables without looping)
-- ─────────────────────────────────────────────────────────────
create or replace function public.is_member(conv uuid, who uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.conversation_members where conversation_id = conv and user_id = who);
$$;

-- Same, for storage paths ("<conversation id>/<file id>"); false for anything that isn't a uuid.
create or replace function public.is_member_path(folder text)
returns boolean
language plpgsql stable security definer set search_path = ''
as $$
begin
  if folder is null or folder !~ '^[0-9a-f-]{36}$' then return false; end if;
  return public.is_member(folder::uuid, auth.uid());
end;
$$;

create or replace function public.is_verified(who uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$ select exists (select 1 from public.verified_accounts where id = who); $$;

-- Can `sender` message `receiver`?  'active' = straight to Chats, 'request' = lands in their Requests,
-- or why not: 'self', 'blocked', 'minor' (under 18 and doesn't follow you), 'missing'.
create or replace function public.dm_rule(sender uuid, receiver uuid)
returns text
language plpgsql stable security definer set search_path = ''
as $$
declare minor boolean; pol text;
begin
  if sender is null or receiver is null then return 'missing'; end if;
  if sender = receiver then return 'self'; end if;
  select is_minor into minor from public.profiles where id = receiver;
  if minor is null then return 'missing'; end if;
  if public.blocked_between(sender, receiver) then return 'blocked'; end if;
  if minor then
    if public.follows_active(receiver, sender) or public.is_verified(sender) then return 'active'; end if;
    return 'minor';
  end if;
  select dm_policy into pol from public.private_profiles where id = receiver;
  if coalesce(pol, 'following') = 'everyone' or public.follows_active(receiver, sender) or public.is_verified(sender) then return 'active'; end if;
  return 'request';
end;
$$;

-- What the app shows before you start typing (dm_rule for the signed-in user).
create or replace function public.can_message(other uuid)
returns text
language sql stable security definer set search_path = ''
as $$ select public.dm_rule(auth.uid(), other); $$;

-- The only way to create a chat. Returns the existing one when there is one.
create or replace function public.start_conversation(other uuid)
returns uuid
language plpgsql volatile security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  rule text;
  conv uuid;
  made integer;
begin
  if me is null then raise exception 'Not signed in'; end if;
  rule := public.dm_rule(me, other);
  if rule = 'minor' then raise exception 'You can message them after they follow you.'; end if;
  if rule in ('blocked', 'self', 'missing') then raise exception 'You can’t message this account.'; end if;
  select a.conversation_id into conv
  from public.conversation_members a join public.conversation_members b on b.conversation_id = a.conversation_id
  where a.user_id = me and b.user_id = other
  limit 1;
  if conv is not null then
    update public.conversation_members set hidden = false where conversation_id = conv and user_id = me;
    return conv;
  end if;
  select count(*) into made from public.conversations where created_by = me and created_at > now() - interval '1 day';
  if made >= 10 then raise exception 'You’ve started a lot of new chats today. Try again tomorrow.'; end if;
  insert into public.conversations (created_by) values (me) returning id into conv;
  insert into public.conversation_members (conversation_id, user_id, state) values (conv, me, 'active');
  insert into public.conversation_members (conversation_id, user_id, state, last_read_at) values (conv, other, rule, 'epoch');
  return conv;
end;
$$;

-- ─────────────────────────────────────────────────────────────
-- 3. Triggers
-- ─────────────────────────────────────────────────────────────
create or replace function public.messages_before_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  my_state text;
  other uuid;
  other_state text;
  rule text;
  sent integer;
begin
  if new.sender_id is distinct from me then raise exception 'You can only send as yourself.'; end if;
  select state into my_state from public.conversation_members where conversation_id = new.conversation_id and user_id = me;
  if my_state is null then raise exception 'You’re not in this chat.'; end if;
  if my_state <> 'active' then raise exception 'Accept this message request to reply.'; end if;
  select user_id, state into other, other_state from public.conversation_members where conversation_id = new.conversation_id and user_id <> me limit 1;
  rule := public.dm_rule(me, other);
  if rule = 'blocked' or rule = 'missing' then raise exception 'You can’t message this account.'; end if;
  if rule = 'minor' then raise exception 'You can message them after they follow you.'; end if;
  if other_state = 'request' then
    select count(*) into sent from public.messages where conversation_id = new.conversation_id and sender_id = me;
    if sent >= 1 then raise exception 'You can send one message until they accept your request.'; end if;
  end if;
  if public.rate_limited('messages', 'sender_id', me, interval '1 minute', 30) then
    raise exception 'You’re sending messages too fast. Try again in a minute.';
  end if;
  new.created_at := now();
  new.deleted_at := null;
  return new;
end;
$$;
drop trigger if exists messages_before_insert on public.messages;
create trigger messages_before_insert before insert on public.messages
  for each row execute function public.messages_before_insert();

create or replace function public.messages_after_insert()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  update public.conversation_members set hidden = false where conversation_id = new.conversation_id;
  update public.conversation_members set last_read_at = new.created_at where conversation_id = new.conversation_id and user_id = new.sender_id;
  return new;
end;
$$;
drop trigger if exists messages_after_insert on public.messages;
create trigger messages_after_insert after insert on public.messages
  for each row execute function public.messages_after_insert();

-- "Delete" = your own message, within 1 hour; the text and files are cleared for both people.
create or replace function public.messages_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if auth.uid() is distinct from old.sender_id then raise exception 'You can only delete your own messages.'; end if;
  if new.id <> old.id or new.conversation_id <> old.conversation_id or new.sender_id <> old.sender_id or new.created_at <> old.created_at
     or new.text <> old.text or new.media <> old.media then
    raise exception 'Messages can’t be edited.';
  end if;
  if old.deleted_at is not null or new.deleted_at is null then raise exception 'Messages can only be deleted.'; end if;
  if now() - old.created_at > interval '1 hour' then raise exception 'Messages can only be deleted for 1 hour.'; end if;
  new.deleted_at := now();
  new.text := '';
  new.media := '[]'::jsonb;
  return new;
end;
$$;
drop trigger if exists messages_before_update on public.messages;
create trigger messages_before_update before update on public.messages
  for each row execute function public.messages_before_update();

-- Your own chat settings only: read time, mute, hide, and accepting a request.
create or replace function public.members_before_update()
returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  -- Updates made by the database itself (from the message trigger) skip these checks.
  if pg_trigger_depth() > 1 then return new; end if;
  if auth.uid() is distinct from old.user_id then raise exception 'You can only change your own chat settings.'; end if;
  if new.conversation_id <> old.conversation_id or new.user_id <> old.user_id or new.created_at <> old.created_at then
    raise exception 'Only your chat settings can change.';
  end if;
  if new.state <> old.state and not (old.state = 'request' and new.state = 'active') then raise exception 'A request can only be accepted.'; end if;
  if new.last_read_at > now() then new.last_read_at := now(); end if;
  return new;
end;
$$;
drop trigger if exists members_before_update on public.conversation_members;
create trigger members_before_update before update on public.conversation_members
  for each row execute function public.members_before_update();

revoke all on function public.messages_before_insert(), public.messages_after_insert(), public.messages_before_update(), public.members_before_update() from public, anon, authenticated;
revoke all on function public.is_member(uuid, uuid), public.is_member_path(text), public.is_verified(uuid), public.dm_rule(uuid, uuid), public.can_message(uuid), public.start_conversation(uuid) from public, anon, authenticated;
grant execute on function public.is_member(uuid, uuid), public.is_member_path(text), public.can_message(uuid), public.start_conversation(uuid) to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 4. Row-level security: only the two members, ever
-- ─────────────────────────────────────────────────────────────
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

drop policy if exists "conversations: members read" on public.conversations;
create policy "conversations: members read" on public.conversations
  for select to authenticated using (public.is_member(id, (select auth.uid())));

drop policy if exists "members: members read" on public.conversation_members;
create policy "members: members read" on public.conversation_members
  for select to authenticated using (public.is_member(conversation_id, (select auth.uid())));
drop policy if exists "members: change own settings" on public.conversation_members;
create policy "members: change own settings" on public.conversation_members
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists "messages: members read" on public.messages;
create policy "messages: members read" on public.messages
  for select to authenticated using (public.is_member(conversation_id, (select auth.uid())));
drop policy if exists "messages: send" on public.messages;
create policy "messages: send" on public.messages
  for insert to authenticated
  with check (sender_id = (select auth.uid()) and public.is_member(conversation_id, (select auth.uid())));
drop policy if exists "messages: delete own" on public.messages;
create policy "messages: delete own" on public.messages
  for update to authenticated
  using (sender_id = (select auth.uid()))
  with check (sender_id = (select auth.uid()));

revoke all on public.conversations, public.conversation_members, public.messages from anon, authenticated;
grant select on public.conversations to authenticated;
grant select on public.conversation_members to authenticated;
grant update (last_read_at, muted, hidden, state) on public.conversation_members to authenticated;
grant select, insert on public.messages to authenticated;
grant update (deleted_at) on public.messages to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 5. Inbox in one call (your chats, the other person, last message, unread count)
-- ─────────────────────────────────────────────────────────────
create or replace function public.dm_inbox()
returns table (
  conversation_id uuid, other_id uuid, other_name text, other_username text, other_role text,
  my_state text, other_state text, muted boolean, hidden boolean,
  last_text text, last_media integer, last_kind text, last_sender uuid, last_deleted boolean, last_at timestamptz,
  unread integer, other_read_at timestamptz
)
language sql stable security definer set search_path = ''
as $$
  select m.conversation_id, o.user_id, coalesce(p.name, ''), coalesce(p.username, ''), coalesce(p.role, ''),
         m.state, o.state, m.muted, m.hidden,
         lm.text, coalesce(jsonb_array_length(lm.media), 0), coalesce(lm.media -> 0 ->> 'kind', ''), lm.sender_id, lm.deleted_at is not null, coalesce(lm.created_at, c.created_at),
         (select count(*)::int from public.messages x where x.conversation_id = m.conversation_id and x.sender_id <> auth.uid() and x.created_at > m.last_read_at and x.deleted_at is null),
         o.last_read_at
  from public.conversation_members m
  join public.conversations c on c.id = m.conversation_id
  join public.conversation_members o on o.conversation_id = m.conversation_id and o.user_id <> m.user_id
  left join public.profiles p on p.id = o.user_id
  left join lateral (select * from public.messages y where y.conversation_id = m.conversation_id order by y.created_at desc limit 1) lm on true
  where m.user_id = auth.uid()
  order by coalesce(lm.created_at, c.created_at) desc;
$$;
create or replace function public.dm_unread_count()
returns integer
language sql stable security definer set search_path = ''
as $$
  select count(*)::int from public.messages x
  join public.conversation_members m on m.conversation_id = x.conversation_id and m.user_id = auth.uid()
  where x.sender_id <> auth.uid() and x.created_at > m.last_read_at and x.deleted_at is null and m.state = 'active' and not m.hidden;
$$;
revoke all on function public.dm_inbox(), public.dm_unread_count() from public, anon;
grant execute on function public.dm_inbox(), public.dm_unread_count() to authenticated;

-- ─────────────────────────────────────────────────────────────
-- 6. Files: a private bucket; only the two members can upload and read, only the sender deletes
-- ─────────────────────────────────────────────────────────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'dm-media', 'dm-media', false, 10485760,
  array[
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif',
    'application/pdf',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ]
)
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "DM files: members upload" on storage.objects;
create policy "DM files: members upload" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'dm-media' and public.is_member_path((storage.foldername(name))[1]));
drop policy if exists "DM files: members read" on storage.objects;
create policy "DM files: members read" on storage.objects
  for select to authenticated
  using (bucket_id = 'dm-media' and public.is_member_path((storage.foldername(name))[1]));
drop policy if exists "DM files: sender deletes" on storage.objects;
create policy "DM files: sender deletes" on storage.objects
  for delete to authenticated
  using (bucket_id = 'dm-media' and owner = (select auth.uid()));

-- Done. You should see "Success. No rows returned."

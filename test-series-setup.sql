-- CA PrepX · Test Series. Adds new tables only; nothing existing is changed.
create table if not exists public.ts_teachers(
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text, name text, subjects text[] not null default '{}', added_at timestamptz not null default now());
create table if not exists public.ts_enrol(
  email text primary key check (email = lower(email)),
  name text, level text not null check (level in ('foundation','inter','final')),
  plan text, added_at timestamptz not null default now());
create table if not exists public.ts_tests(
  id uuid primary key default gen_random_uuid(),
  level text not null check (level in ('foundation','inter','final')),
  paper text not null, title text not null,
  kind text not null check (kind in ('mcq','desc')),
  duration_min int not null check (duration_min between 5 and 600),
  max_marks numeric not null check (max_marks > 0),
  n_questions int check (n_questions between 1 and 300),
  marks_per_q numeric not null default 1, negative numeric not null default 0,
  q_marks jsonb, opens_at timestamptz not null default now(), closes_at timestamptz,
  paper_path text, status text not null default 'draft' check (status in ('draft','published')),
  created_by uuid, created_name text, created_at timestamptz not null default now());
create table if not exists public.ts_keys(
  test_id uuid primary key references public.ts_tests(id) on delete cascade,
  answer_key text not null);
create table if not exists public.ts_attempts(
  id uuid primary key default gen_random_uuid(),
  test_id uuid not null references public.ts_tests(id) on delete cascade,
  user_id uuid not null, student_name text, student_email text,
  started_at timestamptz not null default now(), submitted_at timestamptz, late boolean not null default false,
  answers jsonb, score numeric, max_marks numeric, result jsonb, file_path text,
  status text not null default 'started' check (status in ('started','submitted','checked')),
  checker_id uuid, checker_name text, q_marks jsonb, remarks text, checked_path text, checked_at timestamptz,
  unique (test_id, user_id));
create index if not exists ts_attempts_user on public.ts_attempts(user_id);

create or replace function public.ts_email() returns text language sql stable as
$$ select lower(coalesce(auth.jwt() ->> 'email','')) $$;
create or replace function public.ts_my_level() returns text language sql stable security definer set search_path = public as
$$ select level from public.ts_enrol where email = public.ts_email() and public.ts_email() <> '' $$;
create or replace function public.ts_enrolled(lv text) returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.ts_enrol where email = public.ts_email() and public.ts_email() <> '' and level = lv) $$;
create or replace function public.ts_is_teacher() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.ts_teachers where user_id = auth.uid()) $$;
create or replace function public.ts_teaches(lv text, pp text) returns boolean language sql stable security definer set search_path = public as
$$ select public.is_admin() or exists (select 1 from public.ts_teachers where user_id = auth.uid() and (lv || ':' || pp) = any(subjects)) $$;
create or replace function public.ts_teaches_test(t uuid) returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.ts_tests x where x.id = t and public.ts_teaches(x.level, x.paper)) $$;

alter table public.ts_teachers enable row level security;
alter table public.ts_enrol enable row level security;
alter table public.ts_tests enable row level security;
alter table public.ts_keys enable row level security;
alter table public.ts_attempts enable row level security;

drop policy if exists "ts teachers read" on public.ts_teachers;
create policy "ts teachers read" on public.ts_teachers for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists "ts enrol read" on public.ts_enrol;
create policy "ts enrol read" on public.ts_enrol for select using (public.is_admin() or email = public.ts_email());
drop policy if exists "ts enrol admin" on public.ts_enrol;
create policy "ts enrol admin" on public.ts_enrol for all using (public.is_admin()) with check (public.is_admin());
drop policy if exists "ts tests read" on public.ts_tests;
create policy "ts tests read" on public.ts_tests for select using (public.ts_teaches(level, paper) or (status = 'published' and public.ts_enrolled(level)));
drop policy if exists "ts tests write" on public.ts_tests;
create policy "ts tests write" on public.ts_tests for all using (public.ts_teaches(level, paper)) with check (public.ts_teaches(level, paper));
drop policy if exists "ts keys teachers" on public.ts_keys;
create policy "ts keys teachers" on public.ts_keys for all using (public.ts_teaches_test(test_id)) with check (public.ts_teaches_test(test_id));
drop policy if exists "ts attempts read" on public.ts_attempts;
create policy "ts attempts read" on public.ts_attempts for select using (user_id = auth.uid() or public.ts_teaches_test(test_id));
drop policy if exists "ts attempts mark" on public.ts_attempts;
create policy "ts attempts mark" on public.ts_attempts for update using (public.ts_teaches_test(test_id)) with check (public.ts_teaches_test(test_id));
drop policy if exists "ts attempts admin delete" on public.ts_attempts;
create policy "ts attempts admin delete" on public.ts_attempts for delete using (public.is_admin());

-- admin: add / update / remove a teacher and the subjects they handle
create or replace function public.ts_set_teacher(p_email text, p_name text, p_subjects text[]) returns text
language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  if not public.is_admin() then raise exception 'Only admins can manage teachers'; end if;
  select id into uid from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if uid is null then return 'not_found'; end if;
  insert into public.ts_teachers(user_id,email,name,subjects) values (uid, lower(trim(p_email)), nullif(trim(coalesce(p_name,'')),''), coalesce(p_subjects,'{}'))
  on conflict (user_id) do update set subjects = excluded.subjects, name = coalesce(excluded.name, public.ts_teachers.name);
  return 'ok';
end $$;
create or replace function public.ts_remove_teacher(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only admins can manage teachers'; end if;
  delete from public.ts_teachers where user_id = p_user;
end $$;

-- student: start a test (the clock starts on the server)
create or replace function public.ts_start(p_test uuid) returns public.ts_attempts
language plpgsql security definer set search_path = public as $$
declare t public.ts_tests; a public.ts_attempts; nm text;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select * into t from public.ts_tests where id = p_test;
  if t.id is null or t.status <> 'published' then raise exception 'Test not found'; end if;
  if not public.ts_enrolled(t.level) then raise exception 'This test series is for enrolled students'; end if;
  select * into a from public.ts_attempts where test_id = p_test and user_id = auth.uid();
  if a.id is not null then return a; end if;
  if t.opens_at > now() then raise exception 'This test is not open yet'; end if;
  if t.closes_at is not null and t.closes_at < now() then raise exception 'This test has closed'; end if;
  select coalesce(e.name, p.name) into nm from public.ts_enrol e left join public.profiles p on p.id = auth.uid() where e.email = public.ts_email();
  insert into public.ts_attempts(test_id,user_id,student_name,student_email,max_marks)
  values (p_test, auth.uid(), nm, public.ts_email(), t.max_marks) returning * into a;
  return a;
end $$;

-- student: submit an MCQ test; marking happens here so the answer key never reaches the browser first
create or replace function public.ts_submit_mcq(p_test uuid, p_answers jsonb) returns public.ts_attempts
language plpgsql security definer set search_path = public as $$
declare t public.ts_tests; a public.ts_attempts; k text; i int; ans text; kc text;
  sc numeric := 0; nc int := 0; nw int := 0; nb int := 0; det jsonb := '[]'::jsonb;
begin
  select * into a from public.ts_attempts where test_id = p_test and user_id = auth.uid();
  if a.id is null then raise exception 'Start the test first'; end if;
  if a.status <> 'started' then return a; end if;
  select * into t from public.ts_tests where id = p_test;
  if t.kind <> 'mcq' then raise exception 'Not an MCQ test'; end if;
  select upper(answer_key) into k from public.ts_keys where test_id = p_test;
  if k is null then raise exception 'Answer key missing. Tell your teacher.'; end if;
  for i in 1..t.n_questions loop
    ans := upper(nullif(trim(coalesce(p_answers ->> i::text,'')),''));
    kc := nullif(substr(k, i, 1), '');
    if kc is null or kc not in ('A','B','C','D') then
      det := det || jsonb_build_object('q',i,'a',ans,'k',null,'ok',null);
    elsif ans is null then nb := nb + 1; det := det || jsonb_build_object('q',i,'a',null,'k',kc,'ok',null);
    elsif ans = kc then nc := nc + 1; sc := sc + t.marks_per_q; det := det || jsonb_build_object('q',i,'a',ans,'k',kc,'ok',true);
    else nw := nw + 1; sc := sc - t.negative; det := det || jsonb_build_object('q',i,'a',ans,'k',kc,'ok',false);
    end if;
  end loop;
  update public.ts_attempts set answers = p_answers, score = sc, max_marks = t.max_marks,
    result = jsonb_build_object('correct',nc,'wrong',nw,'blank',nb,'detail',det),
    submitted_at = now(), checked_at = now(), status = 'checked',
    late = now() > a.started_at + make_interval(mins => t.duration_min + 2)
  where id = a.id returning * into a;
  return a;
end $$;

-- student: hand in the single answer PDF for a descriptive test
create or replace function public.ts_submit_desc(p_test uuid, p_path text) returns public.ts_attempts
language plpgsql security definer set search_path = public as $$
declare t public.ts_tests; a public.ts_attempts;
begin
  select * into a from public.ts_attempts where test_id = p_test and user_id = auth.uid();
  if a.id is null then raise exception 'Start the test first'; end if;
  if a.status = 'checked' then raise exception 'This paper is already checked'; end if;
  select * into t from public.ts_tests where id = p_test;
  if t.kind <> 'desc' then raise exception 'Not a descriptive test'; end if;
  if p_path <> 'answers/' || auth.uid()::text || '/' || p_test::text || '.pdf' then raise exception 'Bad file path'; end if;
  update public.ts_attempts set file_path = p_path, status = 'submitted',
    submitted_at = coalesce(submitted_at, now()),
    late = coalesce(submitted_at, now()) > a.started_at + make_interval(mins => t.duration_min + 20)
  where id = a.id returning * into a;
  return a;
end $$;

revoke all on function public.ts_set_teacher(text,text,text[]), public.ts_remove_teacher(uuid), public.ts_start(uuid), public.ts_submit_mcq(uuid,jsonb), public.ts_submit_desc(uuid,text) from public, anon;
grant execute on function public.ts_set_teacher(text,text,text[]), public.ts_remove_teacher(uuid), public.ts_start(uuid), public.ts_submit_mcq(uuid,jsonb), public.ts_submit_desc(uuid,text) to authenticated;

-- private file store for question papers, student answers and checked sheets
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('test-series','test-series', false, 26214400, array['application/pdf'])
on conflict (id) do nothing;
drop policy if exists "ts files read" on storage.objects;
create policy "ts files read" on storage.objects for select using (bucket_id = 'test-series' and (
  public.is_admin() or public.ts_is_teacher()
  or ((storage.foldername(name))[1] = 'answers' and (storage.foldername(name))[2] = auth.uid()::text)
  or ((storage.foldername(name))[1] = 'papers' and exists (select 1 from public.ts_tests t where t.paper_path = name and t.status = 'published' and t.opens_at <= now() and public.ts_enrolled(t.level)))
  or ((storage.foldername(name))[1] = 'checked' and exists (select 1 from public.ts_attempts a where a.checked_path = name and a.user_id = auth.uid()))));
drop policy if exists "ts files upload" on storage.objects;
create policy "ts files upload" on storage.objects for insert with check (bucket_id = 'test-series' and (
  ((storage.foldername(name))[1] = 'answers' and (storage.foldername(name))[2] = auth.uid()::text and public.ts_my_level() is not null)
  or ((storage.foldername(name))[1] in ('papers','checked') and (public.is_admin() or public.ts_is_teacher()))));
drop policy if exists "ts files replace" on storage.objects;
create policy "ts files replace" on storage.objects for update using (bucket_id = 'test-series' and (
  ((storage.foldername(name))[1] = 'answers' and (storage.foldername(name))[2] = auth.uid()::text)
  or ((storage.foldername(name))[1] in ('papers','checked') and (public.is_admin() or public.ts_is_teacher()))));
drop policy if exists "ts files delete" on storage.objects;
create policy "ts files delete" on storage.objects for delete using (bucket_id = 'test-series' and (
  public.is_admin() or ((storage.foldername(name))[1] in ('papers','checked') and public.ts_is_teacher())));

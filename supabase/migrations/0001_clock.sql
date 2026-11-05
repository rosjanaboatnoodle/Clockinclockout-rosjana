-- ระบบตอกบัตร (Clockinclockout)
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).
--
-- ใช้ Supabase project เดียวกับปฏิทิน (Calendarsver2) ได้ ตาราง branches / staff / translations /
-- app_settings ใช้ร่วมกัน ถ้ายังไม่มี (ร้านที่ใช้แค่ตอกบัตร) ไฟล์นี้จะสร้างให้ รันซ้ำได้ไม่เสียหาย

create extension if not exists pgcrypto;

create or replace function crypt_hash(plain text)
returns text language sql as $$
  select crypt(plain, gen_salt('bf'));
$$;

create or replace function crypt_check(plain text, hash text)
returns boolean language sql as $$
  select crypt(plain, hash) = hash;
$$;

-- ---------- ตารางที่ใช้ร่วมกับปฏิทิน (สร้างเฉพาะถ้ายังไม่มี) ----------

create table if not exists app_settings (
  key         text primary key,
  value       jsonb not null,
  updated_at  timestamptz not null default now()
);

create table if not exists admin_log (
  id          bigserial primary key,
  created_at  timestamptz not null default now(),
  action      text not null,
  details     jsonb not null default '{}'
);

create table if not exists branches (
  id              text primary key,
  name            text not null,
  sort            int not null default 0,
  admin_pin_hash  text,
  sync_sheet      boolean not null default false,
  created_at      timestamptz not null default now()
);

create table if not exists staff (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  name        text not null,
  label       text not null default '',
  short       text not null default '',
  active      boolean not null default true,
  sort        int not null default 0,
  created_at  timestamptz not null default now(),
  unique (branch_id, name)
);

create table if not exists translations (
  key         text primary key,
  th          text not null default '',
  en          text not null default '',
  my          text not null default '',
  lo          text not null default '',
  km          text not null default '',
  vi          text not null default '',
  edited      text[] not null default '{}',
  updated_at  timestamptz not null default now()
);

-- ---------- ตอกบัตร ----------

-- PIN ตอกบัตรของพนักงาน (เก็บแบบเข้ารหัส)
alter table staff add column if not exists pin_hash text;

-- หนึ่งแถว = หนึ่งกะ (เข้างาน → ออกงาน)
create table if not exists punches (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  staff_id    bigint not null references staff(id) on delete cascade,
  work_date   date not null,                -- วันที่ของเวลาเข้างาน (ตามเวลาท้องถิ่นของร้าน)
  check_in    timestamptz not null,
  check_out   timestamptz,                  -- ว่าง = ยังทำงานอยู่
  forgot_out  boolean not null default false, -- ลืมตอกออก (ระบบปิดให้ตอนตอกเข้าวันถัดไป) รอแอดมินแก้เวลา
  edited      boolean not null default false, -- แอดมินแก้เวลาแล้ว
  note        text not null default '',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists punches_branch_date on punches (branch_id, work_date);
create index if not exists punches_staff_date on punches (staff_id, work_date);
-- พนักงานหนึ่งคนมีกะที่ยังไม่ได้ตอกออกได้แค่ 1 กะ (กันกดเข้างานซ้ำ)
create unique index if not exists punches_one_open on punches (staff_id) where check_out is null and not forgot_out;

-- Row Level Security: deny-all (ไม่มี policy = ห้ามหมด) เข้าถึงได้ผ่าน Edge Function เท่านั้น
alter table app_settings enable row level security;
alter table admin_log enable row level security;
alter table branches enable row level security;
alter table staff enable row level security;
alter table translations enable row level security;
alter table punches enable row level security;

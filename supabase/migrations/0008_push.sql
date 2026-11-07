-- แจ้งเตือนบนมือถือ (Web Push) ไม่ต้องตั้ง key เอง ระบบสร้างให้ตอนใช้ครั้งแรก
-- ต้องรัน 0007_staff_login.sql ก่อน
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

-- ตั้งค่าแจ้งเตือนของแต่ละสาขา (ว่าง = ใช้ค่าเริ่มต้น เปิดทุกอย่าง)
alter table branches add column if not exists notify jsonb not null default '{}';

-- เครื่องที่เปิดรับแจ้งเตือน
--   role staff = มือถือของพนักงาน (staff_id) / role admin = เครื่องแอดมิน (branch_id ว่าง = ทุกสาขา)
create table if not exists push_subs (
  id          bigserial primary key,
  endpoint    text not null unique,
  p256dh      text not null,
  auth        text not null,
  role        text not null check (role in ('staff', 'admin')),
  staff_id    bigint references staff(id) on delete cascade,
  branch_id   text references branches(id) on delete cascade,
  lang        text not null default 'th',
  user_agent  text not null default '',
  created_at  timestamptz not null default now(),
  last_ok     timestamptz
);

-- กันส่งซ้ำ (เช่น เตือนลืมตอกออกของกะเดียวกันครั้งเดียว)
create table if not exists push_log (
  key         text primary key,
  created_at  timestamptz not null default now()
);

alter table push_subs enable row level security;
alter table push_log enable row level security;

-- ตัวจับเวลา (เตือนก่อนเข้ากะ / ลืมตอกออก / ยังไม่มา / เวรพรุ่งนี้) ใช้ 2 ส่วนเสริมนี้
-- คำสั่งตั้งตัวจับเวลาอยู่ในหน้าแอดมิน → แท็บสาขา → 🔔 แจ้งเตือน (มีรหัสลับใส่ให้แล้ว)
create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net with schema extensions;

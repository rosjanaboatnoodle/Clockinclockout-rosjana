-- ล็อกเพิ่มต่อสาขา (ไม่บังคับ ค่าเริ่มต้นปิดทั้งคู่)
--   require_device = เครื่องใหม่ต้องให้แอดมินอนุมัติก่อน ถึงจะเปิดหน้าตอกบัตรได้
--   require_ip     = ตอกบัตรได้เฉพาะตอนต่อเน็ตของร้าน (IP ใน allowed_ips)
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

alter table branches add column if not exists require_device boolean not null default false;
alter table branches add column if not exists require_ip boolean not null default false;
alter table branches add column if not exists allowed_ips text[] not null default '{}';

-- เครื่องที่เคยเปิดหน้าตอกบัตร (เก็บไว้เสมอ เปิดล็อกแล้วจะอนุญาตเครื่องที่ใช้อยู่ได้ทีเดียว)
create table if not exists devices (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  device_id   text not null,                 -- รหัสสุ่มที่หน้าเว็บเก็บไว้ในเครื่อง
  label       text not null default '',      -- ชื่อที่พนักงานพิมพ์ หรือแอดมินตั้ง
  status      text not null default 'pending' check (status in ('pending', 'approved', 'blocked')),
  user_agent  text not null default '',
  last_ip     text not null default '',
  last_staff  text not null default '',      -- คนล่าสุดที่ตอกบัตรจากเครื่องนี้
  created_at  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  decided_at  timestamptz,
  unique (branch_id, device_id)
);

alter table devices enable row level security;

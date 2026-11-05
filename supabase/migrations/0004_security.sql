-- ขั้นความปลอดภัย: ล็อกเมื่อใส่ PIN ผิดหลายครั้ง + ลิงก์ลับประจำสาขา
-- Run this once in the Supabase Dashboard -> SQL Editor (หลังจาก 0001–0003) รันซ้ำได้ไม่เสียหาย
-- ใช้ร่วมกับปฏิทิน (Calendarsver2) ได้ ไฟล์ของปฏิทินสร้างตารางเดียวกันนี้

create extension if not exists pgcrypto;

-- นับการใส่รหัสผิด  key: admin / staff:<id> / branch:<id>
create table if not exists pin_attempts (
  key           text primary key,
  fails         int not null default 0,
  locked_until  timestamptz,
  updated_at    timestamptz not null default now()
);
alter table pin_attempts enable row level security;

-- รหัสลับในลิงก์ของแต่ละสาขา (?b=...) ไม่มีรหัสนี้ = มองไม่เห็นสาขานั้น
alter table branches add column if not exists access_key text;
update branches set access_key = encode(gen_random_bytes(8), 'hex') where access_key is null;
alter table branches alter column access_key set default encode(gen_random_bytes(8), 'hex');
create unique index if not exists branches_access_key on branches (access_key);

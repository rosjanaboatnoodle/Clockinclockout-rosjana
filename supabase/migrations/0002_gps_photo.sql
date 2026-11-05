-- ขั้นที่ 2: GPS + ถ่ายรูปตอนตอกบัตร
-- Run this once in the Supabase Dashboard -> SQL Editor (หลังจาก 0001_clock.sql) รันซ้ำได้ไม่เสียหาย

-- ตั้งค่าต่อสาขา
alter table branches add column if not exists lat double precision;        -- พิกัดร้าน
alter table branches add column if not exists lng double precision;
alter table branches add column if not exists radius_m int not null default 50;          -- รัศมีที่ตอกบัตรได้ (เมตร)
alter table branches add column if not exists require_gps boolean not null default false; -- บังคับอยู่ในรัศมี
alter table branches add column if not exists require_photo boolean not null default false; -- บังคับถ่ายรูป
alter table branches add column if not exists photo_keep_days int not null default 60;    -- เก็บรูปกี่วัน แล้วลบอัตโนมัติ

-- ตำแหน่งและรูปของแต่ละกะ (เข้า/ออก)
alter table punches add column if not exists in_lat double precision;
alter table punches add column if not exists in_lng double precision;
alter table punches add column if not exists in_accuracy_m real;
alter table punches add column if not exists in_distance_m real;
alter table punches add column if not exists in_photo text;    -- path ในที่เก็บรูป punch-photos
alter table punches add column if not exists out_lat double precision;
alter table punches add column if not exists out_lng double precision;
alter table punches add column if not exists out_accuracy_m real;
alter table punches add column if not exists out_distance_m real;
alter table punches add column if not exists out_photo text;

-- ที่เก็บรูป (ส่วนตัว เปิดดูได้ผ่านหน้าแอดมินเท่านั้น)
insert into storage.buckets (id, name, public)
values ('punch-photos', 'punch-photos', false)
on conflict (id) do nothing;

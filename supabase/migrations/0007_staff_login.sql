-- เครื่องกลางร้าน + ล็อกอินด้วยชื่อ + PIN บนมือถือส่วนตัว (ไม่บังคับ ค่าเริ่มต้นปิด)
--   staff_login = เปิดลิงก์บนมือถือส่วนตัว ต้องใส่ชื่อ + PIN ครั้งแรกก่อนถึงจะเห็นหน้า
--                 คนที่ออก (เอาติ๊ก "ใช้งานอยู่" ออก) จะเด้งออกจากทุกเครื่องทันที
--   devices.kiosk = เครื่องกลางร้าน (เช่น แท็บเล็ต) เห็นชื่อทุกคน แต่ละคนใส่ PIN ตอนตอกบัตร
-- ต้องรัน 0006_access.sql ก่อน
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

alter table branches add column if not exists staff_login boolean not null default false;

alter table devices add column if not exists kiosk boolean not null default false;
alter table devices add column if not exists staff_id bigint references staff(id) on delete set null;
alter table devices add column if not exists login_at timestamptz;

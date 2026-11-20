-- QR ติดผนัง (ไม่บังคับ ค่าเริ่มต้นปิด)
--   qr_required = ตอกเข้า/ออกได้เฉพาะตอนเปิดหน้าจากการสแกน QR ที่ร้าน (เครื่องกลางร้านไม่ต้องสแกน)
--   qr_secret   = รหัสใน QR (คนละตัวกับลิงก์สาขา) กด "เปลี่ยน QR" แล้วต้องปริ้นใหม่
--   wifi        = ชื่อ/รหัส WiFi ร้าน สำหรับ QR ต่อ WiFi บนแผ่นเดียวกัน
-- ใช้คู่กับ "ตอกบัตรได้เฉพาะตอนต่อ WiFi ของร้าน" ถึงจะกันเอารูป QR ไปสแกนที่อื่นได้
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

alter table branches add column if not exists qr_required boolean not null default false;
alter table branches add column if not exists qr_secret text;
alter table branches add column if not exists wifi jsonb not null default '{}';

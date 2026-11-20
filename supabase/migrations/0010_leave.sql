-- ขอลา: พนักงานขอลาในหน้าตอกบัตร (หรือแอดมินบันทึกแทน) หนึ่งแถวต่อหนึ่งวัน
-- วันที่ขอลาแล้ว (รอ/อนุมัติ) ไม่นับเป็น "ขาดไม่แจ้ง" ไม่เตือนเข้ากะ ไม่แจ้งว่ายังไม่มา
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

create table if not exists leaves (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  staff_id    bigint not null references staff(id) on delete cascade,
  date        date not null,
  kind        text not null default 'other' check (kind in ('sick', 'personal', 'other')),
  note        text not null default '',
  status      text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_by  text not null default 'staff',          -- staff / admin
  created_at  timestamptz not null default now(),
  decided_at  timestamptz,
  unique (staff_id, date)
);
create index if not exists leaves_branch_date on leaves (branch_id, date);

alter table leaves enable row level security;

-- นับ "ขาดไม่แจ้ง" ตั้งแต่วันนี้เป็นต้นไป ไม่นับย้อนหลังช่วงที่ยังไม่ได้ใช้ระบบ (แก้ได้ในหน้าแอดมิน แท็บลา)
alter table branches add column if not exists absent_from date default current_date;

-- ขั้นที่ 3: ค่าแรง โอที รอบตัดบิล เบิกเงิน แก้เวลาโดยแอดมิน
-- Run this once in the Supabase Dashboard -> SQL Editor (หลังจาก 0001 และ 0002) รันซ้ำได้ไม่เสียหาย

-- ค่าแรง/โอที: ค่าเริ่มต้นของสาขา และค่าเฉพาะคน (ช่องที่ไม่ได้ตั้ง = ใช้ค่าของสาขา)
--   pay_type daily|hourly, daily_rate, hourly_rate, std_hours, half_day_hours, min_day_hours,
--   ot_mode none|after_hours|after_time|both, ot_after_hours, ot_after_time (HH:MM),
--   ot_rate_type multiplier|fixed, ot_multiplier, ot_fixed_rate, ot_round_min, ot_min_min
alter table branches add column if not exists pay_defaults jsonb not null default '{}';
alter table staff add column if not exists pay jsonb not null default '{}';

-- รอบตัดบิล: ประวัติการตั้งค่า [{ "from": "YYYY-MM-DD", "cfg": {...} }]
-- เปลี่ยนรอบกลางทาง = มีผลตั้งแต่รอบถัดไป (เพิ่มรายการใหม่ ไม่ลบของเดิม)
alter table branches add column if not exists period jsonb not null default '[]';
alter table staff add column if not exists period jsonb;   -- ว่าง = ใช้รอบของสาขา

-- เบิกเงิน
alter table branches add column if not exists staff_advance boolean not null default true;  -- ให้พนักงานขอเบิกเองได้
alter table branches add column if not exists advance_auto_max numeric not null default 0;  -- อนุมัติอัตโนมัติถ้าไม่เกิน (0 = ต้องอนุมัติทุกรายการ)

create table if not exists advances (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  staff_id    bigint not null references staff(id) on delete cascade,
  date        date not null,
  amount      numeric not null check (amount > 0),
  item        text not null default '',
  status      text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_by  text not null default 'admin' check (created_by in ('admin', 'staff')),
  created_at  timestamptz not null default now(),
  decided_at  timestamptz
);
create index if not exists advances_staff_date on advances (staff_id, date);
create index if not exists advances_branch_status on advances (branch_id, status);

-- แอดมินปรับรายวัน
alter table punches add column if not exists day_override numeric;     -- 1 / 0.5 / 0 (ว่าง = คิดอัตโนมัติ)
alter table punches add column if not exists ot_override_min int;      -- นาทีโอที (ว่าง = คิดอัตโนมัติ)
alter table punches add column if not exists review_ok boolean not null default false; -- แอดมินตรวจแล้ว
alter table punches add column if not exists created_by text not null default 'staff';

-- รอบที่ปิดแล้ว (ออกบิลแล้ว) ข้อมูลในรอบนี้ถูกล็อก (ใช้ในขั้นที่ 4)
create table if not exists pay_closures (
  id            bigserial primary key,
  branch_id     text not null references branches(id) on delete cascade,
  staff_id      bigint not null references staff(id) on delete cascade,
  period_start  date not null,
  period_end    date not null,
  summary       jsonb not null default '{}',
  closed_at     timestamptz not null default now(),
  unique (staff_id, period_start)
);

alter table advances enable row level security;
alter table pay_closures enable row level security;

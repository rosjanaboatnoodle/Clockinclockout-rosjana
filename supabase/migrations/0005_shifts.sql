-- กะการทำงาน เวลาพัก มาสาย
-- Run this once in the Supabase Dashboard -> SQL Editor (หลังจาก 0001–0004) รันซ้ำได้ไม่เสียหาย
--
-- ตั้งค่าต่อคน/สาขา (อยู่ใน branches.pay_defaults และ staff.pay เหมือนค่าแรง):
--   work_mode none|flexible|shift, default_shift_id, weekday_shifts {"0".."6": shift id | "off"},
--   auto_shift, count_early, break_mode auto|punch|paid, break_min, break_after_hours,
--   break_min_deduct, break_flag_min, break_fallback_auto, late_deduct, late_after_min,
--   late_mode per_minute|fixed, late_amount

-- กะสำเร็จรูปของแต่ละสาขา (เวลาออก <= เวลาเข้า = ข้ามเที่ยงคืน)
create table if not exists shifts (
  id                 bigserial primary key,
  branch_id          text not null references branches(id) on delete cascade,
  name               text not null,
  start_time         text not null,           -- HH:MM
  end_time           text not null,           -- HH:MM
  break_mode         text check (break_mode in ('auto', 'punch', 'paid')),  -- ว่าง = ใช้ค่าของคน/สาขา
  break_min          int,
  break_after_hours  numeric,
  color              text not null default '#6366f1',
  sort               int not null default 0,
  active             boolean not null default true,
  created_at         timestamptz not null default now()
);

-- ตารางกะรายวัน (แอดมินจัด) shift_id ว่าง = วันหยุดของคนนั้น
create table if not exists shift_roster (
  staff_id   bigint not null references staff(id) on delete cascade,
  date       date not null,
  shift_id   bigint references shifts(id) on delete cascade,
  branch_id  text not null references branches(id) on delete cascade,
  primary key (staff_id, date)
);
create index if not exists shift_roster_branch_date on shift_roster (branch_id, date);

-- เวลาพักที่ตอกจริง (แบบ "ตอกพัก")
create table if not exists breaks (
  id           bigserial primary key,
  punch_id     bigint not null references punches(id) on delete cascade,
  start_at     timestamptz not null,
  end_at       timestamptz,
  auto_closed  boolean not null default false   -- ลืมกดกลับจากพัก ระบบปิดให้ตอนออกงาน
);
create index if not exists breaks_punch on breaks (punch_id);
create unique index if not exists breaks_one_open on breaks (punch_id) where end_at is null;

-- แอดมินปรับรายวัน
alter table punches add column if not exists shift_override bigint;      -- กะที่แอดมินเลือก (-1 = ไม่มีกะ, ว่าง = อัตโนมัติ)
alter table punches add column if not exists break_override_min int;     -- นาทีพักที่หัก (ว่าง = อัตโนมัติ)

alter table shifts enable row level security;
alter table shift_roster enable row level security;
alter table breaks enable row level security;

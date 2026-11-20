-- ประเมินประจำเดือน (ไม่บังคับ เปิดเองในหน้าแอดมิน แท็บประเมิน)
--   branches.eval  = การตั้งค่า (เปิด/ปิด เกณฑ์ โบนัส ระดับ ...) ว่าง = ใช้ค่าเริ่มต้น (ปิดอยู่)
--   eval_notes     = บันทึกระหว่างเดือน 👍/👎 (แอดมินจด, เช็ครายสัปดาห์, เพื่อนชม)
--   evaluations    = ผลประเมินของแต่ละคนต่อรอบเงินเดือน (คะแนน ระดับ โบนัส เหตุผลที่ใส่ในบิล)
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

alter table branches add column if not exists eval jsonb not null default '{}';

create table if not exists eval_notes (
  id             bigserial primary key,
  branch_id      text not null references branches(id) on delete cascade,
  staff_id       bigint not null references staff(id) on delete cascade,
  crit           text,                                    -- เกณฑ์ (ว่าง = คำชมจากเพื่อนที่ยังไม่ได้จัดเกณฑ์)
  sign           smallint not null default 1 check (sign in (-1, 1)),
  note           text not null default '',
  date           date not null default current_date,
  source         text not null default 'admin' check (source in ('admin', 'weekly', 'kudos')),
  from_staff_id  bigint references staff(id) on delete set null,
  status         text not null default 'ok' check (status in ('ok', 'new', 'dismissed')),
  created_at     timestamptz not null default now()
);
create index if not exists eval_notes_staff_date on eval_notes (staff_id, date);
create index if not exists eval_notes_branch_date on eval_notes (branch_id, date);

create table if not exists evaluations (
  id            bigserial primary key,
  branch_id     text not null references branches(id) on delete cascade,
  staff_id      bigint not null references staff(id) on delete cascade,
  period_start  date not null,
  period_end    date not null,
  scores        jsonb not null default '{}',   -- { เกณฑ์: 1-3 }
  total         int not null default 0,
  max           int not null default 12,
  level         int not null default 3,        -- 0 ดีมาก · 1 ดี · 2 พอใช้ · 3 ต้องปรับปรุง
  pct           int not null default 0,
  bonus_on      boolean not null default true,
  bonus_max     numeric not null default 0,
  bonus         numeric not null default 0,
  show          boolean not null default true, -- แสดงผลประเมินในบิล
  reasons       jsonb not null default '[]',   -- [{ sign, th, tr: { my: ..., en: ... }, date }]
  updated_at    timestamptz not null default now(),
  unique (staff_id, period_start)
);

alter table eval_notes enable row level security;
alter table evaluations enable row level security;

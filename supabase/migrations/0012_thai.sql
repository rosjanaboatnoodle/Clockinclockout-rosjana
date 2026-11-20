-- ข้อความที่พนักงานพิมพ์เป็นภาษาของตัวเอง (คำชมเพื่อน / เหตุผลขอลา / รายการขอเบิก)
-- ระบบแปลเป็นไทยให้แอดมินอ่าน และเก็บต้นฉบับไว้ที่ช่อง *_orig (พนักงานเห็นต้นฉบับของตัวเอง)
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

alter table eval_notes add column if not exists note_orig text not null default '';
alter table leaves add column if not exists note_orig text not null default '';
alter table advances add column if not exists item_orig text not null default '';

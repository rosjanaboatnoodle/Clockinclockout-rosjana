// Edge Function "clock" — ระบบตอกบัตร (ใช้ Supabase project เดียวกับปฏิทินได้ หรือใช้เดี่ยวๆ ก็ได้)
//
// Database: run supabase/migrations/0001_clock.sql, 0002_gps_photo.sql, 0003_pay.sql in order.
// Deploy: Supabase Dashboard -> Edge Functions -> create function named "clock" ->
// paste this file's contents -> Deploy -> แท็บ Settings -> ปิด "Verify JWT with legacy secret"
//
// Secrets (Dashboard -> Edge Functions -> Secrets):
//   GEMINI_API_KEY   key ของ Gemini สำหรับแปลภาษา (ตัวเดียวกับปฏิทิน)
//   TIMEZONE         (ไม่บังคับ) เขตเวลาของร้าน ค่าเริ่มต้น Asia/Bangkok
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are auto-injected by the platform.
//
// Every request is a POST with a JSON body: { action: "...", ...params }.
// Every response is JSON with at least an `ok` boolean.
//
// Shared with the calendar ("api" function): branches, staff, translations, app_settings
// (admin_pin_hash = the same central admin PIN). Calendar topics are read if they exist.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, authorization, apikey",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// ============================================================
// Small helpers
// ============================================================

async function logAdmin(action: string, details: Record<string, unknown> = {}) {
  await supabase.from("admin_log").insert({ action, details });
}

async function getSetting<T>(key: string, fallback: T): Promise<T> {
  const { data } = await supabase.from("app_settings").select("value").eq("key", key).maybeSingle();
  return (data?.value as T) ?? fallback;
}

async function setSetting(key: string, value: unknown) {
  await supabase.from("app_settings").upsert({ key, value, updated_at: new Date().toISOString() });
}

async function checkPassword(hash: string | null, plain: string): Promise<boolean> {
  if (!hash) return false;
  const { data, error } = await supabase.rpc("crypt_check", { plain, hash });
  if (error) { console.error("crypt_check error", error); return false; }
  return !!data;
}

async function hashPassword(plain: string): Promise<string> {
  const { data, error } = await supabase.rpc("crypt_hash", { plain });
  if (error) throw error;
  return data as string;
}

const ADMIN_PIN_KEY = "admin_pin_hash";

async function checkAdminPin(pin: string): Promise<boolean> {
  if (!pin) return false;
  return checkPassword(await getSetting<string | null>(ADMIN_PIN_KEY, null), pin);
}

function isIsoDate(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
}


async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs = 20000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw new Error(`request_timed_out_after_${timeoutMs}ms: ${url.split("?")[0]}`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================
// Translations (same table and rules as the calendar's "api" function — keep the two in step)
// One row per text, one column per language. Pages load one language at a time.
// `edited` lists languages a person corrected by hand; AI never overwrites those.
// ============================================================

const LANGS = ["en", "my", "lo", "km", "vi"] as const;
const ALL_LANGS = ["th", ...LANGS] as const;
type Lang = typeof ALL_LANGS[number];
const LANG_NAMES: Record<string, string> = {
  en: "English", my: "Burmese (Myanmar language)", lo: "Lao", km: "Khmer", vi: "Vietnamese",
};
type TranslationRow = { key: string; th: string; en: string; my: string; lo: string; km: string; vi: string; edited: string[] };

function cleanLang(v: unknown): Lang {
  const s = String(v ?? "th");
  return (ALL_LANGS as readonly string[]).includes(s) ? s as Lang : "th";
}

async function getTranslations(keys?: string[], prefix?: string): Promise<TranslationRow[]> {
  let q = supabase.from("translations").select("key, th, en, my, lo, km, vi, edited");
  if (keys) q = q.in("key", keys);
  if (prefix) q = q.like("key", `${prefix}%`);
  const { data, error } = await q;
  if (error) throw new Error(error.message);
  return (data ?? []) as TranslationRow[];
}

// key -> text in `lang`, falling back to Thai when that language is still empty.
function dictFor(rows: TranslationRow[], lang: Lang): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) out[r.key] = (r[lang] || r.th || "").toString();
  return out;
}

const GEMINI_MODEL = "gemini-2.5-flash";

async function callGeminiJson(prompt: string): Promise<unknown> {
  const apiKey = Deno.env.get("GEMINI_API_KEY");
  if (!apiKey) throw new Error("GEMINI_API_KEY not configured");
  // Key in the header, never the URL, so it can't leak into an error message.
  const res = await fetchWithTimeout(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: "application/json" } }),
    },
    90000,
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `gemini_http_${res.status}`);
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error("gemini_empty_response");
  return JSON.parse(text);
}

// Thai texts -> { key: { en, my, lo, km, vi } }. One AI call per 40 texts.
async function aiTranslate(texts: Record<string, string>): Promise<Record<string, Record<string, string>>> {
  const entries = Object.entries(texts).filter(([, th]) => th.trim());
  const out: Record<string, Record<string, string>> = {};
  for (let i = 0; i < entries.length; i += 40) {
    const chunk = Object.fromEntries(entries.slice(i, i + 40));
    const prompt = `You translate short messages for staff of a Thai restaurant (calendar, duty roster, time clock).
Translate every Thai value in this JSON into: ${LANGS.map((l) => `"${l}" = ${LANG_NAMES[l]}`).join(", ")}.
Keep placeholders like {name} exactly as they are. Keep it short, simple and friendly, the way a manager talks to staff.
Return ONLY a JSON object of the same keys, each value an object {"en":"...","my":"...","lo":"...","km":"...","vi":"..."}.

${JSON.stringify(chunk)}`;
    const result = await callGeminiJson(prompt) as Record<string, Record<string, unknown>>;
    for (const key of Object.keys(chunk)) {
      const r = result?.[key] ?? {};
      out[key] = Object.fromEntries(LANGS.map((l) => [l, String(r[l] ?? "").trim()]));
    }
  }
  return out;
}

// Admin: AI suggestions only, nothing saved. The page shows them in editable boxes first.
// texts: { key: thai }
async function handleAiTranslate(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const texts = (p.texts && typeof p.texts === "object") ? p.texts as Record<string, unknown> : {};
  const clean = Object.fromEntries(Object.entries(texts).map(([k, v]) => [k, String(v ?? "")]));
  if (Object.keys(clean).length > 200) return json({ ok: false, error: "too_many_texts" });
  try {
    return json({ ok: true, translations: await aiTranslate(clean) });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: list rows to review/edit (e.g. prefix "ui.cal.").
async function handleListTranslations(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  try {
    const rows = await getTranslations(undefined, String(p.prefix ?? ""));
    rows.sort((a, b) => a.key.localeCompare(b.key));
    return json({ ok: true, rows });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: save rows as typed. rows: [{ key, th?, en?, ..., edited?: [langs] }]
// Only the languages sent are changed; `edited` is merged in.
async function saveTranslationRows(rows: Array<Record<string, unknown>>) {
  const keys = rows.map((r) => String(r.key ?? "")).filter(Boolean);
  const existing = new Map((await getTranslations(keys)).map((r) => [r.key, r]));
  const upserts = rows.filter((r) => r.key).map((r) => {
    const key = String(r.key);
    const prev = existing.get(key);
    const row: Record<string, unknown> = { key, updated_at: new Date().toISOString() };
    for (const l of ALL_LANGS) if (r[l] !== undefined) row[l] = String(r[l] ?? "");
    for (const l of ALL_LANGS) if (row[l] === undefined) row[l] = prev?.[l] ?? "";
    const edited = new Set([...(prev?.edited ?? []), ...((r.edited as string[]) ?? [])]);
    for (const l of ((r.unedited as string[]) ?? [])) edited.delete(l);
    row.edited = [...edited].filter((l) => (LANGS as readonly string[]).includes(l));
    return row;
  });
  if (upserts.length) {
    const { error } = await supabase.from("translations").upsert(upserts);
    if (error) throw new Error(error.message);
  }
}

async function handleSaveTranslations(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  try {
    const rows = Array.isArray(p.rows) ? p.rows as Array<Record<string, unknown>> : [];
    await saveTranslationRows(rows);
    await logAdmin("save_translations", { keys: rows.map((r) => r.key) });
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: make sure every page text exists (Thai from the page), then fill the other languages
// with AI — skipping languages edited by hand, and (unless `all`) ones that already have text.
// texts: { key: thai } as written in the page source. include_topics: also every topic text.
async function handleTranslatePage(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const texts: Record<string, unknown> = { ...((p.texts && typeof p.texts === "object") ? p.texts as Record<string, unknown> : {}) };
  const all = !!p.all;
  try {
    // include_topics: also the texts of every calendar topic (Thai taken from what's saved)
    if (p.include_topics) {
      for (const r of await getTranslations(undefined, "topic.")) if (r.th.trim()) texts[r.key] = r.th;
    }
    const keys = Object.keys(texts);
    if (keys.length > 300) return json({ ok: false, error: "too_many_texts" });
    const existing = new Map((await getTranslations(keys)).map((r) => [r.key, r]));
    const todo: Record<string, string> = {};
    for (const key of keys) {
      const th = String(texts[key] ?? "");
      const prev = existing.get(key);
      const thChanged = !prev || prev.th !== th;
      const missing = LANGS.some((l) => !prev?.[l] && !(prev?.edited ?? []).includes(l));
      if (all || thChanged || missing) todo[key] = th;
    }
    const ai = await aiTranslate(todo);
    const rows = Object.entries(todo).map(([key, th]) => {
      const prev = existing.get(key);
      const thChanged = !prev || prev.th !== th;
      const row: Record<string, unknown> = { key, th };
      for (const l of LANGS) {
        const keep = (prev?.edited ?? []).includes(l) && !thChanged;
        if (!keep && ai[key]?.[l]) row[l] = ai[key][l];
      }
      // Thai source changed: earlier hand edits no longer match, so they're re-translated.
      if (thChanged) row.unedited = [...LANGS];
      return row;
    });
    await saveTranslationRows(rows);
    await logAdmin("translate_page", { count: rows.length, all });
    return json({ ok: true, translated: rows.length });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}


// ============================================================
// Time zone: every shift belongs to the shop's local date of its check-in.
// ============================================================

function shopTz(): string {
  return Deno.env.get("TIMEZONE") || "Asia/Bangkok";
}

function localDate(d: Date): string {
  // en-CA formats as YYYY-MM-DD
  return new Intl.DateTimeFormat("en-CA", { timeZone: shopTz(), year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
}

// A shift still open after this many hours is treated as "forgot to clock out" when the same
// person clocks in again, so a missed check-out never blocks the next day.
const FORGOT_OUT_HOURS = 16;

// ============================================================
// Branches and staff (shared with the calendar)
// ============================================================

function cleanId(s: string): string {
  return s.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

async function hasAdmin(): Promise<boolean> {
  return !!(await getSetting<string | null>(ADMIN_PIN_KEY, null));
}

function staffView(s: Record<string, unknown>) {
  const name = String(s.name ?? "");
  return {
    id: s.id, branch_id: s.branch_id, name,
    label: String(s.label || name), short: String(s.short || name),
  };
}

// Public, one request when the page opens: branches + staff + page texts in `lang`.
async function handleBootstrap(p: Record<string, unknown>) {
  const lang = cleanLang(p.lang);
  const [{ data: branches, error }, { data: staff }] = await Promise.all([
    supabase.from("branches").select("id, name, sort, lat, lng, radius_m, require_gps, require_photo").order("sort").order("name"),
    supabase.from("staff").select("id, branch_id, name, label, short, sort").eq("active", true).order("sort").order("name"),
  ]);
  if (error) return json({ ok: false, error: error.message });
  let dict: Record<string, string> = {};
  try {
    dict = dictFor([...await getTranslations(undefined, "ui.clock."), ...await getTranslations(undefined, "topic.")], lang);
  } catch (e) {
    console.error("bootstrap translations failed", e);
  }
  return json({
    ok: true,
    lang,
    tz: shopTz(),
    has_admin: await hasAdmin(),
    branches: (branches ?? []).map((b) => ({
      ...b,
      staff: (staff ?? []).filter((s) => s.branch_id === b.id).map(staffView),
    })),
    dict,
  });
}

// First run of a shop that has nothing yet: set the central admin PIN and the first branch.
// Refused once an admin PIN exists (the calendar import also sets it).
async function handleSetup(p: Record<string, unknown>) {
  if (await hasAdmin()) return json({ ok: false, error: "already_setup" });
  const pin = String(p.new_pin ?? "").trim();
  const name = String(p.branch_name ?? "").trim();
  const id = cleanId(String(p.branch_id ?? "") || "main") || "main";
  if (pin.length < 4) return json({ ok: false, error: "pin_too_short" });
  if (!name) return json({ ok: false, error: "missing_name" });
  const { error } = await supabase.from("branches").upsert({ id, name });
  if (error) return json({ ok: false, error: error.message });
  await setSetting(ADMIN_PIN_KEY, await hashPassword(pin));
  await logAdmin("clock_setup", { branch: id });
  return json({ ok: true, branch_id: id });
}

async function handleCheckAdminPin(p: Record<string, unknown>) {
  return json({ ok: await checkAdminPin(String(p.admin_pin ?? "")) });
}

async function handleChangeAdminPin(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const next = String(p.new_pin ?? "").trim();
  if (next.length < 4) return json({ ok: false, error: "pin_too_short" });
  await setSetting(ADMIN_PIN_KEY, await hashPassword(next));
  await logAdmin("change_admin_pin");
  return json({ ok: true });
}

// Central admin. Create or rename a branch.
async function handleSaveBranch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const name = String(p.name ?? "").trim();
  const id = cleanId(String(p.id ?? "") || name);
  if (!name) return json({ ok: false, error: "missing_name" });
  if (!id) return json({ ok: false, error: "bad_branch_id" });
  const { error } = await supabase.from("branches").upsert({ id, name });
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("save_branch", { id, name });
  return json({ ok: true, id });
}

// Central admin. Everyone in a branch, including people switched off, and whether they have a PIN.
async function handleListStaffAdmin(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data, error } = await supabase.from("staff")
    .select("id, branch_id, name, label, short, active, sort, pin_hash")
    .eq("branch_id", String(p.branch_id ?? "")).order("sort").order("name");
  if (error) return json({ ok: false, error: error.message });
  return json({
    ok: true,
    staff: (data ?? []).map((s) => ({
      id: s.id, name: s.name, label: s.label, short: s.short, active: s.active, sort: s.sort, has_pin: !!s.pin_hash,
    })),
  });
}

// Central admin. Add (no id) or update one person. pin: "" = keep, "-" = remove, else 4-6 digits.
async function handleSaveStaffMember(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const name = String(p.name ?? "").trim();
  const branchId = String(p.branch_id ?? "");
  if (!name) return json({ ok: false, error: "missing_name" });
  const row: Record<string, unknown> = {
    name,
    label: String(p.label ?? "").trim(),
    short: String(p.short ?? "").trim(),
    active: p.active === undefined ? true : !!p.active,
  };
  const pin = String(p.pin ?? "").trim();
  if (pin === "-") row.pin_hash = null;
  else if (pin) {
    if (!/^\d{4,6}$/.test(pin)) return json({ ok: false, error: "pin_digits" });
    row.pin_hash = await hashPassword(pin);
  }
  const id = Number(p.id) || 0;
  let res;
  if (id) {
    res = await supabase.from("staff").update(row).eq("id", id).select("id").maybeSingle();
  } else {
    if (!branchId) return json({ ok: false, error: "unknown_branch" });
    const { data: all } = await supabase.from("staff").select("sort").eq("branch_id", branchId);
    row.branch_id = branchId;
    row.sort = Math.max(-1, ...(all ?? []).map((s) => s.sort ?? 0)) + 1;
    res = await supabase.from("staff").insert(row).select("id").maybeSingle();
  }
  if (res.error) {
    const dup = String(res.error.message).includes("duplicate") || res.error.code === "23505";
    return json({ ok: false, error: dup ? "duplicate_name" : res.error.message });
  }
  await logAdmin("save_staff_member", { id: id || res.data?.id, name, pin_changed: !!pin });
  return json({ ok: true, id: id || res.data?.id });
}

// ============================================================
// Punching in and out
// ============================================================

type Punch = {
  id: number; branch_id: string; staff_id: number; work_date: string;
  check_in: string; check_out: string | null; forgot_out: boolean; edited: boolean; note: string;
};

// Today's shifts for a branch, plus anyone still on a shift that started earlier (overnight).
async function todayPunches(branchId: string): Promise<Punch[]> {
  const today = localDate(new Date());
  const [{ data: todays }, { data: open }] = await Promise.all([
    supabase.from("punches").select("*").eq("branch_id", branchId).eq("work_date", today).order("check_in"),
    supabase.from("punches").select("*").eq("branch_id", branchId).is("check_out", null).eq("forgot_out", false),
  ]);
  const byId = new Map<number, Punch>();
  for (const r of [...(open ?? []), ...(todays ?? [])] as Punch[]) byId.set(r.id, r);
  return [...byId.values()].sort((a, b) => a.check_in.localeCompare(b.check_in));
}

// Calendar messages for a branch and date in one language. Empty if the calendar isn't installed.
async function calendarMessages(branchId: string, date: string, lang: Lang) {
  try {
    const [{ data: entries, error: e1 }, { data: topics, error: e2 }] = await Promise.all([
      supabase.from("schedule_entries").select("topic_id, person").eq("branch_id", branchId).eq("date", date),
      supabase.from("topics").select("id, color, kind, sort").eq("active", true).order("sort"),
    ]);
    if (e1 || e2 || !entries?.length) return [];
    const rows = await getTranslations(undefined, "topic.");
    const text = (key: string) => { const r = rows.find((x) => x.key === key); return r ? (r[lang] || r.th || "") : ""; };
    const out = [];
    for (const t of topics ?? []) {
      for (const e of entries.filter((x) => x.topic_id === t.id)) {
        const fill = (s: string) => s.split("{name}").join(e.person ?? "");
        out.push({
          topic_id: t.id, color: t.color, person: e.person ?? null,
          name: text(`topic.${t.id}.name`),
          message: fill(text(`topic.${t.id}.message`) || text(`topic.${t.id}.name`)),
        });
      }
    }
    return out;
  } catch {
    return [];
  }
}

// Public: today's list and today's calendar messages for the branch.
async function handleToday(p: Record<string, unknown>) {
  const branchId = String(p.branch ?? "");
  if (!branchId) return json({ ok: false, error: "missing_branch" });
  const lang = cleanLang(p.lang);
  const [punches, messages] = await Promise.all([
    todayPunches(branchId),
    calendarMessages(branchId, localDate(new Date()), lang),
  ]);
  return json({ ok: true, date: localDate(new Date()), punches: punches.map(publicPunch), messages });
}

function publicPunch(r: Punch) {
  return { id: r.id, staff_id: r.staff_id, work_date: r.work_date, check_in: r.check_in, check_out: r.check_out, forgot_out: r.forgot_out };
}

// ============================================================
// GPS and photos
// ============================================================

const PHOTO_BUCKET = "punch-photos";
const MAX_PHOTO_BYTES = 600 * 1024;  // the page shrinks photos to ~50-150 KB; this is only a safety cap
const MAX_GPS_ACCURACY_M = 100;      // weaker readings than this are refused (ask to try again)

// Distance in metres between two points on Earth.
function distanceM(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371000, rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad, dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

type BranchGeo = { id: string; lat: number | null; lng: number | null; radius_m: number; require_gps: boolean; require_photo: boolean };

// Checks the reported position against the branch. Returns the fields to store, or an error code.
function checkLocation(branch: BranchGeo, p: Record<string, unknown>):
  { ok: true; lat: number | null; lng: number | null; accuracy: number | null; distance: number | null } |
  { ok: false; error: string; distance?: number; radius?: number; accuracy?: number } {
  const lat = Number(p.lat), lng = Number(p.lng), accuracy = Number(p.accuracy);
  const has = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180 && !(lat === 0 && lng === 0);
  const shopSet = branch.lat !== null && branch.lng !== null;
  const distance = has && shopSet ? Math.round(distanceM(lat, lng, branch.lat as number, branch.lng as number)) : null;
  if (branch.require_gps && shopSet) {
    if (!has) return { ok: false, error: "gps_required" };
    if (Number.isFinite(accuracy) && accuracy > MAX_GPS_ACCURACY_M) return { ok: false, error: "gps_weak", accuracy: Math.round(accuracy) };
    if ((distance as number) > branch.radius_m) return { ok: false, error: "out_of_area", distance: distance as number, radius: branch.radius_m };
  }
  return { ok: true, lat: has ? lat : null, lng: has ? lng : null, accuracy: has && Number.isFinite(accuracy) ? Math.round(accuracy) : null, distance };
}

// photo: "data:image/jpeg;base64,..." -> stored file path
async function savePhoto(branchId: string, staffId: number, type: string, photo: string, now: Date): Promise<string> {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(photo);
  if (!m) throw new Error("bad_photo");
  const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  if (bytes.length > MAX_PHOTO_BYTES) throw new Error("photo_too_large");
  const ext = m[1] === "jpeg" ? "jpg" : m[1];
  const path = `${branchId}/${localDate(now)}/${staffId}-${type}-${now.getTime()}.${ext}`;
  const { error } = await supabase.storage.from(PHOTO_BUCKET).upload(path, bytes, { contentType: `image/${m[1]}`, upsert: false });
  if (error) throw new Error("photo_upload_failed: " + error.message);
  return path;
}

// Public with the person's own PIN. type: "in" | "out"
// Optional: lat, lng, accuracy (metres) and photo (data URL), required when the branch asks for them.
async function handlePunch(p: Record<string, unknown>) {
  const branchId = String(p.branch ?? "");
  const staffId = Number(p.staff_id) || 0;
  const type = p.type === "out" ? "out" : "in";
  const pin = String(p.pin ?? "").trim();
  const lang = cleanLang(p.lang);
  if (!/^\d{4,6}$/.test(pin)) return json({ ok: false, error: "pin_invalid" });

  const { data: person } = await supabase.from("staff")
    .select("id, branch_id, name, active, pin_hash").eq("id", staffId).maybeSingle();
  if (!person || !person.active || person.branch_id !== branchId) return json({ ok: false, error: "unknown_staff" });
  if (!person.pin_hash) return json({ ok: false, error: "no_pin" });
  if (!(await checkPassword(person.pin_hash, pin))) return json({ ok: false, error: "wrong_pin" });

  const { data: branch } = await supabase.from("branches")
    .select("id, lat, lng, radius_m, require_gps, require_photo").eq("id", branchId).maybeSingle();
  if (!branch) return json({ ok: false, error: "unknown_branch" });
  const loc = checkLocation(branch as BranchGeo, p);
  if (!loc.ok) return json(loc);
  const photo = String(p.photo ?? "");
  if (branch.require_photo && !photo) return json({ ok: false, error: "photo_required" });

  const now = new Date();
  const { data: openRows } = await supabase.from("punches").select("*")
    .eq("staff_id", staffId).is("check_out", null).eq("forgot_out", false);
  const open = (openRows ?? [])[0] as Punch | undefined;

  let status: string;
  let punch: Punch;
  if (type === "in") {
    if (open) {
      const hours = (now.getTime() - Date.parse(open.check_in)) / 3600000;
      if (hours < FORGOT_OUT_HOURS) return json({ ok: false, error: "already_in", check_in: open.check_in });
      // Forgot to clock out last time: close it as "forgot" for the admin to fix, then continue.
      await supabase.from("punches").update({ forgot_out: true, updated_at: now.toISOString() }).eq("id", open.id);
    }
    let photoPath: string | null = null;
    if (photo) {
      try { photoPath = await savePhoto(branchId, staffId, "in", photo, now); }
      catch (e) { return json({ ok: false, error: String((e as Error).message) }); }
    }
    const { data, error } = await supabase.from("punches").insert({
      branch_id: branchId, staff_id: staffId, work_date: localDate(now), check_in: now.toISOString(),
      in_lat: loc.lat, in_lng: loc.lng, in_accuracy_m: loc.accuracy, in_distance_m: loc.distance, in_photo: photoPath,
    }).select("*").maybeSingle();
    if (error) {
      // Two taps at once: the unique "one open shift" index stops the second one.
      if (error.code === "23505" || String(error.message).includes("duplicate")) return json({ ok: false, error: "already_in" });
      return json({ ok: false, error: error.message });
    }
    punch = data as Punch;
    status = open ? "ok_in_after_forgot" : "ok_in";
  } else {
    if (!open) return json({ ok: false, error: "not_in" });
    let photoPath: string | null = null;
    if (photo) {
      try { photoPath = await savePhoto(branchId, staffId, "out", photo, now); }
      catch (e) { return json({ ok: false, error: String((e as Error).message) }); }
    }
    const { data, error } = await supabase.from("punches")
      .update({
        check_out: now.toISOString(), updated_at: now.toISOString(),
        out_lat: loc.lat, out_lng: loc.lng, out_accuracy_m: loc.accuracy, out_distance_m: loc.distance, out_photo: photoPath,
      })
      .eq("id", open.id).is("check_out", null).select("*").maybeSingle();
    if (error) return json({ ok: false, error: error.message });
    if (!data) return json({ ok: false, error: "not_in" });
    punch = data as Punch;
    status = "ok_out";
  }
  const distance = loc.distance;

  const [punches, messages] = await Promise.all([
    todayPunches(branchId),
    calendarMessages(branchId, localDate(now), lang),
  ]);
  return json({
    ok: true, status, punch: publicPunch(punch), staff_name: person.name, distance,
    punches: punches.map(publicPunch), messages,
  });
}

// Central admin. Shifts of a branch between two dates (inclusive), for the admin page.
async function handlePunchesRange(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const branchId = String(p.branch_id ?? "");
  const from = String(p.from ?? "");
  const to = String(p.to ?? from);
  if (!isIsoDate(from) || !isIsoDate(to)) return json({ ok: false, error: "bad_date" });
  await cleanupOldPhotos();
  const { data, error } = await supabase.from("punches").select("*")
    .eq("branch_id", branchId).gte("work_date", from).lte("work_date", to).order("work_date").order("check_in");
  if (error) return json({ ok: false, error: error.message });
  const rows = (data ?? []) as Array<Record<string, unknown>>;
  // Short-lived links to the photos (the bucket is private)
  const paths = rows.flatMap((r) => [r.in_photo, r.out_photo]).filter(Boolean) as string[];
  const urls = new Map<string, string>();
  if (paths.length) {
    const { data: signed } = await supabase.storage.from(PHOTO_BUCKET).createSignedUrls(paths, 3600);
    for (const s of signed ?? []) if (s.path && s.signedUrl) urls.set(s.path, s.signedUrl);
  }
  return json({
    ok: true,
    punches: rows.map((r) => ({
      ...withLocal(r as PunchRow),
      flags: flagsOf(r as PunchRow),
      in_photo_url: r.in_photo ? urls.get(String(r.in_photo)) ?? null : null,
      out_photo_url: r.out_photo ? urls.get(String(r.out_photo)) ?? null : null,
    })),
  });
}

// Deletes photos older than each branch's photo_keep_days. Runs at most once a day, from the admin page.
async function cleanupOldPhotos() {
  try {
    const today = localDate(new Date());
    if ((await getSetting<string | null>("photo_cleanup_date", null)) === today) return;
    await setSetting("photo_cleanup_date", today);
    const { data: branches } = await supabase.from("branches").select("id, photo_keep_days");
    for (const b of branches ?? []) {
      const keep = Math.max(1, Number(b.photo_keep_days) || 60);
      const cutoff = localDate(new Date(Date.now() - keep * 86400000));
      for (const field of ["in_photo", "out_photo"]) {
        const { data: old } = await supabase.from("punches").select(`id, ${field}`)
          .eq("branch_id", b.id).lt("work_date", cutoff).not(field, "is", null).limit(500);
        const list = (old ?? []) as Array<Record<string, unknown>>;
        if (!list.length) continue;
        await supabase.storage.from(PHOTO_BUCKET).remove(list.map((r) => String(r[field])));
        await supabase.from("punches").update({ [field]: null }).in("id", list.map((r) => r.id));
      }
    }
  } catch (e) {
    console.error("photo cleanup failed", e);
  }
}

// Central admin. Location, radius and photo rules of a branch.
async function handleSaveBranchSettings(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const id = String(p.id ?? "");
  const num = (v: unknown) => (v === "" || v === null || v === undefined) ? null : Number(v);
  const lat = num(p.lat), lng = num(p.lng);
  if ((lat === null) !== (lng === null)) return json({ ok: false, error: "bad_location" });
  if (lat !== null && (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng as number) > 180)) {
    return json({ ok: false, error: "bad_location" });
  }
  const radius = Math.round(Number(p.radius_m));
  if (!Number.isFinite(radius) || radius < 5 || radius > 5000) return json({ ok: false, error: "bad_radius" });
  if (p.require_gps && lat === null) return json({ ok: false, error: "location_needed" });
  const keep = Math.round(Number(p.photo_keep_days ?? 60));
  const row = {
    lat, lng, radius_m: radius, require_gps: !!p.require_gps, require_photo: !!p.require_photo,
    photo_keep_days: Number.isFinite(keep) ? Math.min(365, Math.max(1, keep)) : 60,
  };
  const { error } = await supabase.from("branches").update(row).eq("id", id);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("save_branch_settings", { id, ...row });
  return json({ ok: true });
}

// ============================================================
// Dates in the shop's time zone
// ============================================================

function tzOffsetMs(ts: number, tz: string): number {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(ts)).map((p) => [p.type, p.value]));
  const asUtc = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour % 24, +parts.minute, +parts.second);
  return asUtc - Math.floor(ts / 1000) * 1000;
}

// "YYYY-MM-DDTHH:MM" in the shop's time zone -> Date
function localToUtc(local: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/.exec(local);
  if (!m) return null;
  const guess = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  let ts = guess - tzOffsetMs(guess, shopTz());
  ts = guess - tzOffsetMs(ts, shopTz()); // second pass handles daylight-saving edges
  return new Date(ts);
}

// Date -> "YYYY-MM-DDTHH:MM" in the shop's time zone
function utcToLocal(iso: string | null): string | null {
  if (!iso) return null;
  const ts = Date.parse(iso);
  return new Date(ts + tzOffsetMs(ts, shopTz())).toISOString().slice(0, 16);
}

// Plain calendar-date maths on "YYYY-MM-DD"
function dayNum(d: string): number { return Math.round(Date.parse(d + "T00:00:00Z") / 86400000); }
function dayStr(n: number): string { return new Date(n * 86400000).toISOString().slice(0, 10); }
function addDays(d: string, n: number): string { return dayStr(dayNum(d) + n); }
function daysInMonth(y: number, m: number): number { return new Date(Date.UTC(y, m, 0)).getUTCDate(); } // m: 1-12

// ============================================================
// Pay periods (รอบตัดบิล)
//   monthly      { cut_day }               cut_day 31 = end of month
//   semimonthly  { first_end }             1..first_end, first_end+1..end of month
//   weekly       { every, end_weekday, anchor }  end_weekday 0=Sun..6=Sat, periods end on/after anchor
//   days         { every, anchor }         every N days starting at anchor
// Stored as history [{ from, cfg }]; a change applies from the next period.
// ============================================================

type PeriodCfg = { type: string; cut_day?: number; first_end?: number; every?: number; end_weekday?: number; anchor?: string };
type PeriodHist = Array<{ from: string; cfg: PeriodCfg }>;
const DEFAULT_PERIOD: PeriodCfg = { type: "monthly", cut_day: 31 };

function cleanPeriodCfg(raw: Record<string, unknown>): PeriodCfg | null {
  const int = (v: unknown, lo: number, hi: number) => { const n = Math.round(Number(v)); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
  const type = String(raw.type ?? "");
  if (type === "monthly") { const c = int(raw.cut_day, 1, 31); return c ? { type, cut_day: c } : null; }
  if (type === "semimonthly") { const f = int(raw.first_end, 1, 27); return f ? { type, first_end: f } : null; }
  const anchor = String(raw.anchor ?? "");
  if (!isIsoDate(anchor)) return null;
  if (type === "weekly") {
    const e = int(raw.every, 1, 8), w = int(raw.end_weekday, 0, 6);
    return e !== null && w !== null ? { type, every: e, end_weekday: w, anchor } : null;
  }
  if (type === "days") { const e = int(raw.every, 1, 120); return e ? { type, every: e, anchor } : null; }
  return null;
}

// The natural period of `cfg` that contains date d.
function naturalPeriod(cfg: PeriodCfg, d: string): { start: string; end: string } {
  const [y, m, day] = d.split("-").map(Number);
  if (cfg.type === "semimonthly") {
    const f = cfg.first_end as number, dim = daysInMonth(y, m);
    const mm = String(m).padStart(2, "0");
    return day <= f ? { start: `${y}-${mm}-01`, end: `${y}-${mm}-${String(f).padStart(2, "0")}` }
      : { start: `${y}-${mm}-${String(f + 1).padStart(2, "0")}`, end: `${y}-${mm}-${String(dim).padStart(2, "0")}` };
  }
  if (cfg.type === "weekly") {
    const len = 7 * (cfg.every as number);
    const a = dayNum(cfg.anchor as string);
    const aWeekday = new Date(a * 86400000).getUTCDay();
    const firstEnd = a + ((cfg.end_weekday as number) - aWeekday + 7) % 7;
    const k = Math.ceil((dayNum(d) - firstEnd) / len);
    const end = firstEnd + k * len;
    return { start: dayStr(end - len + 1), end: dayStr(end) };
  }
  if (cfg.type === "days") {
    const n = cfg.every as number, a = dayNum(cfg.anchor as string);
    const start = a + Math.floor((dayNum(d) - a) / n) * n;
    return { start: dayStr(start), end: dayStr(start + n - 1) };
  }
  // monthly
  const cut = cfg.cut_day ?? 31;
  const endOf = (yy: number, mo: number) => { // mo may be 0 or 13
    const dt = new Date(Date.UTC(yy, mo - 1, 1));
    const Y = dt.getUTCFullYear(), M = dt.getUTCMonth() + 1;
    return `${Y}-${String(M).padStart(2, "0")}-${String(Math.min(cut, daysInMonth(Y, M))).padStart(2, "0")}`;
  };
  const thisEnd = endOf(y, m);
  if (d <= thisEnd) return { start: addDays(endOf(y, m - 1), 1), end: thisEnd };
  return { start: addDays(thisEnd, 1), end: endOf(y, m + 1) };
}

function periodFor(hist: PeriodHist | null | undefined, d: string): { start: string; end: string; cfg: PeriodCfg } {
  const list = (hist ?? []).filter((h) => h && h.cfg && isIsoDate(h.from)).sort((a, b) => a.from.localeCompare(b.from));
  let idx = -1;
  for (let i = 0; i < list.length; i++) if (list[i].from <= d) idx = i;
  const cfg = idx >= 0 ? list[idx].cfg : (list[0]?.cfg ?? DEFAULT_PERIOD);
  let { start, end } = naturalPeriod(cfg, d);
  if (idx >= 0 && start < list[idx].from) start = list[idx].from;
  const next = list[idx + 1];
  if (next && next.from <= end) end = addDays(next.from, -1);
  return { start, end, cfg };
}

// ============================================================
// Pay rules (ค่าแรง / โอที)
// ============================================================

type Pay = {
  pay_type: "daily" | "hourly"; daily_rate: number; hourly_rate: number;
  std_hours: number; half_day_hours: number; min_day_hours: number;
  ot_mode: "none" | "after_hours" | "after_time" | "both"; ot_after_hours: number; ot_after_time: string;
  ot_rate_type: "multiplier" | "fixed"; ot_multiplier: number; ot_fixed_rate: number;
  ot_round_min: number; ot_min_min: number;
};

const PAY_DEFAULTS: Pay = {
  pay_type: "daily", daily_rate: 0, hourly_rate: 0,
  std_hours: 8, half_day_hours: 4, min_day_hours: 2,
  ot_mode: "none", ot_after_hours: 8, ot_after_time: "20:00",
  ot_rate_type: "multiplier", ot_multiplier: 1.5, ot_fixed_rate: 0,
  ot_round_min: 15, ot_min_min: 30,
};

const PAY_FIELDS: Record<string, { kind: "num" | "enum" | "time"; min?: number; max?: number; values?: string[] }> = {
  pay_type: { kind: "enum", values: ["daily", "hourly"] },
  daily_rate: { kind: "num", min: 0, max: 100000 },
  hourly_rate: { kind: "num", min: 0, max: 10000 },
  std_hours: { kind: "num", min: 1, max: 24 },
  half_day_hours: { kind: "num", min: 0, max: 24 },
  min_day_hours: { kind: "num", min: 0, max: 24 },
  ot_mode: { kind: "enum", values: ["none", "after_hours", "after_time", "both"] },
  ot_after_hours: { kind: "num", min: 0, max: 24 },
  ot_after_time: { kind: "time" },
  ot_rate_type: { kind: "enum", values: ["multiplier", "fixed"] },
  ot_multiplier: { kind: "num", min: 0, max: 10 },
  ot_fixed_rate: { kind: "num", min: 0, max: 10000 },
  ot_round_min: { kind: "num", min: 1, max: 120 },
  ot_min_min: { kind: "num", min: 0, max: 600 },
};

// Keeps only known fields with valid values. Empty string / null = "not set" (inherit).
function cleanPay(raw: Record<string, unknown>): { pay: Record<string, unknown>; bad: string[] } {
  const pay: Record<string, unknown> = {};
  const bad: string[] = [];
  for (const [k, rule] of Object.entries(PAY_FIELDS)) {
    const v = raw?.[k];
    if (v === undefined || v === null || v === "") continue;
    if (rule.kind === "num") {
      const n = Number(v);
      if (!Number.isFinite(n) || n < (rule.min as number) || n > (rule.max as number)) bad.push(k); else pay[k] = n;
    } else if (rule.kind === "enum") {
      if (!(rule.values as string[]).includes(String(v))) bad.push(k); else pay[k] = String(v);
    } else {
      const m = /^(\d{1,2}):(\d{2})$/.exec(String(v));
      if (!m || +m[1] > 23 || +m[2] > 59) bad.push(k); else pay[k] = `${m[1].padStart(2, "0")}:${m[2]}`;
    }
  }
  return { pay, bad };
}

function effectivePay(branchDefaults: unknown, staffPay: unknown): Pay {
  return { ...PAY_DEFAULTS, ...(branchDefaults as object ?? {}), ...(staffPay as object ?? {}) } as Pay;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

type PunchRow = Punch & { day_override: number | null; ot_override_min: number | null; review_ok: boolean; created_by: string };

// One person's day: worked minutes, day fraction, OT minutes and money.
function computeDay(rules: Pay, shifts: PunchRow[], date: string) {
  const closed = shifts.filter((s) => s.check_out);
  const worked = closed.reduce((m, s) => m + Math.max(0, (Date.parse(s.check_out as string) - Date.parse(s.check_in)) / 60000), 0);
  const workedMin = Math.floor(worked);
  const hours = workedMin / 60;

  // OT before rounding
  let otRaw = 0;
  const afterHours = Math.max(0, workedMin - rules.ot_after_hours * 60);
  let afterTime = 0;
  const threshold = localToUtc(`${date}T${rules.ot_after_time}`)?.getTime() ?? Infinity;
  for (const s of closed) {
    const a = Date.parse(s.check_in), b = Date.parse(s.check_out as string);
    afterTime += Math.max(0, (b - Math.max(a, threshold)) / 60000);
  }
  if (rules.ot_mode === "after_hours") otRaw = afterHours;
  else if (rules.ot_mode === "after_time") otRaw = afterTime;
  else if (rules.ot_mode === "both") otRaw = Math.max(afterHours, afterTime); // same minutes are never paid twice
  let otAuto = Math.floor(otRaw / rules.ot_round_min) * rules.ot_round_min;
  if (otAuto < rules.ot_min_min) otAuto = 0;
  const overrides = shifts.filter((s) => s.ot_override_min !== null && s.ot_override_min !== undefined);
  const otMin = overrides.length ? overrides.reduce((m, s) => m + Number(s.ot_override_min), 0) : otAuto;

  // Day fraction (daily pay)
  let dayAuto = 0;
  if (workedMin > 0) dayAuto = hours < rules.min_day_hours ? 0 : hours < rules.half_day_hours ? 0.5 : 1;
  const dayOverride = shifts.find((s) => s.day_override !== null && s.day_override !== undefined)?.day_override;
  const day = dayOverride !== undefined && dayOverride !== null ? Number(dayOverride) : dayAuto;

  const baseHourly = rules.pay_type === "hourly" ? rules.hourly_rate : rules.daily_rate / rules.std_hours;
  const otRate = rules.ot_rate_type === "fixed" ? rules.ot_fixed_rate : baseHourly * rules.ot_multiplier;
  let base: number;
  if (rules.pay_type === "hourly") base = Math.max(0, workedMin - otMin) / 60 * rules.hourly_rate;
  else base = day * rules.daily_rate;
  const otPay = otMin / 60 * otRate;

  return {
    date, worked_min: workedMin, day: rules.pay_type === "hourly" ? (workedMin > 0 ? 1 : 0) : day, day_auto: dayAuto,
    ot_min: otMin, ot_auto_min: otAuto, ot_rate: round2(otRate),
    base: round2(base), ot_pay: round2(otPay), open: shifts.some((s) => !s.check_out && !s.forgot_out),
  };
}

// ============================================================
// Review flags (กล่อง "ต้องตรวจ")
// ============================================================

const LONG_SHIFT_HOURS = 14;
const SHORT_SHIFT_MIN = 5;

function flagsOf(r: PunchRow): string[] {
  if (r.review_ok) return [];
  const f: string[] = [];
  if (r.forgot_out) f.push("forgot_out");
  else if (!r.check_out && Date.now() - Date.parse(r.check_in) > FORGOT_OUT_HOURS * 3600000) f.push("still_open");
  if (r.check_out) {
    const min = (Date.parse(r.check_out) - Date.parse(r.check_in)) / 60000;
    if (min > LONG_SHIFT_HOURS * 60) f.push("long");
    if (min < SHORT_SHIFT_MIN) f.push("short");
  }
  return f;
}

// ============================================================
// Locks: a period that has been billed (step 4) can't be edited until unlocked.
// ============================================================

async function isLocked(staffId: number, date: string): Promise<boolean> {
  const { data } = await supabase.from("pay_closures").select("id")
    .eq("staff_id", staffId).lte("period_start", date).gte("period_end", date).limit(1);
  return !!(data && data.length);
}

// ============================================================
// Person + branch loading
// ============================================================

type StaffFull = { id: number; branch_id: string; name: string; label: string; active: boolean; pay: Record<string, unknown>; period: PeriodHist | null; pin_hash?: string | null };
type BranchFull = { id: string; name: string; pay_defaults: Record<string, unknown>; period: PeriodHist; staff_advance: boolean; advance_auto_max: number };

async function loadBranch(id: string): Promise<BranchFull | null> {
  const { data } = await supabase.from("branches").select("id, name, pay_defaults, period, staff_advance, advance_auto_max").eq("id", id).maybeSingle();
  return (data as BranchFull) ?? null;
}

function staffPeriodHist(b: BranchFull, s: StaffFull): PeriodHist {
  return (s.period && s.period.length) ? s.period : (b.period ?? []);
}

// Period totals for one person. `date` picks the period (default today).
async function staffPeriodSummary(b: BranchFull, s: StaffFull, date?: string) {
  const d = date && isIsoDate(date) ? date : localDate(new Date());
  const per = periodFor(staffPeriodHist(b, s), d);
  const rules = effectivePay(b.pay_defaults, s.pay);
  const [{ data: punches }, { data: adv }, locked] = await Promise.all([
    supabase.from("punches").select("*").eq("staff_id", s.id).gte("work_date", per.start).lte("work_date", per.end).order("check_in"),
    supabase.from("advances").select("*").eq("staff_id", s.id).gte("date", per.start).lte("date", per.end).order("date"),
    isLocked(s.id, per.start),
  ]);
  const byDate = new Map<string, PunchRow[]>();
  for (const p of (punches ?? []) as PunchRow[]) {
    const list = byDate.get(p.work_date) ?? [];
    list.push(p);
    byDate.set(p.work_date, list);
  }
  const days = [...byDate.entries()].sort().map(([dt, list]) => computeDay(rules, list, dt));
  const approved = (adv ?? []).filter((a) => a.status === "approved");
  const pending = (adv ?? []).filter((a) => a.status === "pending");
  const sum = (arr: Array<Record<string, unknown>>, k: string) => round2(arr.reduce((m, x) => m + Number(x[k] || 0), 0));
  const base = sum(days, "base"), otPay = sum(days, "ot_pay"), advTotal = sum(approved, "amount");
  const today = localDate(new Date());
  const lastCounted = per.end < today ? per.end : today;
  const calendarDays = lastCounted >= per.start ? dayNum(lastCounted) - dayNum(per.start) + 1 : 0;
  const daysWorked = days.reduce((m, x) => m + x.day, 0);
  return {
    staff_id: s.id, name: s.name, label: s.label || s.name, pay_type: rules.pay_type,
    period: { start: per.start, end: per.end, cfg: per.cfg }, locked,
    totals: {
      days_worked: daysWorked,
      days_with_punch: days.filter((x) => x.worked_min > 0).length,
      days_off: Math.max(0, calendarDays - days.filter((x) => x.worked_min > 0).length),
      worked_hours: round2(days.reduce((m, x) => m + x.worked_min, 0) / 60),
      ot_hours: round2(days.reduce((m, x) => m + x.ot_min, 0) / 60),
      base, ot_pay: otPay, gross: round2(base + otPay),
      advances: advTotal, pending: sum(pending, "amount"), net: round2(base + otPay - advTotal),
    },
    days,
    advances: (adv ?? []).filter((a) => a.status !== "rejected"),
  };
}

// ============================================================
// Admin: pay settings and periods
// ============================================================

async function handleSavePayDefaults(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { pay, bad } = cleanPay((p.pay ?? {}) as Record<string, unknown>);
  if (bad.length) return json({ ok: false, error: "bad_pay", fields: bad });
  const row: Record<string, unknown> = { pay_defaults: pay };
  if (p.staff_advance !== undefined) row.staff_advance = !!p.staff_advance;
  if (p.advance_auto_max !== undefined) {
    const n = Number(p.advance_auto_max);
    if (!Number.isFinite(n) || n < 0 || n > 100000) return json({ ok: false, error: "bad_pay", fields: ["advance_auto_max"] });
    row.advance_auto_max = n;
  }
  const { error } = await supabase.from("branches").update(row).eq("id", String(p.branch_id ?? ""));
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("save_pay_defaults", { branch_id: p.branch_id, ...row });
  return json({ ok: true });
}

async function handleSaveStaffPay(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { pay, bad } = cleanPay((p.pay ?? {}) as Record<string, unknown>);
  if (bad.length) return json({ ok: false, error: "bad_pay", fields: bad });
  const { error } = await supabase.from("staff").update({ pay }).eq("id", Number(p.staff_id) || 0);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("save_staff_pay", { staff_id: p.staff_id, pay });
  return json({ ok: true });
}

// New period settings. Before anything has been billed they apply right away; after that, from
// the start of the next period, so the period in progress never changes.
async function newPeriodHist(current: PeriodHist, cfg: PeriodCfg, billed: boolean): Promise<PeriodHist> {
  if (!billed) return [{ from: "2000-01-01", cfg }];
  const now = periodFor(current, localDate(new Date()));
  const from = addDays(now.end, 1);
  return [...current.filter((h) => h.from < from), { from, cfg }];
}

async function handleSavePeriod(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const staffId = Number(p.staff_id) || 0;
  const useBranch = staffId && p.cfg === null;
  const cfg = useBranch ? null : cleanPeriodCfg((p.cfg ?? {}) as Record<string, unknown>);
  if (!useBranch && !cfg) return json({ ok: false, error: "bad_period" });
  if (staffId) {
    const { data: s } = await supabase.from("staff").select("id, branch_id, period").eq("id", staffId).maybeSingle();
    if (!s) return json({ ok: false, error: "unknown_staff" });
    if (useBranch) {
      await supabase.from("staff").update({ period: null }).eq("id", staffId);
    } else {
      const b = await loadBranch(s.branch_id);
      const { data: closed } = await supabase.from("pay_closures").select("id").eq("staff_id", staffId).limit(1);
      const current = (s.period && s.period.length) ? s.period : (b?.period ?? []);
      await supabase.from("staff").update({ period: await newPeriodHist(current, cfg as PeriodCfg, !!closed?.length) }).eq("id", staffId);
    }
  } else {
    const b = await loadBranch(String(p.branch_id ?? ""));
    if (!b) return json({ ok: false, error: "unknown_branch" });
    const { data: closed } = await supabase.from("pay_closures").select("id").eq("branch_id", b.id).limit(1);
    await supabase.from("branches").update({ period: await newPeriodHist(b.period ?? [], cfg as PeriodCfg, !!closed?.length) }).eq("id", b.id);
  }
  await logAdmin("save_period", { branch_id: p.branch_id, staff_id: staffId || null, cfg });
  return json({ ok: true });
}

// Everything the admin "pay" screens need for a branch: defaults, period now/next, each person's settings.
async function handlePaySettings(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const b = await loadBranch(String(p.branch_id ?? ""));
  if (!b) return json({ ok: false, error: "unknown_branch" });
  const { data: staff } = await supabase.from("staff").select("id, name, label, active, pay, period")
    .eq("branch_id", b.id).order("sort").order("name");
  const today = localDate(new Date());
  const show = (hist: PeriodHist) => {
    const now = periodFor(hist, today);
    const next = periodFor(hist, addDays(now.end, 1));
    return { now, next };
  };
  return json({
    ok: true,
    system_defaults: PAY_DEFAULTS,
    branch: { id: b.id, pay_defaults: b.pay_defaults ?? {}, staff_advance: b.staff_advance, advance_auto_max: Number(b.advance_auto_max) },
    branch_period: { hist: b.period ?? [], ...show(b.period ?? []) },
    staff: (staff ?? []).map((s) => ({
      id: s.id, name: s.name, label: s.label || s.name, active: s.active, pay: s.pay ?? {},
      own_period: !!(s.period && s.period.length),
      period: show((s.period && s.period.length) ? s.period : (b.period ?? [])),
    })),
  });
}

// Live totals of the current (or `date`) period for everyone active in a branch.
async function handlePaySummary(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const b = await loadBranch(String(p.branch_id ?? ""));
  if (!b) return json({ ok: false, error: "unknown_branch" });
  let q = supabase.from("staff").select("id, branch_id, name, label, active, pay, period").eq("branch_id", b.id);
  if (p.staff_id) q = q.eq("id", Number(p.staff_id)); else q = q.eq("active", true);
  const { data: staff } = await q.order("sort").order("name");
  const people = await Promise.all(((staff ?? []) as StaffFull[]).map((s) => staffPeriodSummary(b, s, String(p.date ?? ""))));
  return json({ ok: true, people });
}

// ============================================================
// Admin: fix shifts by hand
// ============================================================

// Shifts that need a look: forgot to clock out, still open too long, very long or very short.
async function handleReviewList(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const branchId = String(p.branch_id ?? "");
  const since = addDays(localDate(new Date()), -62);
  const { data } = await supabase.from("punches").select("*")
    .eq("branch_id", branchId).gte("work_date", since).eq("review_ok", false).order("check_in");
  const items = ((data ?? []) as PunchRow[]).map((r) => ({ ...withLocal(r), flags: flagsOf(r) })).filter((r) => r.flags.length);
  const { data: pend } = await supabase.from("advances").select("id").eq("branch_id", branchId).eq("status", "pending");
  return json({ ok: true, items, pending_advances: (pend ?? []).length });
}

function withLocal(r: PunchRow) {
  return { ...r, check_in_local: utcToLocal(r.check_in), check_out_local: utcToLocal(r.check_out) };
}

function readShiftInput(p: Record<string, unknown>): { in: Date; out: Date | null } | string {
  const inAt = localToUtc(String(p.check_in ?? ""));
  if (!inAt) return "bad_time";
  const outRaw = String(p.check_out ?? "");
  const outAt = outRaw ? localToUtc(outRaw) : null;
  if (outRaw && !outAt) return "bad_time";
  if (outAt && outAt.getTime() <= inAt.getTime()) return "out_before_in";
  if (outAt && outAt.getTime() - inAt.getTime() > 24 * 3600000) return "too_long";
  if (inAt.getTime() > Date.now() + 5 * 60000) return "in_future";
  return { in: inAt, out: outAt };
}

function readOverrides(p: Record<string, unknown>): Record<string, unknown> | string {
  const out: Record<string, unknown> = {};
  if (p.day_override !== undefined) {
    const v = p.day_override === "" || p.day_override === null ? null : Number(p.day_override);
    if (v !== null && ![0, 0.5, 1].includes(v)) return "bad_day";
    out.day_override = v;
  }
  if (p.ot_override_min !== undefined) {
    const v = p.ot_override_min === "" || p.ot_override_min === null ? null : Math.round(Number(p.ot_override_min));
    if (v !== null && (!Number.isFinite(v) || v < 0 || v > 1440)) return "bad_ot";
    out.ot_override_min = v;
  }
  return out;
}

// Edit one shift (times in shop local "YYYY-MM-DDTHH:MM"), or just mark it as checked (review_ok only).
async function handleEditPunch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data: row } = await supabase.from("punches").select("*").eq("id", Number(p.id) || 0).maybeSingle();
  if (!row) return json({ ok: false, error: "not_found" });
  if (await isLocked(row.staff_id, row.work_date)) return json({ ok: false, error: "locked" });
  const upd: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (p.only_review) {
    upd.review_ok = true;
  } else {
    const t = readShiftInput(p);
    if (typeof t === "string") return json({ ok: false, error: t });
    const o = readOverrides(p);
    if (typeof o === "string") return json({ ok: false, error: o });
    const workDate = localDate(t.in);
    if (workDate !== row.work_date && await isLocked(row.staff_id, workDate)) return json({ ok: false, error: "locked" });
    Object.assign(upd, o, {
      check_in: t.in.toISOString(), check_out: t.out ? t.out.toISOString() : null, work_date: workDate,
      forgot_out: false, edited: true, review_ok: true, note: String(p.note ?? row.note ?? "").slice(0, 300),
    });
  }
  const { error } = await supabase.from("punches").update(upd).eq("id", row.id);
  if (error) {
    const dup = error.code === "23505" || String(error.message).includes("duplicate");
    return json({ ok: false, error: dup ? "open_exists" : error.message });
  }
  await logAdmin("edit_punch", { id: row.id, before: { in: row.check_in, out: row.check_out }, after: upd });
  return json({ ok: true });
}

// Add a shift by hand (forgot to clock in, system was down, ...).
async function handleAddPunch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data: s } = await supabase.from("staff").select("id, branch_id").eq("id", Number(p.staff_id) || 0).maybeSingle();
  if (!s) return json({ ok: false, error: "unknown_staff" });
  const t = readShiftInput(p);
  if (typeof t === "string") return json({ ok: false, error: t });
  if (!t.out) return json({ ok: false, error: "need_out" });
  const o = readOverrides(p);
  if (typeof o === "string") return json({ ok: false, error: o });
  const workDate = localDate(t.in);
  if (await isLocked(s.id, workDate)) return json({ ok: false, error: "locked" });
  const { data, error } = await supabase.from("punches").insert({
    ...o, branch_id: s.branch_id, staff_id: s.id, work_date: workDate,
    check_in: t.in.toISOString(), check_out: t.out.toISOString(),
    edited: true, review_ok: true, created_by: "admin", note: String(p.note ?? "").slice(0, 300),
  }).select("id").maybeSingle();
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("add_punch", { id: data?.id, staff_id: s.id, in: t.in, out: t.out });
  return json({ ok: true, id: data?.id });
}

async function handleDeletePunch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data: row } = await supabase.from("punches").select("*").eq("id", Number(p.id) || 0).maybeSingle();
  if (!row) return json({ ok: false, error: "not_found" });
  if (await isLocked(row.staff_id, row.work_date)) return json({ ok: false, error: "locked" });
  const { error } = await supabase.from("punches").delete().eq("id", row.id);
  if (error) return json({ ok: false, error: error.message });
  const photos = [row.in_photo, row.out_photo].filter(Boolean);
  if (photos.length) await supabase.storage.from(PHOTO_BUCKET).remove(photos);
  await logAdmin("delete_punch", { row });
  return json({ ok: true });
}

// ============================================================
// Advances (เบิกเงิน): admin records (approved at once) or staff request (pending, or
// approved at once when not more than the branch's auto-approve amount).
// ============================================================

function readAmount(v: unknown): number | null {
  const n = round2(Number(v));
  return Number.isFinite(n) && n > 0 && n <= 100000 ? n : null;
}

async function handleAddAdvance(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data: s } = await supabase.from("staff").select("id, branch_id").eq("id", Number(p.staff_id) || 0).maybeSingle();
  if (!s) return json({ ok: false, error: "unknown_staff" });
  const amount = readAmount(p.amount);
  if (!amount) return json({ ok: false, error: "bad_amount" });
  const date = isIsoDate(String(p.date ?? "")) ? String(p.date) : localDate(new Date());
  if (await isLocked(s.id, date)) return json({ ok: false, error: "locked" });
  if (!p.force) {
    // The person already asked for money that day: ask the admin before adding a second entry.
    const { data: pend } = await supabase.from("advances").select("id, amount, item, date")
      .eq("staff_id", s.id).eq("date", date).eq("status", "pending");
    if (pend && pend.length) return json({ ok: false, error: "pending_exists", pending: pend });
  }
  const { data, error } = await supabase.from("advances").insert({
    branch_id: s.branch_id, staff_id: s.id, date, amount, item: String(p.item ?? "").trim().slice(0, 100),
    status: "approved", created_by: "admin", decided_at: new Date().toISOString(),
  }).select("id").maybeSingle();
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("add_advance", { id: data?.id, staff_id: s.id, amount, date });
  return json({ ok: true, id: data?.id });
}

async function handleDecideAdvance(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const status = p.approve ? "approved" : "rejected";
  const { data: a } = await supabase.from("advances").select("*").eq("id", Number(p.id) || 0).maybeSingle();
  if (!a) return json({ ok: false, error: "not_found" });
  if (await isLocked(a.staff_id, a.date)) return json({ ok: false, error: "locked" });
  const { error } = await supabase.from("advances").update({ status, decided_at: new Date().toISOString() }).eq("id", a.id);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("decide_advance", { id: a.id, status });
  return json({ ok: true });
}

async function handleDeleteAdvance(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const { data: a } = await supabase.from("advances").select("*").eq("id", Number(p.id) || 0).maybeSingle();
  if (!a) return json({ ok: false, error: "not_found" });
  if (await isLocked(a.staff_id, a.date)) return json({ ok: false, error: "locked" });
  await supabase.from("advances").delete().eq("id", a.id);
  await logAdmin("delete_advance", { advance: a });
  return json({ ok: true });
}

async function handleListAdvances(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const branchId = String(p.branch_id ?? "");
  const from = String(p.from ?? ""), to = String(p.to ?? "");
  let q = supabase.from("advances").select("*").eq("branch_id", branchId);
  if (isIsoDate(from)) q = q.gte("date", from);
  if (isIsoDate(to)) q = q.lte("date", to);
  const [{ data, error }, { data: pend }] = await Promise.all([
    q.order("date").order("created_at"),
    supabase.from("advances").select("*").eq("branch_id", branchId).eq("status", "pending").order("created_at"),
  ]);
  if (error) return json({ ok: false, error: error.message });
  return json({ ok: true, advances: data ?? [], pending: pend ?? [] });
}

// ============================================================
// Staff self-service (with the person's own PIN)
// ============================================================

async function staffByPin(p: Record<string, unknown>): Promise<{ s: StaffFull; b: BranchFull } | string> {
  const pin = String(p.pin ?? "").trim();
  if (!/^\d{4,6}$/.test(pin)) return "pin_invalid";
  const { data: s } = await supabase.from("staff").select("id, branch_id, name, label, active, pay, period, pin_hash")
    .eq("id", Number(p.staff_id) || 0).maybeSingle();
  if (!s || !s.active || s.branch_id !== String(p.branch ?? "")) return "unknown_staff";
  if (!s.pin_hash) return "no_pin";
  if (!(await checkPassword(s.pin_hash, pin))) return "wrong_pin";
  const b = await loadBranch(s.branch_id);
  if (!b) return "unknown_branch";
  return { s: s as StaffFull, b };
}

// My period so far: days, OT hours, advances. No money totals (those are for the bill).
async function handleMySummary(p: Record<string, unknown>) {
  const who = await staffByPin(p);
  if (typeof who === "string") return json({ ok: false, error: who });
  const sum = await staffPeriodSummary(who.b, who.s);
  return json({
    ok: true,
    staff_advance: who.b.staff_advance,
    period: { start: sum.period.start, end: sum.period.end },
    days_worked: sum.totals.days_worked,
    ot_hours: sum.totals.ot_hours,
    advances: sum.advances.map((a) => ({ id: a.id, date: a.date, amount: Number(a.amount), item: a.item, status: a.status })),
    advances_total: sum.totals.advances,
    pending_total: sum.totals.pending,
  });
}

async function handleRequestAdvance(p: Record<string, unknown>) {
  const who = await staffByPin(p);
  if (typeof who === "string") return json({ ok: false, error: who });
  if (!who.b.staff_advance) return json({ ok: false, error: "advance_off" });
  const amount = readAmount(p.amount);
  if (!amount) return json({ ok: false, error: "bad_amount" });
  const date = localDate(new Date());
  if (await isLocked(who.s.id, date)) return json({ ok: false, error: "locked" });
  const auto = Number(who.b.advance_auto_max) > 0 && amount <= Number(who.b.advance_auto_max);
  const { error } = await supabase.from("advances").insert({
    branch_id: who.b.id, staff_id: who.s.id, date, amount, item: String(p.item ?? "").trim().slice(0, 100),
    status: auto ? "approved" : "pending", created_by: "staff", decided_at: auto ? new Date().toISOString() : null,
  });
  if (error) return json({ ok: false, error: error.message });
  return json({ ok: true, status: auto ? "approved" : "pending" });
}

// ============================================================
// Dispatch
// ============================================================

const ACTIONS: Record<string, (p: Record<string, unknown>) => Promise<Response>> = {
  bootstrap: handleBootstrap,
  today: handleToday,
  punch: handlePunch,
  setup: handleSetup,
  check_admin_pin: handleCheckAdminPin,
  change_admin_pin: handleChangeAdminPin,
  save_branch: handleSaveBranch,
  list_staff_admin: handleListStaffAdmin,
  save_staff_member: handleSaveStaffMember,
  punches_range: handlePunchesRange,
  save_branch_settings: handleSaveBranchSettings,
  pay_settings: handlePaySettings,
  save_pay_defaults: handleSavePayDefaults,
  save_staff_pay: handleSaveStaffPay,
  save_period: handleSavePeriod,
  pay_summary: handlePaySummary,
  review_list: handleReviewList,
  edit_punch: handleEditPunch,
  add_punch: handleAddPunch,
  delete_punch: handleDeletePunch,
  add_advance: handleAddAdvance,
  decide_advance: handleDecideAdvance,
  delete_advance: handleDeleteAdvance,
  list_advances: handleListAdvances,
  my_summary: handleMySummary,
  request_advance: handleRequestAdvance,
  ai_translate: handleAiTranslate,
  translate_page: handleTranslatePage,
  list_translations: handleListTranslations,
  save_translations: handleSaveTranslations,
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS_HEADERS });
  try {
    const params: Record<string, unknown> = req.method === "GET"
      ? Object.fromEntries(new URL(req.url).searchParams)
      : await req.json();
    const action = String(params.action ?? "");
    const handler = ACTIONS[action];
    if (!handler) return json({ ok: false, error: "unknown_action: " + action }, 404);
    return await handler(params);
  } catch (e) {
    console.error("dispatch error", e);
    return json({ ok: false, error: String(e) }, 500);
  }
});

// Edge Function "clock" — ระบบตอกบัตร (ใช้ Supabase project เดียวกับปฏิทินได้ หรือใช้เดี่ยวๆ ก็ได้)
//
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
    supabase.from("branches").select("id, name, sort").order("sort").order("name"),
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

// Public with the person's own PIN. type: "in" | "out"
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
    const { data, error } = await supabase.from("punches").insert({
      branch_id: branchId, staff_id: staffId, work_date: localDate(now), check_in: now.toISOString(),
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
    const { data, error } = await supabase.from("punches")
      .update({ check_out: now.toISOString(), updated_at: now.toISOString() })
      .eq("id", open.id).is("check_out", null).select("*").maybeSingle();
    if (error) return json({ ok: false, error: error.message });
    if (!data) return json({ ok: false, error: "not_in" });
    punch = data as Punch;
    status = "ok_out";
  }

  const [punches, messages] = await Promise.all([
    todayPunches(branchId),
    calendarMessages(branchId, localDate(now), lang),
  ]);
  return json({
    ok: true, status, punch: publicPunch(punch), staff_name: person.name,
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
  const { data, error } = await supabase.from("punches").select("*")
    .eq("branch_id", branchId).gte("work_date", from).lte("work_date", to).order("work_date").order("check_in");
  if (error) return json({ ok: false, error: error.message });
  return json({ ok: true, punches: data ?? [] });
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

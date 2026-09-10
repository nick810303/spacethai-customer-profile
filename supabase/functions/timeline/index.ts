// 小泰空 顧客檔案系統・「時間軸」資料源（唯讀、不回寫任何系統、不呼叫客立樂）
// v1 2026-09-09
// v2 2026-09-09: all-day 事件標 allDay（前端不畫方塊）；隔日凌晨只保留預約（深夜班），占用不跨日
// v3 2026-09-10: 量能（紅天／綠天／黃金天）計畫 vs 實績；快照寫入 capacity_daily；pg_cron 用 x-cron-secret 觸發
//   GET /functions/v1/timeline?date=YYYY-MM-DD   （預設今天，台北日）
//   GET /functions/v1/timeline?date=…&snapshot=plan|actual   （cron：需 x-cron-secret；管理員也可手動）
//   來源：teachers（名單／分店／培訓／頭像）＋ teacher_shift（當日排班窗）＋ 各老師 Google 行事曆 events.list
//   權限：需帶顧客檔案系統的 Supabase Auth JWT，且 staff.is_admin = true（建構期間先限管理員）
//   行事曆讀取、時區工具、預約判定規則皆與 `slots` 引擎相同（同一份資料、同一條 BOOKING_RE）。
//
//   量能規則（依《小泰空總班表概念說明書》＋ Nick 2026-09-10 決定）：
//   - teacher_shift.to_min ＝ 班表「到」+120 分（最後可接受預約開始時間 + 最長服務）；量能小時 = (to_min − 120 − from_min)/60
//   - 實績：把班表區間的「頭」或「尾」被行事曆占用（標題含 休/病/假… 且不含 聚餐/拍攝/公務… ）的部分切掉；中間的占用不算；整天占用＝當天 0
//   - 分級：紅天 H<28 或 人數<（假日類 4／平日 3）；黃金天 H≥35 且 人數≥5；其餘綠天。假日類＝週六日＋holidays 表
import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const TPE = 8 * 3600 * 1000;
const GCAL_KEY = Deno.env.get("GCAL_API_KEY")!;
const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SB_SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SB_ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const BUFFER = 15;
const BOOKING_RE = /(\d{2,3})\s*min/i; // 標題含「XX min」＝真預約（有無 #編號都算）；其餘＝占用
const MAX_SERVICE = 120;               // 班表「到」→ to_min 的偏移
const LEAVE_RE = /休|病|假|早退|晚到|遲到|急事|請假|離開|提早|延後/;
const DUTY_RE = /聚餐|拍攝|公務|會議|開會|教育|培訓|訓練|受訓|支援|教學|活動/;
const TH = { hoursOk: 28, hoursGold: 35, nWeekday: 3, nHoliday: 4, nGold: 5 };

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-cron-secret",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};
const pad = (n: number) => String(n).padStart(2, "0");
function tpeParts(ms: number) {
  const d = new Date(ms + TPE);
  return { y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate(), wd: d.getUTCDay(), hh: d.getUTCHours(), mm: d.getUTCMinutes() };
}
const tpeEpoch = (y: number, m: number, d: number, hh: number, mm: number) => Date.UTC(y, m - 1, d, hh, mm, 0) - TPE;
function tpeIso(ms: number) {
  const p = tpeParts(ms);
  return `${p.y}-${pad(p.m)}-${pad(p.d)}T${pad(p.hh)}:${pad(p.mm)}:00+08:00`;
}
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const SB_HDR = { apikey: SB_SERVICE, authorization: `Bearer ${SB_SERVICE}` };
async function sbGet(path: string) {
  const r = await fetch(`${SB_URL}/rest/v1/${path}`, { headers: SB_HDR });
  if (!r.ok) throw new Error(`sb ${path} ${r.status}`);
  return r.json();
}
async function sbUpsert(table: string, rows: unknown[]) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: { ...SB_HDR, "Content-Type": "application/json", Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!r.ok) throw new Error(`sb upsert ${table} ${r.status} ${await r.text()}`);
}

// 權限：用使用者 JWT 向 Auth 取得 email → 查 staff.is_admin
async function requireAdmin(req: Request): Promise<{ ok: true; email: string } | { ok: false; status: number; error: string }> {
  const auth = req.headers.get("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return { ok: false, status: 401, error: "missing token" };
  const r = await fetch(`${SB_URL}/auth/v1/user`, { headers: { apikey: SB_ANON, authorization: `Bearer ${token}` } });
  if (!r.ok) return { ok: false, status: 401, error: "invalid session" };
  const u = await r.json();
  const email = (u?.email || "").toLowerCase();
  if (!email) return { ok: false, status: 401, error: "no email" };
  const rows = await sbGet(`staff?select=is_admin&email=eq.${encodeURIComponent(email)}&limit=1`);
  if (!rows.length || !rows[0].is_admin) return { ok: false, status: 403, error: "admin only" };
  return { ok: true, email };
}
// cron：x-cron-secret 需等於 app_config.capacity_cron_secret
async function isCron(req: Request) {
  const s = req.headers.get("x-cron-secret");
  if (!s) return false;
  const rows = await sbGet(`app_config?select=value&key=eq.capacity_cron_secret&limit=1`);
  return !!rows.length && rows[0].value === s;
}

type Ev = { start: string; end: string; kind: "booking" | "block"; title: string; allDay?: boolean; duration?: number; customerNum?: number | null; displayName?: string };

function parseEvent(summary: string, s: number, e: number): Ev {
  const title = (summary || "").trim();
  const m = title.match(BOOKING_RE);
  if (!m) return { start: tpeIso(s), end: tpeIso(e), kind: "block", title };
  const numM = title.match(/^#\s*(\d+)/);
  const displayName = title.split("|")[0].replace(/^#\s*\d+\s*/, "").trim();
  return {
    start: tpeIso(s), end: tpeIso(e), kind: "booking", title,
    duration: +m[1], customerNum: numM ? +numM[1] : null, displayName,
  };
}

async function fetchEvents(calId: string, timeMin: string, timeMax: string): Promise<{ events: Ev[]; ok: boolean }> {
  const url = `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events`
    + `?key=${GCAL_KEY}&timeMin=${encodeURIComponent(timeMin)}&timeMax=${encodeURIComponent(timeMax)}`
    + `&singleEvents=true&orderBy=startTime&maxResults=2500`;
  const r = await fetch(url);
  if (!r.ok) return { events: [], ok: false };
  const j = await r.json();
  const events: Ev[] = [];
  for (const e of (j.items || [])) {
    const s = e.start?.dateTime ? Date.parse(e.start.dateTime) : (e.start?.date ? Date.parse(e.start.date + "T00:00:00+08:00") : NaN);
    const en = e.end?.dateTime ? Date.parse(e.end.dateTime) : (e.end?.date ? Date.parse(e.end.date + "T00:00:00+08:00") : NaN);
    if (!isFinite(s) || !isFinite(en)) continue;
    const ev = parseEvent(e.summary, s, en);
    if (!e.start?.dateTime) ev.allDay = true;
    events.push(ev);
  }
  return { events, ok: true };
}

// ── 量能 ─────────────────────────────────────────────────────────────
type Shift = { fromMin: number; toMin: number } | null;
type TeacherCap = { staffId: string; name: string; plan: [number, number] | null; actual: [number, number] | null; planHours: number; actualHours: number; cut: string[] };

// 從班表區間切掉頭尾的休/病占用（分鐘，相對當日 00:00）
function actualInterval(shift: Shift, events: Ev[], dayStart: number): { iv: [number, number] | null; cut: string[] } {
  if (!shift) return { iv: null, cut: [] };
  let a = shift.fromMin, b = shift.toMin; const cut: string[] = [];
  const leaves = events.filter(ev => ev.kind === "block" && LEAVE_RE.test(ev.title) && !DUTY_RE.test(ev.title))
    .map(ev => ({ s: ev.allDay ? -1e9 : (Date.parse(ev.start) - dayStart) / 60000, e: ev.allDay ? 1e9 : (Date.parse(ev.end) - dayStart) / 60000, title: ev.title, allDay: !!ev.allDay }));
  // 反覆套用直到穩定（先切頭再切尾，可能互相影響）
  for (let iter = 0; iter < 4; iter++) {
    let changed = false;
    for (const l of leaves) {
      if (l.e <= a || l.s >= b) continue;                 // 不重疊
      if (l.allDay || (l.s <= a && l.e >= b)) { cut.push(l.title); a = b; changed = true; break; } // 整段
      if (l.s <= a && l.e > a) { a = l.e; cut.push(l.title); changed = true; }   // 切頭
      else if (l.e >= b - MAX_SERVICE && l.s < b) { b = l.s; cut.push(l.title); changed = true; } // 切尾（占用延伸到最後可預約時間之後＝提早離開）
      // 中間的占用：不算
    }
    if (!changed) break;
  }
  return { iv: b > a ? [a, b] : null, cut: [...new Set(cut)] };
}
const hoursOf = (iv: [number, number] | null) => iv ? Math.max(0, iv[1] - MAX_SERVICE - iv[0]) / 60 : 0;
function grade(h: number, n: number, holiday: boolean): "red" | "green" | "gold" {
  if (h < TH.hoursOk || n < (holiday ? TH.nHoliday : TH.nWeekday)) return "red";
  if (h >= TH.hoursGold && n >= TH.nGold) return "gold";
  return "green";
}
const r2 = (x: number) => Math.round(x * 100) / 100;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    const url = new URL(req.url);
    const snapshot = url.searchParams.get("snapshot"); // plan | actual | null
    let cron = false;
    if (snapshot) cron = await isCron(req);
    if (!cron) {
      const gate = await requireAdmin(req);
      if (!gate.ok) return json({ error: gate.error }, gate.status);
    }
    if (snapshot && snapshot !== "plan" && snapshot !== "actual") return json({ error: "bad snapshot" }, 400);

    const now = Date.now();
    const tp = tpeParts(now);
    let dateKey = url.searchParams.get("date") || `${tp.y}-${pad(tp.m)}-${pad(tp.d)}`;
    if (dateKey === "yesterday") { const q = tpeParts(now - 86400000); dateKey = `${q.y}-${pad(q.m)}-${pad(q.d)}`; }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) return json({ error: "bad date" }, 400);
    const [y, m, d] = dateKey.split("-").map(Number);
    dateKey = `${y}-${pad(m)}-${pad(d)}`;
    const todayKey = `${tp.y}-${pad(tp.m)}-${pad(tp.d)}`;

    // 當日 00:00（台北）起，多抓一天避免漏跨午夜（深夜班最晚 00:45 結束）
    const dayStart = tpeEpoch(y, m, d, 0, 0);
    const dayEnd = dayStart + 86400000;          // 隔日 00:00
    const timeMin = new Date(dayStart).toISOString();
    const timeMax = new Date(dayStart + 2 * 86400000).toISOString();

    const [teachers, shifts, hol, snaps] = await Promise.all([
      sbGet("teachers?select=staff_id,name,branch,calendar_id,is_trainee,active,sort,avatar&active=eq.true&order=branch,sort,name"),
      sbGet(`teacher_shift?select=staff_id,from_min,to_min&work_date=eq.${dateKey}`),
      sbGet(`holidays?select=day,name&day=eq.${dateKey}`),
      sbGet(`capacity_daily?select=branch,kind,hours,headcount,is_holiday,grade,detail,snapshot_at&work_date=eq.${dateKey}`),
    ]);
    const shiftMap: Record<string, Shift> = {};
    for (const s of shifts) shiftMap[s.staff_id] = (s.to_min > 0) ? { fromMin: s.from_min, toMin: s.to_min } : null;
    const wd = new Date(dayStart + TPE).getUTCDay();
    const isHoliday = wd === 0 || wd === 6 || hol.length > 0;

    const errors: string[] = [];
    const out = await Promise.all(teachers.map(async (t: any) => {
      let events: Ev[] = [];
      if (t.calendar_id) {
        const r = await fetchEvents(t.calendar_id, timeMin, timeMax);
        if (!r.ok) errors.push(t.name);
        // 當日 00:00 – 24:00 開始的事件全留；隔日 00:00 – 06:00 開始的只留預約（深夜班跨午夜仍算當日），占用不跨日
        events = r.events.filter(ev => {
          const s = Date.parse(ev.start);
          if (s < dayStart) return false;
          if (s < dayEnd) return true;
          return ev.kind === "booking" && s < dayEnd + 6 * 3600000;
        });
      }
      return {
        staffId: t.staff_id, name: t.name, branch: t.branch,
        isTrainee: !!t.is_trainee, avatar: t.avatar || "",
        shift: shiftMap[t.staff_id] ?? null,
        events,
      };
    }));

    // 量能：每店 計畫 vs 實績
    const branches: Record<string, any> = {};
    for (const br of ["南京三民", "中山"]) {
      const list = out.filter(t => t.branch === br);
      const tc: TeacherCap[] = list.map(t => {
        const plan: [number, number] | null = t.shift ? [t.shift.fromMin, t.shift.toMin] : null;
        const { iv, cut } = actualInterval(t.shift, t.events, dayStart);
        return { staffId: t.staffId, name: t.name, plan, actual: iv, planHours: r2(hoursOf(plan)), actualHours: r2(hoursOf(iv)), cut };
      });
      const pH = r2(tc.reduce((s, x) => s + x.planHours, 0)), pN = tc.filter(x => x.planHours > 0).length;
      const aH = r2(tc.reduce((s, x) => s + x.actualHours, 0)), aN = tc.filter(x => x.actualHours > 0).length;
      const stored: Record<string, any> = {};
      for (const s of snaps) if (s.branch === br) stored[s.kind] = { hours: +s.hours, headcount: s.headcount, grade: s.grade, snapshotAt: s.snapshot_at };
      branches[br] = {
        plan: { hours: pH, headcount: pN, grade: grade(pH, pN, isHoliday) },
        actual: { hours: aH, headcount: aN, grade: grade(aH, aN, isHoliday) },
        stored,
        teachers: tc,
      };
    }
    const capacity = { isHoliday, holidayName: hol[0]?.name || null, thresholds: TH, branches };

    // 快照：cron 或管理員手動 ?snapshot=plan|actual
    let snapshotResult: any = null;
    if (snapshot) {
      const rows = Object.entries(branches).map(([br, c]: [string, any]) => ({
        work_date: dateKey, branch: br, kind: snapshot,
        hours: c[snapshot].hours, headcount: c[snapshot].headcount, is_holiday: isHoliday, grade: c[snapshot].grade,
        detail: { teachers: c.teachers, calendarErrors: errors, plan: c.plan, actual: c.actual },
        snapshot_at: new Date(now).toISOString(),
      }));
      await sbUpsert("capacity_daily", rows);
      snapshotResult = { kind: snapshot, date: dateKey, rows: rows.map(r => ({ branch: r.branch, hours: r.hours, headcount: r.headcount, grade: r.grade })) };
      if (cron) return json({ ok: true, snapshot: snapshotResult });
    } else if (dateKey < todayKey && !errors.length) {
      // 補記：過去日期若尚無實績快照，順手記下（cron 漏跑時的保險）
      const missing = Object.entries(branches).filter(([, c]: [string, any]) => !c.stored.actual);
      if (missing.length) {
        await sbUpsert("capacity_daily", missing.map(([br, c]: [string, any]) => ({
          work_date: dateKey, branch: br, kind: "actual",
          hours: c.actual.hours, headcount: c.actual.headcount, is_holiday: isHoliday, grade: c.actual.grade,
          detail: { teachers: c.teachers, calendarErrors: errors, plan: c.plan, actual: c.actual, lazy: true },
          snapshot_at: new Date(now).toISOString(),
        })));
        for (const [br, c] of missing) c.stored.actual = { hours: c.actual.hours, headcount: c.actual.headcount, grade: c.actual.grade, snapshotAt: new Date(now).toISOString(), lazy: true };
      }
    }

    const body: any = { date: dateKey, fetchedAt: now, buffer: BUFFER, teachers: out, capacity };
    if (snapshotResult) body.snapshot = snapshotResult;
    if (errors.length) body.calendarErrors = errors;
    return json(body);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

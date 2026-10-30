"use strict";
const __M = {};
__M["core/kv.js"] = (() => {
// لایه ذخیره‌سازی: یک رابط ساده + پیاده‌سازی IndexedDB (مرورگر) و حافظه (تست)
const STORES = ['meta', 'mem', 'ent', 'blob', 'queue', 'tomb', 'sync', 'conflict'];
class MemoryKV {
    d = new Map();
    /** برای تست خطای ذخیره‌سازی */
    failWrites = false;
    st(s) { let m = this.d.get(s); if (!m) {
        m = new Map();
        this.d.set(s, m);
    } return m; }
    async get(s, k) { const v = this.st(s).get(k); return v === undefined ? undefined : structuredClone(v); }
    async put(s, k, v) { if (this.failWrites)
        throw new DOMException('QuotaExceededError', 'QuotaExceededError'); this.st(s).set(k, structuredClone(v)); }
    async del(s, k) { this.st(s).delete(k); }
    async all(s) { return [...this.st(s).entries()].map(([k, v]) => [k, structuredClone(v)]); }
    async clear(s) { this.st(s).clear(); }
}
class IdbKV {
    db;
    static async open(name = 'sene-db') {
        const kv = new IdbKV();
        kv.db = await new Promise((res, rej) => {
            const r = indexedDB.open(name, 1);
            r.onupgradeneeded = () => { for (const s of STORES)
                if (!r.result.objectStoreNames.contains(s))
                    r.result.createObjectStore(s); };
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error ?? new Error('IndexedDB باز نشد'));
            r.onblocked = () => rej(new Error('IndexedDB مسدود است'));
        });
        return kv;
    }
    tx(s, mode, fn) {
        return new Promise((res, rej) => {
            const t = this.db.transaction(s, mode);
            const r = fn(t.objectStore(s));
            t.oncomplete = () => res(r.result);
            t.onerror = () => rej(t.error ?? r.error);
            t.onabort = () => rej(t.error ?? new Error('تراکنش لغو شد'));
        });
    }
    get(s, k) { return this.tx(s, 'readonly', (o) => o.get(k)); }
    async put(s, k, v) { await this.tx(s, 'readwrite', (o) => o.put(v, k)); }
    async del(s, k) { await this.tx(s, 'readwrite', (o) => o.delete(k)); }
    clear(s) { return this.tx(s, 'readwrite', (o) => o.clear()).then(() => undefined); }
    async all(s) {
        return new Promise((res, rej) => {
            const t = this.db.transaction(s, 'readonly');
            const o = t.objectStore(s);
            const out = [];
            const c = o.openCursor();
            c.onsuccess = () => { const cur = c.result; if (cur) {
                out.push([String(cur.key), cur.value]);
                cur.continue();
            } };
            t.oncomplete = () => res(out);
            t.onerror = () => rej(t.error);
        });
    }
    async estimate() {
        const e = await navigator.storage?.estimate?.();
        const persisted = await navigator.storage?.persisted?.();
        return { usage: e?.usage, quota: e?.quota, persisted };
    }
}

return { STORES, MemoryKV, IdbKV };
})();
__M["util/id.js"] = (() => {
function uid(prefix = '') {
    const b = new Uint8Array(10);
    crypto.getRandomValues(b);
    const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    return prefix + Date.now().toString(36) + hex;
}
function b64(bytes) {
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH)
        s += String.fromCharCode(...bytes.subarray(i, i + CH));
    return btoa(s);
}
function unb64(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i += 1)
        out[i] = s.charCodeAt(i);
    return out;
}
async function sha256Hex(data) {
    const d = await crypto.subtle.digest('SHA-256', data);
    return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

return { uid, b64, unb64, sha256Hex };
})();
__M["core/crypto.js"] = (() => {
// رمزگذاری با Web Crypto: PBKDF2 (SHA-256) برای مشتق‌سازی کلید و AES-256-GCM برای داده‌ها
const { b64, unb64 } = __M["util/id.js"];
const KDF_ITERATIONS = 310_000; // پیش‌فرض OWASP برای PBKDF2-SHA256
const CHUNK = 1024 * 1024; // قطعه‌بندی فایل‌های بزرگ (۱ مگابایت)
const enc = new TextEncoder();
const dec = new TextDecoder();
function randomBytes(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
async function deriveKey(password, p) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(p.salt), iterations: p.iterations }, base, { name: 'AES-GCM', length: 256 }, false, // کلید قابل استخراج نیست
    ['encrypt', 'decrypt']);
}
function newKdfParams(iterations = KDF_ITERATIONS) {
    return { kdf: 'PBKDF2-SHA256', iterations, salt: b64(randomBytes(16)) };
}
/** هر رمزگذاری IV تصادفی ۱۲ بایتی جدید دارد؛ aad رکورد را به شناسه‌اش می‌بندد (جلوگیری از جابه‌جایی رکوردها) */
async function encryptJson(key, value, aad) {
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(value)));
    return { v: 1, iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function decryptJson(key, env, aad) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv), additionalData: enc.encode(aad) }, key, unb64(env.ct));
    return JSON.parse(dec.decode(pt));
}
/** رمزگذاری بایت‌ها به‌صورت قطعه‌های مستقل: [iv(12)+ciphertext] برای هر قطعه */
async function encryptBytes(key, data, aad) {
    const out = [];
    const total = Math.max(1, Math.ceil(data.length / CHUNK));
    for (let i = 0; i < total; i += 1) {
        const iv = randomBytes(12);
        const part = data.subarray(i * CHUNK, (i + 1) * CHUNK);
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(`${aad}#${i}/${total}`) }, key, part));
        const chunk = new Uint8Array(12 + ct.length);
        chunk.set(iv, 0);
        chunk.set(ct, 12);
        out.push(chunk);
    }
    return out;
}
async function decryptBytes(key, chunks, aad) {
    const parts = [];
    for (let i = 0; i < chunks.length; i += 1) {
        const c = chunks[i];
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.subarray(0, 12), additionalData: enc.encode(`${aad}#${i}/${chunks.length}`) }, key, c.subarray(12));
        parts.push(new Uint8Array(pt));
    }
    const len = parts.reduce((a, p) => a + p.length, 0);
    const res = new Uint8Array(len);
    let o = 0;
    for (const p of parts) {
        res.set(p, o);
        o += p.length;
    }
    return res;
}
/** قطعه‌ها را برای آپلود/پشتیبان به یک بایت‌آرایه تبدیل می‌کند: [count u32][len u32 + data]... */
function packChunks(chunks) {
    const size = 4 + chunks.reduce((a, c) => a + 4 + c.length, 0);
    const out = new Uint8Array(size);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, chunks.length);
    let o = 4;
    for (const c of chunks) {
        dv.setUint32(o, c.length);
        o += 4;
        out.set(c, o);
        o += c.length;
    }
    return out;
}
function unpackChunks(buf) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const n = dv.getUint32(0);
    const res = [];
    let o = 4;
    for (let i = 0; i < n; i += 1) {
        const l = dv.getUint32(o);
        o += 4;
        if (o + l > buf.length)
            throw new Error('فایل خراب است');
        res.push(buf.subarray(o, o + l));
        o += l;
    }
    return res;
}

return { KDF_ITERATIONS, CHUNK, randomBytes, deriveKey, newKdfParams, encryptJson, decryptJson, encryptBytes, decryptBytes, packChunks, unpackChunks };
})();
__M["core/vault.js"] = (() => {
const { decryptJson, deriveKey, encryptJson, newKdfParams, KDF_ITERATIONS } = __M["core/crypto.js"];
const VERIFY_TEXT = { sene: 'ok' };
const MIN_PASSWORD = 8;
class WrongPassword extends Error {
    constructor() { super('رمز نادرست است'); }
}
class LockedOut extends Error {
    until;
    constructor(until) {
        super('به‌دلیل ورودهای اشتباه موقتاً قفل است');
        this.until = until;
    }
}
function passwordStrengthError(p) {
    if (p.length < MIN_PASSWORD)
        return `رمز باید دست‌کم ${MIN_PASSWORD} نویسه باشد`;
    if (/^(.)\1+$/.test(p))
        return 'رمز بسیار ساده است';
    return null;
}
class Vault {
    kv;
    iterations;
    key = null;
    constructor(kv, iterations = KDF_ITERATIONS) {
        this.kv = kv;
        this.iterations = iterations;
    }
    async header() { return this.kv.get('meta', 'vault'); }
    async exists() { return !!(await this.header()); }
    get unlocked() { return !!this.key; }
    async create(password) {
        const err = passwordStrengthError(password);
        if (err)
            throw new Error(err);
        if (await this.exists())
            throw new Error('گاوصندوق از قبل ساخته شده است');
        const p = newKdfParams(this.iterations);
        const key = await deriveKey(password, p);
        const header = { v: 1, ...p, verifier: await encryptJson(key, VERIFY_TEXT, 'vault'), createdAt: new Date().toISOString() };
        await this.kv.put('meta', 'vault', header);
        this.key = key;
    }
    /** پس از هر ورود اشتباه، تأخیر نمایی (۱، ۲، ۴، … حداکثر ۳۰۰ ثانیه) از ششمین خطا به بعد */
    async lockoutRemaining() {
        const s = await this.kv.get('meta', 'lockout');
        return s ? Math.max(0, s.until - Date.now()) : 0;
    }
    async unlock(password) {
        const rem = await this.lockoutRemaining();
        if (rem > 0)
            throw new LockedOut(Date.now() + rem);
        const h = await this.header();
        if (!h)
            throw new Error('گاوصندوقی ساخته نشده است');
        const key = await deriveKey(password, h);
        try {
            await decryptJson(key, h.verifier, 'vault');
        }
        catch {
            const s = (await this.kv.get('meta', 'lockout')) ?? { fails: 0, until: 0 };
            s.fails += 1;
            s.until = s.fails >= 5 ? Date.now() + Math.min(300, 2 ** (s.fails - 5)) * 1000 : 0;
            await this.kv.put('meta', 'lockout', s);
            throw new WrongPassword();
        }
        await this.kv.put('meta', 'lockout', { fails: 0, until: 0 });
        this.key = key;
    }
    lock() { this.key = null; }
    /** بررسی رمز بدون تغییر وضعیت (برای تأیید عملیات حساس) */
    async verify(password) {
        const h = await this.header();
        if (!h)
            return false;
        try {
            await decryptJson(await deriveKey(password, h), h.verifier, 'vault');
            return true;
        }
        catch {
            return false;
        }
    }
}

return { MIN_PASSWORD, WrongPassword, LockedOut, passwordStrengthError, Vault };
})();
__M["core/types.js"] = (() => {
const DEFAULT_CATEGORIES = ['خاطرات روزانه', 'افکار', 'احساسات', 'روابط', 'تصمیم‌ها و پیامدها', 'اهداف', 'سلامت و عادت‌ها', 'امور مالی', 'رسانه‌ها', 'رؤیاها'];
const MOODS = [
    { score: 1, label: 'خیلی بد', emoji: '😞' }, { score: 2, label: 'بد', emoji: '🙁' }, { score: 3, label: 'معمولی', emoji: '😐' },
    { score: 4, label: 'خوب', emoji: '🙂' }, { score: 5, label: 'عالی', emoji: '😄' },
];
const DEFAULT_SETTINGS = {
    mode: 'simple', theme: 'auto', accent: 'indigo', font: 'system', fontSize: 100, lineHeight: 1.8, lockMinutes: 5,
    customCategories: [], showGregorian: true, online: { drive: false, externalAi: false },
    driveClientId: '', driveFolderName: 'sene', driveFolderId: '', autoSync: true,
    reminders: { morning: null, evening: null, night: null },
    ai: { endpoint: '', model: '', apiKey: '', provider: 'openai' },
};

return { DEFAULT_CATEGORIES, MOODS, DEFAULT_SETTINGS };
})();
__M["util/jalali.js"] = (() => {
const breaks = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178];
function div(a, b) { return ~~(a / b); }
function mod(a, b) { return a - ~~(a / b) * b; }
function jalCal(jy) {
    const bl = breaks.length;
    const gy = jy + 621;
    let leapJ = -14;
    let jp = breaks[0];
    let jump = 0;
    for (let i = 1; i < bl; i += 1) {
        const jm = breaks[i];
        jump = jm - jp;
        if (jy < jm)
            break;
        leapJ = leapJ + div(jump, 33) * 8 + div(mod(jump, 33), 4);
        jp = jm;
    }
    let n = jy - jp;
    leapJ = leapJ + div(n, 33) * 8 + div(mod(n, 33) + 3, 4);
    if (mod(jump, 33) === 4 && jump - n === 4)
        leapJ += 1;
    const leapG = div(gy, 4) - div((div(gy, 100) + 1) * 3, 4) - 150;
    const march = 20 + leapJ - leapG;
    if (jump - n < 6)
        n = n - jump + div(jump + 4, 33) * 33;
    let leap = mod(mod(n + 1, 33) - 1, 4);
    if (leap === -1)
        leap = 4;
    return { leap, gy, march };
}
function g2d(gy, gm, gd) {
    let d = div((gy + div(gm - 8, 6) + 100100) * 1461, 4) + div(153 * mod(gm + 9, 12) + 2, 5) + gd - 34840408;
    d = d - div(div(gy + 100100 + div(gm - 8, 6), 100) * 3, 4) + 752;
    return d;
}
function d2g(jdn) {
    let j = 4 * jdn + 139361631;
    j = j + div(div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908;
    const i = div(mod(j, 1461), 4) * 5 + 308;
    const gd = div(mod(i, 153), 5) + 1;
    const gm = mod(div(i, 153), 12) + 1;
    const gy = div(j, 1461) - 100100 + div(8 - gm, 6);
    return { y: gy, m: gm, d: gd };
}
function j2d(jy, jm, jd) {
    const r = jalCal(jy);
    return g2d(r.gy, 3, r.march) + (jm - 1) * 31 - div(jm, 7) * (jm - 7) + jd - 1;
}
function d2j(jdn) {
    const g = d2g(jdn);
    let jy = g.y - 621;
    const r = jalCal(jy);
    const jdn1f = g2d(g.y, 3, r.march);
    let k = jdn - jdn1f;
    if (k >= 0) {
        if (k <= 185)
            return { y: jy, m: 1 + div(k, 31), d: mod(k, 31) + 1 };
        k -= 186;
    }
    else {
        jy -= 1;
        k += 179;
        if (r.leap === 1)
            k += 1;
    }
    return { y: jy, m: 7 + div(k, 30), d: mod(k, 30) + 1 };
}
function toJalali(gy, gm, gd) { return d2j(g2d(gy, gm, gd)); }
function toGregorian(jy, jm, jd) { return d2g(j2d(jy, jm, jd)); }
function isJalaliLeap(jy) { return jalCal(jy).leap === 0; }
function jalaliMonthLength(jy, jm) {
    if (jm <= 6)
        return 31;
    if (jm <= 11)
        return 30;
    return isJalaliLeap(jy) ? 30 : 29;
}
function isValidJalali(y, m, d) {
    return Number.isInteger(y) && Number.isInteger(m) && Number.isInteger(d) && m >= 1 && m <= 12 && d >= 1 && d <= jalaliMonthLength(y, m);
}
const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const GREG_MONTHS = ['ژانویه', 'فوریه', 'مارس', 'آوریل', 'مه', 'ژوئن', 'ژوئیه', 'اوت', 'سپتامبر', 'اکتبر', 'نوامبر', 'دسامبر'];
// هفته از شنبه شروع می‌شود
const WEEKDAYS = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'];
const WEEKDAYS_SHORT = ['ش', 'ی', 'د', 'س', 'چ', 'پ', 'ج'];
/** شاخص روز هفته با شنبه=۰ */
function weekdayIndex(date) { return (date.getDay() + 1) % 7; }
const FA_DIGITS = '۰۱۲۳۴۵۶۷۸۹';
function faDigits(s) { return String(s).replace(/\d/g, (d) => FA_DIGITS[+d]); }
function enDigits(s) {
    return s.replace(/[۰-۹]/g, (d) => String(FA_DIGITS.indexOf(d))).replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660));
}
const pad2 = (n) => String(n).padStart(2, '0');
function dateToJalali(date) { return toJalali(date.getFullYear(), date.getMonth() + 1, date.getDate()); }
function jalaliToDate(y, m, d, hh = 0, mm = 0, ss = 0) {
    const g = toGregorian(y, m, d);
    return new Date(g.y, g.m - 1, g.d, hh, mm, ss);
}
function formatJalali(date, opts = {}) {
    const j = dateToJalali(date);
    let s = `${faDigits(j.d)} ${JALALI_MONTHS[j.m - 1]} ${faDigits(j.y)}`;
    if (opts.weekday)
        s = `${WEEKDAYS[weekdayIndex(date)]} ${s}`;
    if (opts.time)
        s += `، ${faDigits(pad2(date.getHours()))}:${faDigits(pad2(date.getMinutes()))}${opts.seconds ? ':' + faDigits(pad2(date.getSeconds())) : ''}`;
    return s;
}
function formatGregorian(date, opts = {}) {
    let s = `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
    if (opts.time)
        s += ` ${pad2(date.getHours())}:${pad2(date.getMinutes())}${opts.seconds ? ':' + pad2(date.getSeconds()) : ''}`;
    return s;
}
function jalaliKey(date) { const j = dateToJalali(date); return `${j.y}-${pad2(j.m)}-${pad2(j.d)}`; }
function dayKey(date) { return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`; }

return { toJalali, toGregorian, isJalaliLeap, jalaliMonthLength, isValidJalali, JALALI_MONTHS, GREG_MONTHS, WEEKDAYS, WEEKDAYS_SHORT, weekdayIndex, faDigits, enDigits, pad2, dateToJalali, jalaliToDate, formatJalali, formatGregorian, jalaliKey, dayKey };
})();
__M["util/text.js"] = (() => {
// نرمال‌سازی و توکن‌سازی متن فارسی/انگلیسی
const { enDigits } = __M["util/jalali.js"];
function normalize(s) {
    return enDigits(s)
        .replace(/[\u064B-\u065F\u0670\u0640]/g, '')
        .replace(/[يى]/g, 'ی')
        .replace(/ك/g, 'ک')
        .replace(/[أإآ]/g, 'ا')
        .replace(/ۀ|ة/g, 'ه')
        .replace(/\u200c/g, ' ')
        .replace(/[^\p{L}\p{N}\s]/gu, ' ')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
}
const STOP = new Set('و در به از که را این آن با برای است بود شد شده می هم یا اما تا هر یک بر هیچ من تو او ما شما خود نیز اگر پس ولی چون چه کرد کردم کنم کرده بعد قبل روز امروز دیروز خیلی داشتم دارم باید the a an and or of to in is was i it for on with at'.split(' ').map((w) => normalize(w)));
function tokenize(s) {
    return normalize(s).split(' ').filter((t) => t.length > 1 && !STOP.has(t));
}
function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function uniq(a) { return [...new Set(a)]; }
function splitList(s) {
    return uniq(s.split(/[,،;؛\n]/).map((x) => x.trim()).filter(Boolean));
}

return { normalize, tokenize, escapeHtml, uniq, splitList };
})();
__M["core/archive.js"] = (() => {
const { decryptBytes, decryptJson, encryptBytes, encryptJson } = __M["core/crypto.js"];
const { DEFAULT_SETTINGS } = __M["core/types.js"];
const { uid, sha256Hex } = __M["util/id.js"];
const { uniq } = __M["util/text.js"];
const itemKey = (store, id) => `${store}.${id}`;
class ValidationError extends Error {
}
function kindOfMime(m) {
    if (m.startsWith('image/'))
        return 'image';
    if (m.startsWith('video/'))
        return 'video';
    if (m.startsWith('audio/'))
        return 'audio';
    return 'file';
}
const clean = (a) => uniq((a ?? []).map((s) => s.trim()).filter(Boolean));
class Archive {
    kv;
    vault;
    deviceId;
    memories = new Map();
    profile = { interests: [], goals: [], values: [], habits: [], preferences: [], confirmed: [], notes: '' };
    people = new Map();
    insights = new Map();
    listeners = new Set();
    constructor(kv, vault, deviceId) {
        this.kv = kv;
        this.vault = vault;
        this.deviceId = deviceId;
    }
    get key() { if (!this.vault.key)
        throw new Error('برنامه قفل است'); return this.vault.key; }
    onChange(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
    emit() { this.listeners.forEach((f) => f()); }
    // ---------- تنظیمات (غیرحساس، قابل خواندن پیش از ورود) ----------
    async loadSettings() {
        const s = (await this.kv.get('meta', 'settings')) ?? {};
        return { ...DEFAULT_SETTINGS, ...s, online: { ...DEFAULT_SETTINGS.online, ...(s.online ?? {}) }, reminders: { ...DEFAULT_SETTINGS.reminders, ...(s.reminders ?? {}) }, ai: { ...DEFAULT_SETTINGS.ai, ...(s.ai ?? {}), apiKey: '' } };
    }
    async saveSettings(s) {
        await this.kv.put('meta', 'settings', { ...s, ai: { ...s.ai, apiKey: '' } });
    }
    /** کلید API (در صورت استفاده) فقط به‌صورت رمزگذاری‌شده و همگام‌نشده نگهداری می‌شود */
    async getSecret() {
        const env = await this.kv.get('meta', 'secret');
        return env ? decryptJson(this.key, env, 'secret') : { aiKey: '' };
    }
    async setSecret(v) { await this.kv.put('meta', 'secret', await encryptJson(this.key, v, 'secret')); }
    // ---------- پیش‌نویس خودکار (رمزگذاری‌شده، همگام‌نشده) ----------
    async getDraft() { const e = await this.kv.get('meta', 'draft'); if (!e)
        return null; try {
        return await decryptJson(this.key, e, 'draft');
    }
    catch {
        return null;
    } }
    async setDraft(v) { await this.kv.put('meta', 'draft', await encryptJson(this.key, v, 'draft')); }
    async clearDraft() { await this.kv.del('meta', 'draft'); }
    // ---------- بارگذاری ----------
    async load() {
        const corrupted = [];
        this.memories.clear();
        this.people.clear();
        this.insights.clear();
        for (const [id, rec] of await this.kv.all('mem')) {
            try {
                const m = await decryptJson(this.key, rec.env, `mem:${id}`);
                m.rev = rec.rev;
                this.memories.set(id, m);
            }
            catch {
                corrupted.push(itemKey('mem', id));
            }
        }
        for (const [id, rec] of await this.kv.all('ent')) {
            try {
                const v = await decryptJson(this.key, rec.env, `ent:${id}`);
                if (id === 'profile')
                    this.profile = { ...this.profile, ...v };
                else if (id.startsWith('person:'))
                    this.people.set(id, v);
                else if (id.startsWith('insight:'))
                    this.insights.set(id, v);
            }
            catch {
                corrupted.push(itemKey('ent', id));
            }
        }
        this.emit();
        return { corrupted };
    }
    unloadMemoryCache() { this.memories.clear(); this.people.clear(); this.insights.clear(); this.profile = { interests: [], goals: [], values: [], habits: [], preferences: [], confirmed: [], notes: '' }; }
    // ---------- صف ----------
    async enqueue(store, id, op) {
        const key = itemKey(store, id);
        const q = { key, store, id, op, at: new Date().toISOString(), attempts: 0 };
        await this.kv.put('queue', key, q);
    }
    async queue() { return (await this.kv.all('queue')).map(([, v]) => v).sort((a, b) => a.at.localeCompare(b.at)); }
    async tombstones() { return (await this.kv.all('tomb')).map(([, v]) => v); }
    async writeRec(store, id, value, rev) {
        const env = await encryptJson(this.key, value, `${store}:${id}`);
        const rec = { id, rev, updatedAt: new Date().toISOString(), env };
        await this.kv.put(store, id, rec);
        await this.kv.del('tomb', itemKey(store, id));
        await this.enqueue(store, id, 'put');
    }
    /** نسخهٔ رمزگذاری‌شده را مستقیماً (بدون تغییر rev) می‌نویسد — برای دریافت از Drive/بازیابی */
    async putRawRecord(store, rec) { await this.kv.put(store, rec.id, rec); await this.kv.del('tomb', itemKey(store, rec.id)); }
    // ---------- خاطرات ----------
    async createMemory(input) {
        const text = (input.text ?? '').trim();
        const now = new Date();
        const eventAt = input.eventAt ?? now;
        if (Number.isNaN(eventAt.getTime()))
            throw new ValidationError('تاریخ وقوع معتبر نیست');
        const id = uid('m');
        const m = {
            id, text, originalText: text, createdAt: now.toISOString(), tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
            eventAt: eventAt.toISOString(), eventAtHistory: [], updatedAt: now.toISOString(), mood: input.mood ?? null,
            category: input.category ?? 'خاطرات روزانه', tags: clean(input.tags), people: clean(input.people), events: clean(input.events),
            decisions: (input.decisions ?? '').trim(), goals: (input.goals ?? '').trim(), outcomes: (input.outcomes ?? '').trim(),
            attachments: [], context: { online: typeof navigator !== 'undefined' ? navigator.onLine : true, source: input.source ?? 'quick', userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined },
            links: clean(input.links), revisions: [], rev: 1,
        };
        await this.writeRec('mem', id, m, 1);
        this.memories.set(id, m);
        this.emit();
        return m;
    }
    async updateMemory(id, patch) {
        const cur = this.memories.get(id);
        if (!cur)
            throw new ValidationError('خاطره پیدا نشد');
        const m = structuredClone(cur);
        const now = new Date().toISOString();
        if (patch.text !== undefined && patch.text.trim() !== cur.text) {
            m.revisions.push({ at: now, field: 'text', before: cur.text });
            m.text = patch.text.trim();
        }
        if (patch.eventAt !== undefined && patch.eventAt !== cur.eventAt) {
            if (Number.isNaN(new Date(patch.eventAt).getTime()))
                throw new ValidationError('تاریخ وقوع معتبر نیست');
            m.eventAtHistory.push({ at: now, from: cur.eventAt, to: patch.eventAt });
            m.eventAt = patch.eventAt;
        }
        for (const f of ['mood', 'category', 'decisions', 'goals', 'outcomes'])
            if (patch[f] !== undefined)
                m[f] = patch[f];
        for (const f of ['tags', 'people', 'events', 'links'])
            if (patch[f] !== undefined)
                m[f] = clean(patch[f]);
        m.updatedAt = now;
        m.rev = cur.rev + 1;
        await this.writeRec('mem', id, m, m.rev);
        this.memories.set(id, m);
        this.emit();
        return m;
    }
    async deleteMemory(id) {
        const m = this.memories.get(id);
        if (!m)
            return;
        const now = new Date().toISOString();
        for (const a of m.attachments)
            await this.removeBlob(a.id);
        await this.kv.del('mem', id);
        await this.kv.put('tomb', itemKey('mem', id), { key: itemKey('mem', id), store: 'mem', id, deletedAt: now });
        await this.enqueue('mem', id, 'delete');
        this.memories.delete(id);
        // پاک‌کردن ارجاع‌های سایر خاطره‌ها به این مورد
        for (const o of [...this.memories.values()])
            if (o.links.includes(id))
                await this.updateMemory(o.id, { links: o.links.filter((x) => x !== id) });
        this.emit();
    }
    // ---------- پیوست‌ها ----------
    async addAttachment(memId, file, extra = {}) {
        const m = this.memories.get(memId);
        if (!m)
            throw new ValidationError('خاطره پیدا نشد');
        const buf = new Uint8Array(await file.arrayBuffer());
        const id = uid('a');
        const att = {
            id, name: file.name || 'file', mime: file.type || 'application/octet-stream', size: buf.length, kind: kindOfMime(file.type || ''),
            addedAt: new Date().toISOString(), lastModified: file.lastModified, sha256: await sha256Hex(buf), ...extra,
        };
        const chunks = await encryptBytes(this.key, buf, `blob:${id}`); // فایل اصلی بدون تغییر؛ فقط رمزگذاری می‌شود
        await this.kv.put('blob', id, { id, memId, rev: 1, size: buf.length, chunks });
        await this.enqueue('blob', id, 'put');
        const m2 = structuredClone(m);
        m2.attachments.push(att);
        m2.updatedAt = new Date().toISOString();
        m2.rev += 1;
        await this.writeRec('mem', memId, m2, m2.rev);
        this.memories.set(memId, m2);
        this.emit();
        return att;
    }
    async getAttachmentBytes(att) {
        const rec = await this.kv.get('blob', att.id);
        if (!rec)
            throw new Error('فایل پیوست در این دستگاه موجود نیست (شاید هنوز همگام نشده است)');
        const bytes = await decryptBytes(this.key, rec.chunks, `blob:${att.id}`);
        if ((await sha256Hex(bytes)) !== att.sha256)
            throw new Error('یکپارچگی فایل تأیید نشد');
        return bytes;
    }
    async removeAttachment(memId, attId) {
        const m = this.memories.get(memId);
        if (!m)
            return;
        const m2 = structuredClone(m);
        m2.attachments = m2.attachments.filter((a) => a.id !== attId);
        m2.updatedAt = new Date().toISOString();
        m2.rev += 1;
        await this.removeBlob(attId);
        await this.writeRec('mem', memId, m2, m2.rev);
        this.memories.set(memId, m2);
        this.emit();
    }
    async setAttachmentText(memId, attId, text) {
        const m = this.memories.get(memId);
        if (!m)
            return;
        const m2 = structuredClone(m);
        const a = m2.attachments.find((x) => x.id === attId);
        if (!a)
            return;
        a.extractedText = text.trim() || undefined;
        m2.updatedAt = new Date().toISOString();
        m2.rev += 1;
        await this.writeRec('mem', memId, m2, m2.rev);
        this.memories.set(memId, m2);
        this.emit();
    }
    async removeBlob(id) {
        await this.kv.del('blob', id);
        await this.kv.put('tomb', itemKey('blob', id), { key: itemKey('blob', id), store: 'blob', id, deletedAt: new Date().toISOString() });
        await this.enqueue('blob', id, 'delete');
    }
    // ---------- موجودیت‌ها: پروفایل، اشخاص، برداشت‌ها ----------
    async saveProfile(p) { this.profile = p; await this.writeRec('ent', 'profile', p, ((await this.kv.get('ent', 'profile'))?.rev ?? 0) + 1); this.emit(); }
    async savePerson(p) {
        const id = p.id ?? `person:${uid()}`;
        const v = { ...p, id };
        await this.writeRec('ent', id, v, ((await this.kv.get('ent', id))?.rev ?? 0) + 1);
        this.people.set(id, v);
        this.emit();
        return v;
    }
    async saveInsight(i) {
        await this.writeRec('ent', i.id, i, ((await this.kv.get('ent', i.id))?.rev ?? 0) + 1);
        this.insights.set(i.id, i);
        this.emit();
    }
    async deleteEntity(id) {
        await this.kv.del('ent', id);
        await this.kv.put('tomb', itemKey('ent', id), { key: itemKey('ent', id), store: 'ent', id, deletedAt: new Date().toISOString() });
        await this.enqueue('ent', id, 'delete');
        this.people.delete(id);
        this.insights.delete(id);
        this.emit();
    }
    // ---------- یکپارچگی ----------
    async integrityCheck(deep = false) {
        const problems = [];
        let checked = 0;
        for (const [id, rec] of await this.kv.all('mem')) {
            checked += 1;
            try {
                const m = await decryptJson(this.key, rec.env, `mem:${id}`);
                if (m.id !== id)
                    problems.push({ key: itemKey('mem', id), problem: 'شناسهٔ داخلی با کلید رکورد نمی‌خواند' });
                for (const a of m.attachments) {
                    const b = await this.kv.get('blob', a.id);
                    if (!b) {
                        problems.push({ key: itemKey('blob', a.id), problem: `پیوست «${a.name}» در این دستگاه نیست` });
                        continue;
                    }
                    if (deep) {
                        try {
                            await this.getAttachmentBytes(a);
                        }
                        catch {
                            problems.push({ key: itemKey('blob', a.id), problem: `پیوست «${a.name}» خراب است` });
                        }
                    }
                }
            }
            catch {
                problems.push({ key: itemKey('mem', id), problem: 'رمزگشایی ناموفق: داده تغییر کرده یا خراب است' });
            }
        }
        for (const [id, rec] of await this.kv.all('ent')) {
            checked += 1;
            try {
                await decryptJson(this.key, rec.env, `ent:${id}`);
            }
            catch {
                problems.push({ key: itemKey('ent', id), problem: 'رمزگشایی ناموفق' });
            }
        }
        return { checked, problems };
    }
    async storageSummary() {
        const blobs = await this.kv.all('blob');
        const attachmentBytes = blobs.reduce((a, [, b]) => a + b.size, 0);
        const est = (await this.kv.estimate?.()) ?? {};
        return { memories: this.memories.size, attachments: blobs.length, attachmentBytes, ...est };
    }
}

return { itemKey, ValidationError, kindOfMime, Archive };
})();
__M["sync/drive.js"] = (() => {
// رابط Drive + پیاده‌سازی واقعی Google Drive (REST) + Drive آزمایشی درون‌حافظه‌ای برای تست محلی
const { sha256Hex } = __M["util/id.js"];
class AuthError extends Error {
    constructor(m = 'مجوز Google منقضی یا رد شده است') { super(m); }
}
class NetworkError extends Error {
    constructor(m = 'اتصال اینترنت برقرار نیست') { super(m); }
}
class DriveError extends Error {
    status;
    constructor(status, m) {
        super(m);
        this.status = status;
    }
}
// ---------- Drive واقعی ----------
const API = 'https://www.googleapis.com/drive/v3';
const UPLOAD = 'https://www.googleapis.com/upload/drive/v3';
class GoogleDriveApi {
    getToken;
    fetchFn;
    constructor(getToken, fetchFn = (...a) => fetch(...a)) {
        this.getToken = getToken;
        this.fetchFn = fetchFn;
    }
    async req(url, init = {}, attempt = 0) {
        const token = await this.getToken();
        let res;
        try {
            res = await this.fetchFn(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token}` } });
        }
        catch {
            throw new NetworkError();
        }
        if (res.status === 401)
            throw new AuthError();
        if ((res.status === 429 || res.status >= 500) && attempt < 3) {
            await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
            return this.req(url, init, attempt + 1);
        }
        if (!res.ok) {
            const body = await res.text().catch(() => '');
            if (res.status === 403 && /insufficientPermissions|forbidden|PERMISSION/i.test(body))
                throw new AuthError('دسترسی کافی به Drive داده نشده است');
            throw new DriveError(res.status, `خطای Drive (${res.status}): ${body.slice(0, 200)}`);
        }
        return res;
    }
    async ensureFolder(name, folderId) {
        if (folderId) {
            try {
                const r = await this.req(`${API}/files/${folderId}?fields=id,trashed`);
                const j = await r.json();
                if (!j.trashed)
                    return j.id;
            }
            catch (e) {
                if (!(e instanceof DriveError) || e.status !== 404)
                    throw e;
            }
        }
        const q = encodeURIComponent(`name='${name.replace(/'/g, "\\'")}' and mimeType='application/vnd.google-apps.folder' and trashed=false`);
        const found = await (await this.req(`${API}/files?q=${q}&fields=files(id)&pageSize=1`)).json();
        if (found.files?.[0])
            return found.files[0].id;
        const created = await (await this.req(`${API}/files?fields=id`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, mimeType: 'application/vnd.google-apps.folder' }) })).json();
        return created.id;
    }
    async list(folderId) {
        const out = [];
        let page = '';
        do {
            const q = encodeURIComponent(`'${folderId}' in parents and trashed=false`);
            const j = await (await this.req(`${API}/files?q=${q}&pageSize=1000&fields=nextPageToken,files(id,name,appProperties,md5Checksum,modifiedTime,size)${page ? `&pageToken=${page}` : ''}`)).json();
            for (const f of j.files ?? [])
                out.push({ id: f.id, name: f.name, appProps: f.appProperties ?? {}, checksum: f.md5Checksum ?? '', modifiedTime: f.modifiedTime, size: Number(f.size ?? 0) });
            page = j.nextPageToken ?? '';
        } while (page);
        return out;
    }
    async upload(folderId, name, bytes, appProps, existingId) {
        const meta = existingId ? { appProperties: appProps } : { name, parents: [folderId], appProperties: appProps };
        const boundary = `sene${Math.random().toString(36).slice(2)}`;
        const body = new Blob([`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`, bytes, `\r\n--${boundary}--`]);
        const url = existingId ? `${UPLOAD}/files/${existingId}?uploadType=multipart&fields=id,name,appProperties,md5Checksum,modifiedTime,size` : `${UPLOAD}/files?uploadType=multipart&fields=id,name,appProperties,md5Checksum,modifiedTime,size`;
        const f = await (await this.req(url, { method: existingId ? 'PATCH' : 'POST', headers: { 'Content-Type': `multipart/related; boundary=${boundary}` }, body })).json();
        return { id: f.id, name: f.name, appProps: f.appProperties ?? {}, checksum: f.md5Checksum ?? '', modifiedTime: f.modifiedTime, size: Number(f.size ?? 0) };
    }
    async download(fileId) { return new Uint8Array(await (await this.req(`${API}/files/${fileId}?alt=media`)).arrayBuffer()); }
    async remove(fileId) { await this.req(`${API}/files/${fileId}`, { method: 'DELETE' }); }
}
// ---------- Drive آزمایشی (فقط برای تست) ----------
class MockDrive {
    files = new Map();
    folders = new Map();
    offline = false;
    authExpired = false;
    calls = [];
    n = 0;
    guard() { if (this.offline)
        throw new NetworkError(); if (this.authExpired)
        throw new AuthError(); }
    async ensureFolder(name, folderId) {
        this.guard();
        if (folderId && [...this.folders.values()].includes(folderId))
            return folderId;
        let id = this.folders.get(name);
        if (!id) {
            id = `folder${++this.n}`;
            this.folders.set(name, id);
        }
        return id;
    }
    async list(folderId) { this.guard(); return [...this.files.values()].filter((f) => f.folder === folderId).map(({ bytes, folder, ...r }) => ({ ...r })); }
    async upload(folderId, name, bytes, appProps, existingId) {
        this.guard();
        this.calls.push(`${existingId ? 'update' : 'create'}:${name}`);
        const id = existingId ?? `file${++this.n}`;
        const f = { id, name, appProps, checksum: await sha256Hex(bytes), modifiedTime: new Date().toISOString(), size: bytes.length, bytes: bytes.slice(), folder: folderId };
        this.files.set(id, f);
        const { bytes: _b, folder: _f, ...r } = f;
        return r;
    }
    async download(id) { this.guard(); const f = this.files.get(id); if (!f)
        throw new DriveError(404, 'پیدا نشد'); return f.bytes.slice(); }
    async remove(id) { this.guard(); this.calls.push(`remove:${id}`); this.files.delete(id); }
}

return { AuthError, NetworkError, DriveError, GoogleDriveApi, MockDrive };
})();
__M["sync/google-auth.js"] = (() => {
// ورود با OAuth رسمی Google (Google Identity Services). فقط کمینه‌دسترسی: drive.file
const { AuthError } = __M["sync/drive.js"];
const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
class GoogleAuth {
    clientId;
    token = '';
    expires = 0;
    script;
    constructor(clientId) {
        this.clientId = clientId;
    }
    get connected() { return !!this.token && Date.now() < this.expires; }
    signOut() { try {
        if (this.token)
            google?.accounts?.oauth2?.revoke?.(this.token, () => { });
    }
    catch { /* ignore */ } this.token = ''; this.expires = 0; }
    load() {
        if (typeof google !== 'undefined' && google.accounts?.oauth2)
            return Promise.resolve();
        this.script ??= new Promise((res, rej) => {
            const s = document.createElement('script');
            s.src = 'https://accounts.google.com/gsi/client';
            s.async = true;
            s.onload = () => res();
            s.onerror = () => { this.script = undefined; rej(new Error('بارگذاری اسکریپت ورود Google ممکن نشد (اینترنت یا مسدودسازی)')); };
            document.head.appendChild(s);
        });
        return this.script;
    }
    /** interactive=true باید از رویداد لمس کاربر صدا زده شود (مرورگر پنجرهٔ ورود را مسدود نکند) */
    async getToken(interactive) {
        if (this.connected)
            return this.token;
        const id = this.clientId().trim();
        if (!id)
            throw new AuthError('شناسهٔ OAuth (Client ID) در تنظیمات وارد نشده است');
        await this.load();
        return new Promise((res, rej) => {
            const client = google.accounts.oauth2.initTokenClient({
                client_id: id, scope: DRIVE_SCOPE, prompt: interactive ? 'consent' : '',
                callback: (r) => { if (r.error || !r.access_token)
                    rej(new AuthError(r.error_description || 'ورود به Google انجام نشد'));
                else {
                    this.token = r.access_token;
                    this.expires = Date.now() + (Number(r.expires_in) - 60) * 1000;
                    res(this.token);
                } },
                error_callback: (e) => rej(new AuthError(e?.type === 'popup_closed' ? 'پنجرهٔ ورود بسته شد' : 'ورود به Google انجام نشد')),
            });
            client.requestAccessToken();
        });
    }
}

return { DRIVE_SCOPE, GoogleAuth };
})();
__M["sync/engine.js"] = (() => {
// موتور همگام‌سازی دوطرفه: صف محلی، شناسایی تعارض، حذف همگام، بدون بازنویسی بی‌صدا
const { itemKey } = __M["core/archive.js"];
const { decryptJson, packChunks, unpackChunks } = __M["core/crypto.js"];
const { AuthError, NetworkError } = __M["sync/drive.js"];
const { uid } = __M["util/id.js"];
class VaultMismatch extends Error {
    constructor() { super('آرشیو موجود در Drive با رمز/گاوصندوق دیگری ساخته شده است. برای ادامه، همان رمز را در یک نصب تازه وارد کنید یا از پشتیبان بازیابی کنید.'); }
}
const enc = new TextEncoder();
const dec = new TextDecoder();
const dataName = (k) => `${encodeURIComponent(k)}.sene`;
const delName = (k) => `${encodeURIComponent(k)}.del`;
const VAULT_FILE = 'vault.json';
class SyncEngine {
    a;
    api;
    opts;
    running = false;
    onProgress;
    constructor(a, api, opts) {
        this.a = a;
        this.api = api;
        this.opts = opts;
    }
    async state(key) { return this.a.kv.get('sync', key); }
    isDirty = async (key) => !!(await this.a.kv.get('queue', key));
    async run() {
        if (this.running)
            throw new Error('همگام‌سازی در حال اجراست');
        this.running = true;
        const res = { uploaded: 0, downloaded: 0, deleted: 0, conflicts: 0, errors: [], at: new Date().toISOString() };
        let changedLocal = false;
        try {
            this.onProgress?.('اتصال به پوشهٔ Drive…');
            const folder = await this.api.ensureFolder(this.opts.folderName, this.opts.folderId);
            if (folder !== this.opts.folderId) {
                this.opts.folderId = folder;
                this.opts.onFolder?.(folder);
            }
            let remote = await this.api.list(folder);
            await this.checkVault(folder, remote);
            remote = remote.filter((f) => f.name !== VAULT_FILE);
            const byKey = new Map();
            const delByKey = new Map();
            for (const f of remote) {
                const k = f.appProps.k;
                if (!k)
                    continue;
                (f.name.endsWith('.del') ? delByKey : byKey).set(k, f);
            }
            const guard = async (key, fn) => {
                try {
                    await fn();
                }
                catch (e) {
                    if (e instanceof AuthError || e instanceof NetworkError)
                        throw e;
                    const msg = e instanceof Error ? e.message : String(e);
                    res.errors.push({ key, message: msg });
                    const q = await this.a.kv.get('queue', key);
                    if (q)
                        await this.a.kv.put('queue', key, { ...q, attempts: q.attempts + 1, lastError: msg });
                }
            };
            // ۱) حذف‌های محلی → Drive
            for (const t of await this.a.tombstones()) {
                if (t.syncedAt)
                    continue;
                await guard(t.key, async () => {
                    const rf = byKey.get(t.key);
                    const st = await this.state(t.key);
                    if (rf && st && st.checksum !== rf.checksum && t.store !== 'blob') {
                        await this.a.kv.put('conflict', t.key, { key: t.key, store: t.store, id: t.id, kind: 'local-deleted', detectedAt: new Date().toISOString(), remoteFileId: rf.id, remoteChecksum: rf.checksum });
                        res.conflicts += 1;
                        return;
                    }
                    if (rf)
                        await this.api.remove(rf.id);
                    if (!delByKey.has(t.key))
                        await this.api.upload(folder, delName(t.key), enc.encode(JSON.stringify({ deletedAt: t.deletedAt })), { k: t.key, del: '1' });
                    await this.a.kv.put('tomb', t.key, { ...t, syncedAt: new Date().toISOString() });
                    await this.a.kv.del('queue', t.key);
                    await this.a.kv.del('sync', t.key);
                    byKey.delete(t.key);
                    res.deleted += 1;
                });
            }
            const localTombKeys = new Set((await this.a.tombstones()).map((t) => t.key));
            // ۲) حذف‌های راه‌دور → محلی
            for (const [key, df] of delByKey) {
                if (localTombKeys.has(key))
                    continue;
                const [store, id] = splitKey(key);
                await guard(key, async () => {
                    const local = await this.a.kv.get(store, id);
                    if (!local)
                        return;
                    const st = await this.state(key);
                    const dirty = (await this.isDirty(key)) || !st;
                    if (dirty && store !== 'blob') {
                        await this.a.kv.put('conflict', key, { key, store, id, kind: 'remote-deleted', detectedAt: new Date().toISOString(), remoteFileId: df.id });
                        res.conflicts += 1;
                        return;
                    }
                    await this.a.kv.del(store, id);
                    await this.a.kv.del('sync', key);
                    await this.a.kv.del('queue', key);
                    res.deleted += 1;
                    changedLocal = true;
                    byKey.delete(key);
                });
            }
            // ۳) دریافت و تعارض
            for (const [key, rf] of byKey) {
                if (delByKey.has(key) || localTombKeys.has(key))
                    continue;
                if (await this.a.kv.get('conflict', key))
                    continue;
                const [store, id] = splitKey(key);
                await guard(key, async () => {
                    const local = await this.a.kv.get(store, id);
                    const st = await this.state(key);
                    if (!local) {
                        await this.pull(key, store, id, rf);
                        res.downloaded += 1;
                        changedLocal = true;
                        return;
                    }
                    const dirty = (await this.isDirty(key)) || !st;
                    const remoteChanged = !st || st.checksum !== rf.checksum;
                    if (!remoteChanged && !dirty)
                        return;
                    if (remoteChanged && !dirty) {
                        this.onProgress?.('دریافت تغییرات…');
                        await this.pull(key, store, id, rf);
                        res.downloaded += 1;
                        changedLocal = true;
                        return;
                    }
                    if (dirty && !remoteChanged)
                        return; // در مرحلهٔ ۴ ارسال می‌شود
                    // هر دو تغییر کرده‌اند
                    if (store === 'blob') {
                        await this.a.kv.put('sync', key, { remoteId: rf.id, checksum: rf.checksum, rev: 1 });
                        await this.a.kv.del('queue', key);
                        return;
                    }
                    const bytes = await this.api.download(rf.id);
                    if (dec.decode(bytes) === JSON.stringify(local)) {
                        await this.a.kv.put('sync', key, { remoteId: rf.id, checksum: rf.checksum, rev: local.rev });
                        await this.a.kv.del('queue', key);
                        return;
                    }
                    const remoteRec = JSON.parse(dec.decode(bytes));
                    await this.a.kv.put('conflict', key, { key, store, id, kind: 'both-changed', detectedAt: new Date().toISOString(), remoteFileId: rf.id, remoteChecksum: rf.checksum, remoteRec });
                    res.conflicts += 1;
                });
            }
            // ۴) ارسال تغییرات محلی
            for (const store of ['mem', 'ent', 'blob']) {
                for (const [id] of await this.a.kv.all(store)) {
                    const key = itemKey(store, id);
                    if (localTombKeys.has(key) || delByKey.has(key) || await this.a.kv.get('conflict', key))
                        continue;
                    const st = await this.state(key);
                    const rf = byKey.get(key);
                    const dirty = (await this.isDirty(key)) || !st || !rf;
                    if (!dirty)
                        continue;
                    if (rf && st && rf.checksum !== st.checksum)
                        continue; // تعارض/دریافت در مرحلهٔ ۳ رسیدگی شده
                    await guard(key, async () => {
                        this.onProgress?.(`ارسال ${store === 'blob' ? 'پیوست' : 'خاطره'}…`);
                        const local = await this.a.kv.get(store, id);
                        const bytes = store === 'blob' ? packChunks(local.chunks) : enc.encode(JSON.stringify(local));
                        const up = await this.api.upload(folder, dataName(key), bytes, { k: key, rev: String(local.rev ?? 1), ...(store === 'blob' ? { mem: String(local.memId ?? '') } : {}) }, rf?.id ?? st?.remoteId);
                        await this.a.kv.put('sync', key, { remoteId: up.id, checksum: up.checksum, rev: local.rev ?? 1 });
                        await this.a.kv.del('queue', key);
                        res.uploaded += 1;
                    });
                }
            }
            // ثبت‌های صف که دیگر مورد محلی ندارند و حذف هم نشده‌اند
            for (const q of await this.a.queue())
                if (q.op === 'put' && !(await this.a.kv.get(q.store, q.id)))
                    await this.a.kv.del('queue', q.key);
            await this.a.kv.put('meta', 'lastSync', { at: res.at, errors: res.errors.length, conflicts: await this.conflictCount() });
            return res;
        }
        catch (e) {
            await this.a.kv.put('meta', 'lastSync', { at: res.at, fatal: e instanceof Error ? e.message : String(e) });
            throw e;
        }
        finally {
            this.running = false;
            if (changedLocal)
                await this.a.load();
        }
    }
    async conflictCount() { return (await this.a.kv.all('conflict')).length; }
    async checkVault(folder, remote) {
        const local = await this.a.vault.header();
        if (!local)
            throw new Error('گاوصندوق محلی وجود ندارد');
        const vf = remote.find((f) => f.name === VAULT_FILE);
        if (!vf) {
            await this.api.upload(folder, VAULT_FILE, enc.encode(JSON.stringify(local)), { k: 'vault' });
            return;
        }
        const r = JSON.parse(dec.decode(await this.api.download(vf.id)));
        if (r.salt !== local.salt)
            throw new VaultMismatch();
    }
    async pull(key, store, id, rf) {
        const bytes = await this.api.download(rf.id);
        if (store === 'blob') {
            const chunks = unpackChunks(bytes);
            const mem = String(rf.appProps.mem ?? '');
            await this.a.kv.put('blob', id, { id, memId: mem, rev: 1, size: 0, chunks });
        }
        else {
            const rec = JSON.parse(dec.decode(bytes));
            if (rec.id !== id)
                throw new Error('رکورد دریافتی با شناسه نمی‌خواند');
            const key2 = this.a.vault.key;
            if (!key2)
                throw new Error('برنامه قفل است');
            await decryptJson(key2, rec.env, `${store}:${id}`); // اعتبارسنجی؛ در صورت دست‌کاری/کلید نادرست خطا می‌دهد
            await this.a.putRawRecord(store, rec);
        }
        await this.a.kv.put('sync', key, { remoteId: rf.id, checksum: rf.checksum, rev: rf.appProps.rev ? Number(rf.appProps.rev) : 1 });
        await this.a.kv.del('queue', key);
    }
    /** دریافت یک پیوست خاص هنگام نیاز */
    async pullBlob(attId) {
        const folder = await this.api.ensureFolder(this.opts.folderName, this.opts.folderId);
        const rf = (await this.api.list(folder)).find((f) => f.appProps.k === itemKey('blob', attId) && f.name.endsWith('.sene'));
        if (!rf)
            throw new Error('پیوست در Drive پیدا نشد');
        await this.pull(itemKey('blob', attId), 'blob', attId, rf);
    }
    // ---------- تصمیم کاربر دربارهٔ تعارض ----------
    async conflicts() { return (await this.a.kv.all('conflict')).map(([, v]) => v); }
    async resolve(key, choice) {
        const c = await this.a.kv.get('conflict', key);
        if (!c)
            return;
        const [store, id] = [c.store, c.id];
        if (c.kind === 'both-changed' && c.remoteRec) {
            const local = await this.a.kv.get(store, id);
            if (choice === 'remote' || choice === 'both') {
                if (choice === 'both' && store === 'mem' && local) {
                    const lm = await decryptJson(this.a.vault.key, local.env, `mem:${id}`);
                    const copy = await this.a.createMemory({ text: lm.text, eventAt: new Date(lm.eventAt), mood: lm.mood, category: lm.category, tags: lm.tags, people: lm.people, events: lm.events, decisions: lm.decisions, goals: lm.goals, outcomes: lm.outcomes, source: 'conflict-copy' });
                    void copy;
                }
                await decryptJson(this.a.vault.key, c.remoteRec.env, `${store}:${id}`);
                await this.a.putRawRecord(store, c.remoteRec);
                await this.a.kv.put('sync', c.key, { remoteId: c.remoteFileId, checksum: c.remoteChecksum, rev: c.remoteRec.rev });
                await this.a.kv.del('queue', c.key);
            }
            else if (local) {
                // نسخهٔ محلی نگه داشته می‌شود و با rev بالاتر روی Drive می‌نشیند
                await this.a.kv.put(store, id, { ...local, rev: Math.max(local.rev, c.remoteRec.rev) + 1 });
                await this.a.kv.put('sync', c.key, { remoteId: c.remoteFileId, checksum: c.remoteChecksum, rev: c.remoteRec.rev });
                await this.a.enqueue(store, id, 'put');
            }
        }
        else if (c.kind === 'local-deleted') {
            if (choice === 'remote' || choice === 'both') {
                const bytes = await this.api.download(c.remoteFileId);
                const rec = JSON.parse(dec.decode(bytes));
                await decryptJson(this.a.vault.key, rec.env, `${store}:${id}`);
                await this.a.putRawRecord(store, rec);
                await this.a.kv.put('sync', c.key, { remoteId: c.remoteFileId, checksum: c.remoteChecksum, rev: rec.rev });
                await this.a.kv.del('queue', c.key);
                await this.a.kv.del('tomb', c.key);
            }
            else {
                // حذف محلی نهایی؛ در همگام‌سازی بعدی روی Drive اعمال می‌شود
                await this.a.kv.put('sync', c.key, { remoteId: c.remoteFileId, checksum: c.remoteChecksum, rev: 0 });
            }
        }
        else if (c.kind === 'remote-deleted') {
            if (choice === 'local') {
                // نگه‌داشتن نسخهٔ محلی: نشانهٔ حذف راه‌دور برداشته می‌شود و آیتم دوباره ارسال می‌شود
                const folder = await this.api.ensureFolder(this.opts.folderName, this.opts.folderId);
                const df = (await this.api.list(folder)).find((f) => f.appProps.k === c.key && f.name.endsWith('.del'));
                if (df)
                    await this.api.remove(df.id);
                await this.a.kv.del('sync', c.key);
                await this.a.enqueue(store, id, 'put');
            }
            else {
                await this.a.kv.del(store, id);
                await this.a.kv.del('sync', c.key);
                await this.a.kv.del('queue', c.key);
            }
        }
        await this.a.kv.del('conflict', key);
        await this.a.load();
    }
}
function splitKey(key) {
    const i = key.indexOf('.');
    return [key.slice(0, i), key.slice(i + 1)];
}
const newDeviceId = () => uid('d');
/** دستگاه تازه: سرفایل گاوصندوق را از Drive می‌گیرد تا با همان رمز بتوان آرشیو را باز کرد */
async function adoptRemoteVault(kv, api, folderName, folderId) {
    if (await kv.get('meta', 'vault'))
        throw new Error('روی این دستگاه از قبل گاوصندوق وجود دارد');
    const folder = await api.ensureFolder(folderName, folderId);
    const vf = (await api.list(folder)).find((f) => f.name === VAULT_FILE);
    if (!vf)
        throw new Error('در این پوشهٔ Drive آرشیوی پیدا نشد');
    const header = JSON.parse(dec.decode(await api.download(vf.id)));
    if (header.v !== 1 || !header.salt || !header.verifier)
        throw new Error('سرفایل آرشیو معتبر نیست');
    await kv.put('meta', 'vault', header);
    return folder;
}

return { VaultMismatch, SyncEngine, splitKey, newDeviceId, adoptRemoteVault };
})();
__M["core/reminders.js"] = (() => {
const SLOTS = [['morning', 'صبح', 'امروز صبح چه خبر بود؟ لحظه‌ای برای ثبت خاطره'], ['evening', 'عصر', 'عصر بخیر — اتفاقی ارزش ثبت‌شدن دارد؟'], ['night', 'شب', 'پایان روز؛ خاطره‌ها و حال‌وهوای امروز را ثبت کنید']];
function dueReminders(r, now, fired) {
    const day = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    const mins = now.getHours() * 60 + now.getMinutes();
    const out = [];
    for (const [slot, , text] of SLOTS) {
        const t = r[slot];
        if (!t || fired[slot] === day)
            continue;
        const [hh, mm] = t.split(':').map(Number);
        if (mins >= hh * 60 + mm)
            out.push({ slot, text });
    }
    return out;
}
function buildIcs(r, now = new Date()) {
    const pad = (n) => String(n).padStart(2, '0');
    const d = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
    const ev = [];
    for (const [slot, name, text] of SLOTS) {
        const t = r[slot];
        if (!t)
            continue;
        const [hh, mm] = t.split(':').map(Number);
        ev.push('BEGIN:VEVENT', `UID:sene-${slot}@sene.local`, `DTSTAMP:${d}T000000Z`, `DTSTART:${d}T${pad(hh)}${pad(mm)}00`, `DTEND:${d}T${pad(hh)}${pad(Math.min(59, mm + 10))}00`, 'RRULE:FREQ=DAILY', `SUMMARY:sene — یادآوری ${name}`, `DESCRIPTION:${text}`, 'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${text}`, 'TRIGGER:PT0M', 'END:VALARM', 'END:VEVENT');
    }
    if (!ev.length)
        throw new Error('هیچ یادآوری‌ای تنظیم نشده است');
    return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//sene//fa//', 'CALSCALE:GREGORIAN', ...ev, 'END:VCALENDAR'].join('\r\n');
}

return { SLOTS, dueReminders, buildIcs };
})();
__M["ui/dom.js"] = (() => {
// ابزارهای ساخت DOM (همه متن‌ها با textContent → بدون خطر تزریق HTML)
const { dateToJalali, faDigits, isValidJalali, jalaliMonthLength, jalaliToDate, JALALI_MONTHS, pad2 } = __M["util/jalali.js"];
function h(tag, props = null, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props ?? {})) {
        if (v === undefined || v === null || v === false)
            continue;
        if (k === 'class')
            el.className = v;
        else if (k === 'style' && typeof v === 'object')
            Object.assign(el.style, v);
        else if (k.startsWith('on') && typeof v === 'function')
            el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected')
            el[k] = v;
        else
            el.setAttribute(k, v === true ? '' : String(v));
    }
    const add = (c) => {
        if (Array.isArray(c))
            c.forEach(add);
        else if (c === null || c === undefined || c === false)
            return;
        else
            el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    };
    kids.forEach(add);
    return el;
}
const clear = (el) => { while (el.firstChild)
    el.removeChild(el.firstChild); };
function toast(msg, kind = 'ok', ms = 3500) {
    let box = document.getElementById('toasts');
    if (!box) {
        box = h('div', { id: 'toasts', role: 'status', 'aria-live': 'polite' });
        document.body.append(box);
    }
    const t = h('div', { class: `toast ${kind}` }, msg);
    box.append(t);
    setTimeout(() => t.remove(), ms);
}
function openSheet(title, body, onClose) {
    const prev = document.activeElement;
    const back = h('div', { class: 'backdrop' });
    const box = h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, h('div', { class: 'sheet-head' }, h('h2', null, title), h('button', { class: 'icon-btn', 'aria-label': 'بستن', onclick: () => close() }, '✕')), body);
    back.append(box);
    const close = () => { back.remove(); document.removeEventListener('keydown', esc); prev?.focus?.(); onClose?.(); };
    const esc = (e) => { if (e.key === 'Escape')
        close(); };
    back.addEventListener('click', (e) => { if (e.target === back)
        close(); });
    document.addEventListener('keydown', esc);
    document.body.append(back);
    box.querySelector('input,textarea,select,button.primary')?.focus();
    return { close, el: box };
}
function confirmBox(message, o = {}) {
    return new Promise((res) => {
        let done = false;
        const fin = (v) => { if (!done) {
            done = true;
            res(v);
            s.close();
        } };
        const body = h('div', { class: 'stack' }, h('p', null, message), o.detail && h('p', { class: 'muted' }, o.detail), h('div', { class: 'row end' }, h('button', { class: 'btn', onclick: () => fin(false) }, 'انصراف'), h('button', { class: `btn ${o.danger ? 'danger' : 'primary'}`, onclick: () => fin(true) }, o.confirmText ?? 'تأیید')));
        const s = openSheet('تأیید', body, () => { if (!done) {
            done = true;
            res(false);
        } });
    });
}
function promptBox(label, o = {}) {
    return new Promise((res) => {
        let done = false;
        const input = h('input', { type: o.password ? 'password' : 'text', value: o.value ?? '', autocomplete: o.password ? 'current-password' : 'off', 'aria-label': label });
        const fin = (v) => { if (!done) {
            done = true;
            res(v);
            s.close();
        } };
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter')
            fin(input.value); });
        const body = h('div', { class: 'stack' }, h('label', null, label, input), o.hint && h('p', { class: 'muted' }, o.hint), h('div', { class: 'row end' }, h('button', { class: 'btn', onclick: () => fin(null) }, 'انصراف'), h('button', { class: 'btn primary', onclick: () => fin(input.value) }, o.confirmText ?? 'تأیید')));
        const s = openSheet(label, body, () => { if (!done) {
            done = true;
            res(null);
        } });
    });
}
/** انتخاب تاریخ شمسی (سه لیست) + ساعت با ثانیه؛ به‌خاطر پایداری در مرورگرهای گوشی از input[type=date] استفاده نمی‌شود */
function dateField(o = {}) {
    const now = new Date();
    const base = o.value === undefined ? now : o.value;
    const cj = dateToJalali(now);
    const j = base ? dateToJalali(base) : null;
    const yearSel = h('select', { 'aria-label': 'سال' });
    const monSel = h('select', { 'aria-label': 'ماه' });
    const daySel = h('select', { 'aria-label': 'روز' });
    const empty = () => h('option', { value: '' }, '—');
    if (o.optional) {
        yearSel.append(empty());
        monSel.append(empty());
        daySel.append(empty());
    }
    for (let y = cj.y + 1; y >= 1300; y -= 1)
        yearSel.append(h('option', { value: y }, faDigits(y)));
    JALALI_MONTHS.forEach((m, i) => monSel.append(h('option', { value: i + 1 }, m)));
    const fillDays = () => {
        const y = +yearSel.value || cj.y;
        const m = +monSel.value || 1;
        const cur = daySel.value;
        clear(daySel);
        if (o.optional)
            daySel.append(empty());
        for (let d = 1; d <= jalaliMonthLength(y, m); d += 1)
            daySel.append(h('option', { value: d }, faDigits(d)));
        if (cur && +cur <= jalaliMonthLength(y, m))
            daySel.value = cur;
    };
    yearSel.value = j ? String(j.y) : '';
    monSel.value = j ? String(j.m) : '';
    fillDays();
    daySel.value = j ? String(j.d) : '';
    yearSel.addEventListener('change', fillDays);
    monSel.addEventListener('change', fillDays);
    const time = h('input', { type: 'time', step: '1', 'aria-label': 'ساعت', value: base ? `${pad2(base.getHours())}:${pad2(base.getMinutes())}:${pad2(base.getSeconds())}` : '00:00:00' });
    const el = h('div', { class: 'datefield' }, o.label && h('span', { class: 'lbl' }, o.label), h('div', { class: 'row wrap' }, daySel, monSel, yearSel, o.time ? time : null));
    return {
        el,
        get() {
            if (!yearSel.value || !monSel.value || !daySel.value)
                return null;
            const [hh, mm, ss] = (time.value || '00:00:00').split(':').map((x) => +x);
            if (!isValidJalali(+yearSel.value, +monSel.value, +daySel.value))
                return null;
            return jalaliToDate(+yearSel.value, +monSel.value, +daySel.value, hh || 0, mm || 0, ss || 0);
        },
    };
}
const fmtBytes = (n) => (n < 1024 ? `${faDigits(n)} بایت` : n < 1048576 ? `${faDigits((n / 1024).toFixed(1))} کیلوبایت` : n < 1073741824 ? `${faDigits((n / 1048576).toFixed(1))} مگابایت` : `${faDigits((n / 1073741824).toFixed(2))} گیگابایت`);
function download(blob, name) {
    const a = h('a', { href: URL.createObjectURL(blob), download: name });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
}
if (typeof Element !== 'undefined') {
    const nativeAppend = Element.prototype.append;
    Element.prototype.append = function (...nodes) {
        nativeAppend.apply(this, nodes.flat(Infinity).filter((x) => x !== null && x !== undefined && x !== false));
    };
}

return { h, clear, toast, openSheet, confirmBox, promptBox, dateField, fmtBytes, download };
})();
__M["platform.js"] = (() => {
// لایهٔ پلتفرم: همهٔ دسترسی‌ها به قابلیت‌های دستگاه از این‌جا می‌گذرد تا در تبدیل به اپ اندروید (Capacitor)
// فقط همین فایل با افزونه‌های Capacitor جایگزین شود و بقیهٔ برنامه تغییر نکند.
const { download } = __M["ui/dom.js"];
const platform = {
    isNative: false,
    saveFile(blob, name) { download(blob, name); }, // Capacitor: Filesystem + Share
    async requestPersistentStorage() { return (await navigator.storage?.persist?.()) ?? false; },
    async notificationPermission() { return 'Notification' in window ? Notification.permission : 'unsupported'; },
    async requestNotifications() { return 'Notification' in window ? Notification.requestPermission() : 'unsupported'; },
    async notify(title, body) {
        if (!('Notification' in window) || Notification.permission !== 'granted')
            return false;
        try {
            const reg = await navigator.serviceWorker?.getRegistration();
            if (reg)
                await reg.showNotification(title, { body, icon: 'icon-192.png', dir: 'rtl', lang: 'fa' });
            else
                new Notification(title, { body });
            return true;
        }
        catch {
            return false;
        }
    },
    online() { return navigator.onLine; },
};

return { platform };
})();
__M["core/backup.js"] = (() => {
// پشتیبان‌گیری رمزگذاری‌شده، اعتبارسنجی و بازیابی
const { itemKey } = __M["core/archive.js"];
const { decryptBytes, decryptJson, deriveKey, encryptBytes, encryptJson, packChunks, unpackChunks } = __M["core/crypto.js"];
const { b64, sha256Hex, unb64 } = __M["util/id.js"];
const enc = new TextEncoder();
/** پشتیبان کامل: همهٔ داده‌ها همان‌طور که روی دستگاه رمزگذاری شده‌اند؛ هیچ کلید یا رمزی داخل فایل نیست */
async function createBackup(a) {
    const vault = await a.vault.header();
    if (!vault)
        throw new Error('گاوصندوق وجود ندارد');
    const mem = await a.kv.all('mem');
    const ent = await a.kv.all('ent');
    const blob = await a.kv.all('blob');
    const header = { format: 'sene-backup', version: 1, createdAt: new Date().toISOString(), vault, counts: { mem: mem.length, ent: ent.length, blob: blob.length } };
    const lines = [JSON.stringify(header)];
    for (const [, rec] of mem)
        lines.push(JSON.stringify({ t: 'mem', rec }));
    for (const [, rec] of ent)
        lines.push(JSON.stringify({ t: 'ent', rec }));
    for (const [id, b] of blob)
        lines.push(JSON.stringify({ t: 'blob', id, memId: b.memId, data: b64(packChunks(b.chunks)) }));
    const hashes = [];
    for (const l of lines)
        hashes.push(await sha256Hex(enc.encode(l)));
    lines.push(JSON.stringify({ t: 'end', lines: lines.length, digest: await sha256Hex(enc.encode(hashes.join(''))) }));
    return new Blob(lines.map((l) => l + '\n'), { type: 'application/octet-stream' });
}
async function* readLines(stream) {
    const reader = stream.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
        const { done, value } = await reader.read();
        if (value)
            buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
            const l = buf.slice(0, i);
            buf = buf.slice(i + 1);
            if (l)
                yield l;
        }
        if (done) {
            if (buf.trim())
                yield buf;
            return;
        }
    }
}
/** اعتبارسنجی ساختار و جمع‌کنترلی پیش از هر بازیابی؛ در صورت دادن رمز، رمزگشایی نمونه‌ای هم انجام می‌شود */
async function verifyBackup(blob, password) {
    const problems = [];
    const counts = { mem: 0, ent: 0, blob: 0 };
    let header;
    const hashes = [];
    let end;
    let n = 0;
    try {
        for await (const line of readLines(blob.stream())) {
            let o;
            try {
                o = JSON.parse(line);
            }
            catch {
                problems.push(`خط ${n + 1}: ساختار JSON خراب است`);
                break;
            }
            if (n === 0) {
                if (o.format !== 'sene-backup' || o.version !== 1) {
                    problems.push('این فایل پشتیبان sene (نسخهٔ ۱) نیست');
                    break;
                }
                header = o;
            }
            else if (o.t === 'end')
                end = o;
            else if (o.t === 'mem' || o.t === 'ent' || o.t === 'blob')
                counts[o.t] += 1;
            if (o.t !== 'end')
                hashes.push(await sha256Hex(enc.encode(line)));
            n += 1;
        }
    }
    catch {
        problems.push('خواندن فایل ممکن نشد');
    }
    if (header) {
        if (!end)
            problems.push('فایل ناقص است (پایان‌نامه وجود ندارد)');
        else if (end.digest !== await sha256Hex(enc.encode(hashes.join(''))))
            problems.push('جمع‌کنترلی نمی‌خواند: فایل تغییر کرده یا خراب است');
        if (header.counts.mem !== counts.mem || header.counts.ent !== counts.ent || header.counts.blob !== counts.blob)
            problems.push('تعداد اقلام با سرفایل نمی‌خواند');
        if (password !== undefined) {
            try {
                await decryptJson(await deriveKey(password, header.vault), header.vault.verifier, 'vault');
            }
            catch {
                problems.push('رمز پشتیبان نادرست است');
            }
        }
    }
    return { ok: problems.length === 0 && !!header, header, problems, counts };
}
/** بازیابی ادغامی و ایمن: چیزی حذف نمی‌شود؛ موارد حذف‌شدهٔ محلی برنمی‌گردند؛ نسخهٔ محلی جدیدتر حفظ می‌شود */
async function restoreBackup(a, blob, password) {
    const v = await verifyBackup(blob, password);
    if (!v.ok || !v.header)
        throw new Error(v.problems.join('؛ ') || 'پشتیبان معتبر نیست');
    const bk = await deriveKey(password, v.header.vault);
    const local = await a.vault.header();
    const same = !!local && local.salt === v.header.vault.salt;
    const myKey = a.vault.key;
    const res = { added: 0, updated: 0, skippedExisting: 0, skippedDeleted: 0, blobs: 0 };
    const tombs = new Set((await a.tombstones()).map((t) => t.key));
    const skipBlobs = new Set();
    let first = true;
    for await (const line of readLines(blob.stream())) {
        if (first) {
            first = false;
            continue;
        }
        const o = JSON.parse(line);
        if (o.t === 'mem' || o.t === 'ent') {
            const rec = o.rec;
            const store = o.t;
            const key = itemKey(store, rec.id);
            if (tombs.has(key)) {
                res.skippedDeleted += 1;
                continue;
            }
            const cur = await a.kv.get(store, rec.id);
            if (cur && cur.rev >= rec.rev) {
                res.skippedExisting += 1;
                continue;
            }
            let out = rec;
            if (!same) {
                const val = await decryptJson(bk, rec.env, `${store}:${rec.id}`);
                out = { ...rec, env: await encryptJson(myKey, val, `${store}:${rec.id}`) };
            }
            else
                await decryptJson(bk, rec.env, `${store}:${rec.id}`);
            await a.putRawRecord(store, out);
            await a.enqueue(store, rec.id, 'put');
            if (cur)
                res.updated += 1;
            else
                res.added += 1;
        }
        else if (o.t === 'blob') {
            if (tombs.has(itemKey('blob', o.id)) || skipBlobs.has(o.id))
                continue;
            if (await a.kv.get('blob', o.id))
                continue;
            let chunks = unpackChunks(unb64(o.data));
            if (!same) {
                const bytes = await decryptBytes(bk, chunks, `blob:${o.id}`);
                chunks = await encryptBytes(myKey, bytes, `blob:${o.id}`);
            }
            await a.kv.put('blob', o.id, { id: o.id, memId: o.memId, rev: 1, size: 0, chunks });
            await a.enqueue('blob', o.id, 'put');
            res.blobs += 1;
        }
    }
    await a.load();
    return res;
}

return { createBackup, verifyBackup, restoreBackup };
})();
__M["ui/views/lock.js"] = (() => {
const { clear, h, promptBox, toast } = __M["ui/dom.js"];
const { LockedOut, MIN_PASSWORD, WrongPassword, passwordStrengthError } = __M["core/vault.js"];
const { restoreBackup, verifyBackup } = __M["core/backup.js"];
const { adoptRemoteVault } = __M["sync/engine.js"];
const { GoogleDriveApi } = __M["sync/drive.js"];
const { faDigits } = __M["util/jalali.js"];
function lockScreen(ctx, onUnlocked) {
    const wrap = h('div', { class: 'lock' });
    const draw = async () => {
        clear(wrap);
        const exists = await ctx.vault.exists();
        wrap.append(h('img', { src: 'icon-192.png', alt: '', class: 'logo', width: '96', height: '96' }), h('h1', null, 'sene'), h('p', { class: 'muted' }, 'آرشیو خصوصی زندگی'));
        exists ? unlockForm() : setupForm();
    };
    const err = h('p', { class: 'error', role: 'alert' });
    function unlockForm() {
        const pw = h('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'رمز ورود', placeholder: 'رمز ورود' });
        const btn = h('button', { class: 'btn primary wide', type: 'button' }, 'ورود');
        const go = async () => {
            err.textContent = '';
            btn.setAttribute('disabled', '');
            try {
                await ctx.vault.unlock(pw.value);
                pw.value = '';
                onUnlocked();
            }
            catch (e) {
                if (e instanceof LockedOut)
                    err.textContent = `به‌دلیل چند ورود اشتباه، ${faDigits(Math.ceil((e.until - Date.now()) / 1000))} ثانیه صبر کنید.`;
                else if (e instanceof WrongPassword)
                    err.textContent = 'رمز نادرست است.';
                else
                    err.textContent = `خطا: ${e.message}`;
                btn.removeAttribute('disabled');
                pw.select();
            }
        };
        btn.addEventListener('click', go);
        pw.addEventListener('keydown', (e) => { if (e.key === 'Enter')
            void go(); });
        wrap.append(h('div', { class: 'stack' }, pw, btn, err, h('p', { class: 'muted small' }, 'اثر انگشت در نسخهٔ وب پشتیبانی نمی‌شود؛ قفل با رمز اصلی انجام می‌شود.')));
        pw.focus();
    }
    function setupForm() {
        const p1 = h('input', { type: 'password', autocomplete: 'new-password', 'aria-label': 'رمز جدید', placeholder: `رمز (دست‌کم ${faDigits(MIN_PASSWORD)} نویسه)` });
        const p2 = h('input', { type: 'password', autocomplete: 'new-password', 'aria-label': 'تکرار رمز', placeholder: 'تکرار رمز' });
        const ack = h('input', { type: 'checkbox', id: 'ack' });
        const btn = h('button', { class: 'btn primary wide', type: 'button' }, 'ساخت آرشیو');
        btn.addEventListener('click', async () => {
            err.textContent = '';
            const pe = passwordStrengthError(p1.value);
            if (pe) {
                err.textContent = pe;
                return;
            }
            if (p1.value !== p2.value) {
                err.textContent = 'تکرار رمز یکسان نیست.';
                return;
            }
            if (!ack.checked) {
                err.textContent = 'لطفاً هشدار فقدان رمز را تأیید کنید.';
                return;
            }
            btn.setAttribute('disabled', '');
            try {
                await ctx.vault.create(p1.value);
                onUnlocked();
            }
            catch (e) {
                err.textContent = e.message;
                btn.removeAttribute('disabled');
            }
        });
        const restoreBtn = h('button', { class: 'btn', type: 'button', onclick: restoreFlow }, 'بازیابی از فایل پشتیبان');
        const driveBtn = h('button', { class: 'btn', type: 'button', onclick: driveFlow }, 'اتصال به آرشیو موجود در Google Drive');
        wrap.append(h('div', { class: 'stack' }, h('p', null, 'برای شروع یک رمز اصلی بسازید. تمام خاطره‌ها و فایل‌ها با همین رمز روی گوشی رمزگذاری می‌شوند.'), p1, p2, h('label', { class: 'check', for: 'ack' }, ack, h('span', null, 'می‌دانم که رمز در هیچ‌جا ذخیره نمی‌شود و در صورت فراموشی، بازیابی اطلاعات ممکن نیست.')), btn, err, h('hr'), restoreBtn, driveBtn));
    }
    async function restoreFlow() {
        const inp = h('input', { type: 'file', accept: '.sene-backup,.json,application/octet-stream' });
        inp.addEventListener('change', async () => {
            const f = inp.files?.[0];
            if (!f)
                return;
            const v = await verifyBackup(f);
            if (!v.ok) {
                toast(`فایل معتبر نیست: ${v.problems.join('؛ ')}`, 'err', 7000);
                return;
            }
            const backupPw = await promptBox('رمز اصلیِ آن پشتیبان', { password: true });
            if (backupPw === null)
                return;
            const np = await promptBox('رمز اصلی جدید برای این دستگاه (می‌تواند همان رمز قبلی باشد)', { password: true });
            if (!np)
                return;
            const pe = passwordStrengthError(np);
            if (pe) {
                toast(pe, 'err');
                return;
            }
            try {
                const kv = ctx.kv;
                void kv;
                await ctx.vault.create(np);
                const r = await restoreBackup(ctx.archive, f, backupPw);
                toast(`بازیابی شد: ${faDigits(r.added)} خاطره، ${faDigits(r.blobs)} پیوست`, 'ok', 6000);
                onUnlocked();
            }
            catch (e) {
                toast(`بازیابی ناموفق: ${e.message}`, 'err', 7000);
            }
        });
        inp.click();
    }
    async function driveFlow() {
        const cid = await promptBox('شناسهٔ OAuth (Client ID) مربوط به گوگل', { hint: 'راه‌اندازی در README توضیح داده شده است. این شناسه محرمانه نیست.', value: ctx.settings.driveClientId });
        if (!cid)
            return;
        try {
            await ctx.setSettings({ driveClientId: cid.trim(), online: { ...ctx.settings.online, drive: true } });
            await ctx.auth.getToken(true);
            const api = new GoogleDriveApi(() => ctx.auth.getToken(false));
            const folder = await adoptRemoteVault(ctx.kv, api, ctx.settings.driveFolderName || 'sene', ctx.settings.driveFolderId || undefined);
            await ctx.setSettings({ driveFolderId: folder });
            toast('آرشیو پیدا شد. همان رمز اصلی قبلی را وارد کنید.', 'ok', 6000);
            void draw();
        }
        catch (e) {
            toast(e.message, 'err', 7000);
        }
    }
    void draw();
    return wrap;
}

return { lockScreen };
})();
__M["core/search.js"] = (() => {
const { normalize, tokenize } = __M["util/text.js"];
const FIELDS = [
    { name: 'text', label: 'متن', get: (m) => m.text, w: 1 },
    { name: 'tags', label: 'برچسب', get: (m) => m.tags.join(' '), w: 2 },
    { name: 'people', label: 'اشخاص', get: (m) => m.people.join(' '), w: 2 },
    { name: 'events', label: 'رویداد', get: (m) => m.events.join(' '), w: 2 },
    { name: 'category', label: 'دسته', get: (m) => m.category, w: 1.5 },
    { name: 'decisions', label: 'تصمیم', get: (m) => m.decisions, w: 1.2 },
    { name: 'goals', label: 'هدف', get: (m) => m.goals, w: 1.2 },
    { name: 'outcomes', label: 'نتیجه', get: (m) => m.outcomes, w: 1.2 },
    { name: 'attachments', label: 'پیوست', get: (m) => m.attachments.map((a) => `${a.name} ${a.extractedText ?? ''}`).join(' '), w: 1 },
];
function applyFilters(all, f) {
    return all.filter((m) => {
        if (f.category && m.category !== f.category)
            return false;
        if (f.tag && !m.tags.includes(f.tag))
            return false;
        if (f.person && !m.people.includes(f.person))
            return false;
        if (f.event && !m.events.includes(f.event))
            return false;
        const d = new Date(f.by === 'created' ? m.createdAt : m.eventAt);
        if (f.from && d < f.from)
            return false;
        if (f.to && d > f.to)
            return false;
        if (f.moodMin !== undefined && (!m.mood || m.mood.score < f.moodMin))
            return false;
        if (f.moodMax !== undefined && (!m.mood || m.mood.score > f.moodMax))
            return false;
        if (f.hasAttachment && m.attachments.length === 0)
            return false;
        if (f.attachmentKind && !m.attachments.some((a) => a.kind === f.attachmentKind))
            return false;
        return true;
    });
}
function search(all, query, f = {}) {
    const pool = applyFilters(all, f);
    const qt = tokenize(query);
    if (qt.length === 0)
        return pool.map((m) => ({ memory: m, score: 0, why: ['مطابق فیلترها'] })).sort((a, b) => b.memory.eventAt.localeCompare(a.memory.eventAt));
    // IDF
    const docs = pool.map((m) => FIELDS.map((fl) => tokenize(fl.get(m))));
    const df = new Map();
    docs.forEach((fs) => new Set(fs.flat()).forEach((t) => df.set(t, (df.get(t) ?? 0) + 1)));
    const N = Math.max(1, pool.length);
    const hits = [];
    pool.forEach((m, i) => {
        let score = 0;
        const why = [];
        for (const q of qt) {
            let best = 0;
            let bestField = '';
            let bestTok = '';
            docs[i].forEach((toks, fi) => {
                const tf = new Map();
                toks.forEach((t) => tf.set(t, (tf.get(t) ?? 0) + 1));
                for (const [t, c] of tf) {
                    const exact = t === q;
                    const prefix = !exact && q.length >= 2 && (t.startsWith(q) || (q.length >= 3 && q.startsWith(t) && t.length >= 3));
                    if (!exact && !prefix)
                        continue;
                    const idf = Math.log(1 + N / (df.get(t) ?? 1));
                    const s = (exact ? 1 : 0.6) * idf * FIELDS[fi].w * (1 + Math.log(c));
                    if (s > best) {
                        best = s;
                        bestField = FIELDS[fi].label;
                        bestTok = t;
                    }
                }
            });
            if (best > 0) {
                score += best;
                why.push(`«${bestTok}» در ${bestField}`);
            }
        }
        // عبارت کامل در متن، امتیاز بیشتر
        if (qt.length > 1 && normalize(m.text).includes(normalize(query))) {
            score += 2;
            why.push('عبارت کامل در متن');
        }
        if (score > 0)
            hits.push({ memory: m, score, why });
    });
    return hits.sort((a, b) => b.score - a.score || b.memory.eventAt.localeCompare(a.memory.eventAt));
}
/** قطعه‌ای از متن اطراف اولین تطابق */
function snippet(text, query, len = 90) {
    const toks = tokenize(query);
    const nt = text;
    let idx = -1;
    for (const t of toks) {
        const i = normalize(nt).indexOf(t);
        if (i >= 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0)
        return nt.slice(0, len) + (nt.length > len ? '…' : '');
    const start = Math.max(0, idx - 25);
    return (start > 0 ? '…' : '') + nt.slice(start, start + len) + (start + len < nt.length ? '…' : '');
}

return { applyFilters, search, snippet };
})();
__M["core/analysis.js"] = (() => {
// تحلیل‌های محلی و مبتنی بر قاعده — بدون هیچ سرویس خارجی.
// هر خروجی «برداشت» است نه واقعیت؛ همراه با شواهد (شناسه، تاریخ، گزیده) برگردانده می‌شود.
const { MOODS } = __M["core/types.js"];
const { normalize, tokenize } = __M["util/text.js"];
const { dateToJalali, faDigits, formatJalali, JALALI_MONTHS, WEEKDAYS, weekdayIndex } = __M["util/jalali.js"];
const evidenceOf = (m) => ({ id: m.id, date: m.eventAt, snippet: m.text.slice(0, 80) });
const avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
// ---------- پیشنهادها (نیازمند تأیید کاربر) ----------
const CATEGORY_WORDS = {
    'امور مالی': ['پول', 'حقوق', 'قیمت', 'خرید', 'قسط', 'وام', 'بانک', 'هزینه', 'درآمد', 'بدهی', 'پس‌انداز', 'اجاره'],
    'سلامت و عادت‌ها': ['دکتر', 'ورزش', 'خواب', 'دارو', 'سرماخوردگی', 'رژیم', 'پیاده‌روی', 'درد', 'بیمارستان', 'سلامت', 'دویدن'],
    'روابط': ['دوست', 'مادر', 'پدر', 'برادر', 'خواهر', 'همسر', 'خانواده', 'رفیق', 'دعوا', 'قرار', 'مهمانی'],
    'اهداف': ['هدف', 'برنامه', 'می‌خواهم', 'قصد', 'آرزو', 'تصمیم دارم', 'باید یاد بگیرم'],
    'رؤیاها': ['خواب دیدم', 'خوابم', 'کابوس', 'در خواب'],
    'رسانه‌ها': ['فیلم', 'کتاب', 'سریال', 'آهنگ', 'موسیقی', 'پادکست', 'بازی'],
    'تصمیم‌ها و پیامدها': ['تصمیم گرفتم', 'انتخاب کردم', 'نتیجه', 'پیامد', 'پشیمان'],
    'احساسات': ['احساس', 'ناراحت', 'خوشحال', 'نگران', 'استرس', 'عصبانی', 'دلتنگ', 'ترسیده'],
    'افکار': ['فکر', 'ایده', 'به نظرم', 'اندیشیدم', 'فکر می‌کنم'],
};
function suggestCategory(text) {
    const n = normalize(text);
    let best = null;
    for (const [cat, words] of Object.entries(CATEGORY_WORDS)) {
        const hit = words.filter((w) => n.includes(normalize(w)));
        if (hit.length && (!best || hit.length > best.because.length))
            best = { category: cat, because: hit };
    }
    return best;
}
function suggestTags(text, existing, max = 5) {
    const n = normalize(text);
    const fromExisting = existing.filter((t) => n.includes(normalize(t)));
    const freq = new Map();
    tokenize(text).filter((t) => t.length >= 4).forEach((t) => freq.set(t, (freq.get(t) ?? 0) + 1));
    const extra = [...freq.entries()].filter(([, c]) => c >= 2).sort((a, b) => b[1] - a[1]).map(([t]) => t);
    return [...new Set([...fromExisting, ...extra])].slice(0, max);
}
const POS = ['خوشحال', 'عالی', 'لذت', 'شاد', 'آرام', 'موفق', 'قشنگ', 'عاشق', 'مهربان'];
const NEG = ['ناراحت', 'غمگین', 'استرس', 'نگران', 'عصبانی', 'خسته', 'تنها', 'ترس', 'شکست', 'گریه'];
function suggestMood(text) {
    const n = normalize(text);
    const p = POS.filter((w) => n.includes(normalize(w)));
    const g = NEG.filter((w) => n.includes(normalize(w)));
    if (!p.length && !g.length)
        return null;
    const d = p.length - g.length;
    return { score: (d >= 2 ? 5 : d === 1 ? 4 : d === 0 ? 3 : d === -1 ? 2 : 1), because: [...p, ...g] };
}
// ---------- ارتباط‌ها ----------
function vec(m) {
    const v = new Map();
    tokenize([m.text, m.decisions, m.goals, m.outcomes, m.tags.join(' '), m.events.join(' ')].join(' ')).forEach((t) => v.set(t, (v.get(t) ?? 0) + 1));
    return v;
}
function related(target, all, max = 5) {
    const tv = vec(target);
    const df = new Map();
    const vecs = all.map((m) => { const v = vec(m); v.forEach((_, t) => df.set(t, (df.get(t) ?? 0) + 1)); return v; });
    const N = all.length || 1;
    const w = (t, c) => c * Math.log(1 + N / (df.get(t) ?? 1));
    const norm = (v) => Math.sqrt([...v].reduce((a, [t, c]) => a + w(t, c) ** 2, 0)) || 1;
    const tn = norm(tv);
    const out = [];
    all.forEach((m, i) => {
        if (m.id === target.id)
            return;
        let dot = 0;
        const shared = [];
        tv.forEach((c, t) => { const o = vecs[i].get(t); if (o) {
            dot += w(t, c) * w(t, o);
            shared.push(t);
        } });
        const sp = m.people.filter((p) => target.people.includes(p));
        const st = m.tags.filter((t) => target.tags.includes(t));
        const score = dot / (tn * norm(vecs[i])) + sp.length * 0.2 + st.length * 0.15 + (target.links.includes(m.id) || m.links.includes(target.id) ? 1 : 0);
        if (score > 0.12)
            out.push({ memory: m, score, why: [...sp.map((p) => `شخص مشترک: ${p}`), ...st.map((t) => `برچسب مشترک: ${t}`), ...(shared.length ? [`واژه‌های مشترک: ${shared.slice(0, 4).join('، ')}`] : [])] });
    });
    return out.sort((a, b) => b.score - a.score).slice(0, max);
}
function onThisDay(all, today = new Date()) {
    const j = dateToJalali(today);
    return all.filter((m) => { const d = new Date(m.eventAt); const jd = dateToJalali(d); return jd.m === j.m && jd.d === j.d && jd.y !== j.y; })
        .sort((a, b) => b.eventAt.localeCompare(a.eventAt));
}
// ---------- آمار ----------
function countBy(items, key) {
    const c = new Map();
    items.forEach((i) => { const k = key(i); (Array.isArray(k) ? k : [k]).forEach((x) => c.set(x, (c.get(x) ?? 0) + 1)); });
    return [...c.entries()].sort((a, b) => b[1] - a[1]);
}
function monthKey(d) { const j = dateToJalali(d); return `${j.y}/${String(j.m).padStart(2, '0')}`; }
function periodStats(all, from, to) {
    const ms = all.filter((m) => { const d = new Date(m.eventAt); return d >= from && d <= to; });
    const moods = ms.filter((m) => m.mood).map((m) => m.mood.score);
    return {
        count: ms.length, avgMood: moods.length ? avg(moods) : null, moodCount: moods.length,
        categories: countBy(ms, (m) => m.category), tags: countBy(ms, (m) => m.tags).slice(0, 8), people: countBy(ms, (m) => m.people).slice(0, 8),
        decisions: ms.filter((m) => m.decisions).length, withOutcome: ms.filter((m) => m.decisions && m.outcomes).length, memories: ms,
    };
}
function moodSeries(all) {
    return all.filter((m) => m.mood).map((m) => ({ t: new Date(m.eventAt).getTime(), v: m.mood.score, id: m.id })).sort((a, b) => a.t - b.t);
}
function generateInsights(all) {
    const out = [];
    const add = (kind, signature, text, ev) => out.push({ kind, signature, text, evidence: ev.slice(0, 5).map(evidenceOf), source: 'rule-based' });
    // الگوی روز هفته برای حال‌وهوا
    const byDay = new Map();
    all.filter((m) => m.mood).forEach((m) => { const k = weekdayIndex(new Date(m.eventAt)); byDay.set(k, [...(byDay.get(k) ?? []), m]); });
    const days = [...byDay.entries()].filter(([, v]) => v.length >= 3).map(([k, v]) => ({ k, v, a: avg(v.map((m) => m.mood.score)) }));
    if (days.length >= 3) {
        const lo = days.reduce((a, b) => (b.a < a.a ? b : a));
        const hi = days.reduce((a, b) => (b.a > a.a ? b : a));
        if (hi.a - lo.a >= 1) {
            add('pattern', `weekday:${lo.k}:${hi.k}`, `در خاطره‌های ثبت‌شده، میانگین حال‌وهوای «${WEEKDAYS[lo.k]}» (${faDigits(lo.a.toFixed(1))}) پایین‌تر از «${WEEKDAYS[hi.k]}» (${faDigits(hi.a.toFixed(1))}) بوده است. این فقط یک هم‌زمانی آماری در داده‌های ثبت‌شده است، نه توضیح علّی.`, lo.v);
        }
    }
    // تغییر حال‌وهوا بین دو دورهٔ ۳۰ روزه
    const now = Date.now();
    const D = 30 * 86400000;
    const rec = all.filter((m) => m.mood && now - new Date(m.eventAt).getTime() <= D);
    const prev = all.filter((m) => m.mood && now - new Date(m.eventAt).getTime() > D && now - new Date(m.eventAt).getTime() <= 2 * D);
    if (rec.length >= 5 && prev.length >= 5) {
        const d = avg(rec.map((m) => m.mood.score)) - avg(prev.map((m) => m.mood.score));
        if (Math.abs(d) >= 0.7)
            add('change', `moodshift:${d > 0 ? 'up' : 'down'}:${Math.floor(now / (7 * 86400000))}`, `میانگین حال‌وهوای ثبت‌شده در ۳۰ روز اخیر نسبت به ۳۰ روز قبل از آن ${d > 0 ? 'بالاتر' : 'پایین‌تر'} است (اختلاف ${faDigits(Math.abs(d).toFixed(1))}).`, rec);
    }
    // اشخاص و برچسب‌های پرتکرار
    for (const [p, c] of countBy(all, (m) => m.people).filter(([, c]) => c >= 5).slice(0, 3)) {
        add('pattern', `person:${p}:${c >= 10 ? 10 : 5}`, `نام «${p}» در ${faDigits(c)} خاطره آمده است.`, all.filter((m) => m.people.includes(p)));
    }
    // واژه‌های تکرارشونده در ماه‌های مختلف
    const monthsByWord = new Map();
    all.forEach((m) => tokenize(m.text).filter((t) => t.length >= 4).forEach((t) => { const s = monthsByWord.get(t) ?? new Set(); s.add(monthKey(new Date(m.eventAt))); monthsByWord.set(t, s); }));
    for (const [w, s] of [...monthsByWord].filter(([, s]) => s.size >= 4).sort((a, b) => b[1].size - a[1].size).slice(0, 2)) {
        add('pattern', `word:${w}:${s.size >= 8 ? 8 : 4}`, `واژهٔ «${w}» در خاطره‌های ${faDigits(s.size)} ماه مختلف تکرار شده است.`, all.filter((m) => normalize(m.text).includes(w)));
    }
    // تصمیم بدون نتیجهٔ ثبت‌شده (قدیمی‌تر از ۹۰ روز)
    const open = all.filter((m) => m.decisions && !m.outcomes && now - new Date(m.eventAt).getTime() > 90 * 86400000);
    if (open.length >= 1)
        add('suggestion', `openDecisions:${open.length}`, `${faDigits(open.length)} تصمیم ثبت‌شده بیش از ۹۰ روز است که نتیجه‌ای برایشان ثبت نشده است.`, open);
    return out;
}
/** تناقض‌های احتمالی: «دوست دارم X» در برابر «دوست ندارم X» برای یک X یکسان */
const POL = [[/نمی‌?\s?خواهم\s+(.{3,40})/, -1], [/می‌?\s?خواهم\s+(.{3,40})/, 1], [/دوست\s?ندارم\s+(.{3,40})/, -1], [/دوست\s?دارم\s+(.{3,40})/, 1]];
function findContradictions(all) {
    const stmts = [];
    for (const m of all) {
        const n = normalize(m.text).replace(/\s?می\s/g, 'می‌ ');
        const t = m.text.replace(/[.!؟?]/g, '\n');
        for (const line of t.split('\n')) {
            for (const [re, pol] of POL) {
                const mt = re.exec(line.replace(/\u200c/g, '‌'));
                if (mt) {
                    const topic = tokenize(mt[1]).slice(0, 2).join(' ');
                    if (topic) {
                        stmts.push({ m, topic, pol });
                        break;
                    }
                }
            }
        }
        void n;
    }
    const out = [];
    const seen = new Set();
    for (let i = 0; i < stmts.length; i += 1)
        for (let j = i + 1; j < stmts.length; j += 1) {
            const a = stmts[i];
            const b = stmts[j];
            if (a.m.id === b.m.id || a.topic !== b.topic || a.pol === b.pol)
                continue;
            const sig = `contra:${[a.m.id, b.m.id].sort().join(':')}`;
            if (seen.has(sig))
                continue;
            seen.add(sig);
            out.push({ kind: 'contradiction', signature: sig, source: 'rule-based', evidence: [evidenceOf(a.m), evidenceOf(b.m)],
                text: `دو خاطره دربارهٔ «${a.topic}» ظاهراً نظرهای متفاوتی دارند (${formatJalali(new Date(a.m.eventAt))} و ${formatJalali(new Date(b.m.eventAt))}). ممکن است نظر شما با گذشت زمان تغییر کرده باشد یا شرایط متفاوت بوده باشد؛ این فقط یک احتمال است.` });
        }
    return out;
}
function buildReport(all, o) {
    let ms = all.filter((m) => { const d = new Date(m.eventAt); return d >= o.from && d <= o.to; });
    if (o.topic) {
        const q = tokenize(o.topic);
        ms = ms.filter((m) => { const n = normalize([m.text, m.tags.join(' '), m.people.join(' '), m.events.join(' '), m.category].join(' ')); return q.every((t) => n.includes(t)); });
    }
    ms.sort((a, b) => a.eventAt.localeCompare(b.eventAt));
    const s = periodStats(ms, o.from, o.to);
    return { title: o.title, from: o.from, to: o.to, stats: s, memories: ms };
}
function reportPeriod(kind, ref = new Date()) {
    const f = new Date(ref);
    const t = new Date(ref);
    if (kind === 'day') {
        f.setHours(0, 0, 0, 0);
        t.setHours(23, 59, 59, 999);
        return { from: f, to: t, title: `گزارش روزانه — ${formatJalali(ref)}` };
    }
    if (kind === 'week') {
        const wi = weekdayIndex(ref);
        f.setDate(f.getDate() - wi);
        f.setHours(0, 0, 0, 0);
        t.setTime(f.getTime() + 7 * 86400000 - 1);
        return { from: f, to: t, title: `گزارش هفتگی — از ${formatJalali(f)}` };
    }
    if (kind === 'month') {
        const j = dateToJalali(ref);
        return { from: monthStart(j.y, j.m), to: new Date(monthStart(j.m === 12 ? j.y + 1 : j.y, j.m === 12 ? 1 : j.m + 1).getTime() - 1), title: `گزارش ماهانه — ${JALALI_MONTHS[j.m - 1]} ${faDigits(j.y)}` };
    }
    const j = dateToJalali(ref);
    return { from: monthStart(j.y, 1), to: new Date(monthStart(j.y + 1, 1).getTime() - 1), title: `گزارش سالانه — ${faDigits(j.y)}` };
}
const { jalaliToDate } = __M["util/jalali.js"];
function monthStart(y, m) { return jalaliToDate(y, m, 1, 0, 0, 0); }
/** روایت زمانی ساده از خاطره‌های واقعی (بدون تولید متن توسط مدل) */
function narrative(ms, max = 40) {
    const s = [...ms].sort((a, b) => a.eventAt.localeCompare(b.eventAt)).slice(-max);
    return s.map((m) => `${formatJalali(new Date(m.eventAt))}: ${m.text.split('\n')[0].slice(0, 160)}${m.mood ? ` (حال‌وهوای ثبت‌شده: ${MOODS[m.mood.score - 1].label})` : ''}`).join('\n');
}

return { suggestCategory, suggestTags, suggestMood, related, onThisDay, countBy, monthKey, periodStats, moodSeries, generateInsights, findContradictions, buildReport, reportPeriod, narrative };
})();
__M["core/ai.js"] = (() => {
const { formatJalali } = __M["util/jalali.js"];
const { b64 } = __M["util/id.js"];
const GEMINI_HOST = 'generativelanguage.googleapis.com';
const GEMINI_DEFAULT_MODEL = 'gemini-3.8-flash';
const MAX_OCR_BYTES = 6 * 1024 * 1024;
/** نشانی رسمی Gemini (REST بومی). نام مدل اعتبارسنجی می‌شود تا مسیر درخواست دست‌کاری نشود. */
function geminiUrl(model) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(model))
        throw new Error('نام مدل Gemini معتبر نیست');
    return `https://${GEMINI_HOST}/v1beta/models/${model}:generateContent`;
}
/** میزبانی که داده به آن فرستاده می‌شود (برای نمایش در پنجرهٔ تأیید) */
function aiHost(cfg) { return cfg.provider === 'gemini' ? GEMINI_HOST : hostOf(cfg.endpoint); }
function buildPrompt(question, memories, maxChars = 1200) {
    const ctx = memories.map((m, i) => `[${i + 1}] ${formatJalali(new Date(m.eventAt))}: ${m.text.slice(0, maxChars)}`).join('\n');
    const sys = 'تو دستیار آرشیو شخصی هستی. فقط بر اساس خاطره‌های زیر پاسخ بده، منبع را با شماره [n] بیاور و اگر پاسخ در خاطره‌ها نیست بگو «در آرشیو پیدا نشد». هرگز واقعیت جدید نساز و همبستگی را علت قطعی نخوان.';
    const user = `خاطره‌ها:\n${ctx || '(هیچ)'}\n\nپرسش: ${question}`;
    return { messages: [{ role: 'system', content: sys }, { role: 'user', content: user }], preview: `${sys}\n\n${user}` };
}
function hostOf(endpoint) { try {
    return new URL(endpoint).host;
}
catch {
    return endpoint;
} }
const defaultFetch = (...a) => fetch(...a);
async function callGemini(cfg, body, fetchFn) {
    if (!cfg.apiKey)
        throw new Error('کلید API برای Gemini وارد نشده است');
    const res = await fetchFn(geminiUrl(cfg.model || GEMINI_DEFAULT_MODEL), { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': cfg.apiKey }, body: JSON.stringify(body) });
    if (!res.ok)
        throw new Error(`خطای سرویس Gemini (${res.status})`);
    const j = await res.json();
    const parts = j?.candidates?.[0]?.content?.parts;
    const t = Array.isArray(parts) ? parts.map((p) => (typeof p?.text === 'string' ? p.text : '')).join('') : '';
    if (!t)
        throw new Error('پاسخ Gemini خالی یا مسدودشده بود');
    return t;
}
/** استخراج متن از تصویر (OCR) با Gemini؛ فقط پس از تأیید صریح کاربر در لایهٔ رابط فراخوانی می‌شود */
async function extractImageText(cfg, bytes, mime, fetchFn = defaultFetch) {
    if (cfg.provider !== 'gemini')
        throw new Error('استخراج متن از تصویر فقط با Gemini پشتیبانی می‌شود');
    if (!/^image\/(png|jpe?g|webp|heic|heif)$/i.test(mime))
        throw new Error('قالب تصویر برای استخراج متن پشتیبانی نمی‌شود');
    if (bytes.length > MAX_OCR_BYTES)
        throw new Error('تصویر برای ارسال بزرگ است (حداکثر ۶ مگابایت)');
    return callGemini(cfg, { contents: [{ role: 'user', parts: [{ text: 'فقط متن موجود در این تصویر را عیناً و بدون توضیح اضافه بنویس. اگر متنی نیست بنویس: «متنی یافت نشد».' }, { inlineData: { mimeType: mime, data: b64(bytes) } }] }], generationConfig: { temperature: 0 } }, fetchFn);
}
async function askExternal(cfg, messages, fetchFn = defaultFetch) {
    if (cfg.provider === 'gemini') {
        const sys = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
        const user = messages.filter((m) => m.role === 'user').map((m) => ({ role: 'user', parts: [{ text: m.content }] }));
        return callGemini(cfg, { ...(sys ? { systemInstruction: { parts: [{ text: sys }] } } : {}), contents: user, generationConfig: { temperature: 0.2 } }, fetchFn);
    }
    if (!cfg.endpoint || !cfg.model)
        throw new Error('نشانی سرویس و نام مدل در تنظیمات وارد نشده است');
    let u;
    try {
        u = new URL(cfg.endpoint);
    }
    catch {
        throw new Error('نشانی سرویس معتبر نیست');
    }
    if (u.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(u.hostname))
        throw new Error('فقط نشانی https (یا localhost) پذیرفته می‌شود');
    const res = await fetchFn(cfg.endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {}) }, body: JSON.stringify({ model: cfg.model, messages, temperature: 0.2 }) });
    if (!res.ok)
        throw new Error(`خطای سرویس هوش مصنوعی (${res.status})`);
    const j = await res.json();
    const t = j?.choices?.[0]?.message?.content;
    if (typeof t !== 'string')
        throw new Error('پاسخ سرویس قابل فهم نبود');
    return t;
}

return { GEMINI_HOST, GEMINI_DEFAULT_MODEL, MAX_OCR_BYTES, geminiUrl, aiHost, buildPrompt, hostOf, extractImageText, askExternal };
})();
__M["ui/views/memory.js"] = (() => {
const { MOODS } = __M["core/types.js"];
const { applyFilters, search, snippet } = __M["core/search.js"];
const { related, suggestCategory, suggestMood, suggestTags } = __M["core/analysis.js"];
const { clear, confirmBox, dateField, fmtBytes, h, openSheet, toast, download } = __M["ui/dom.js"];
const { faDigits, formatGregorian, formatJalali } = __M["util/jalali.js"];
const { splitList } = __M["util/text.js"];
const { extractImageText, aiHost } = __M["core/ai.js"];
const { onThisDay } = __M["core/analysis.js"];
function moodBadge(m) { return m.mood ? h('span', { class: 'badge' }, MOODS[m.mood.score - 1].emoji, ' ', m.mood.label) : null; }
function memCard(ctx, m, extra) {
    const d = new Date(m.eventAt);
    return h('a', { class: 'card mem', href: `#/m/${encodeURIComponent(m.id)}` }, h('div', { class: 'row between' }, h('span', { class: 'date' }, formatJalali(d, { time: true }), ctx.settings.showGregorian && h('small', { class: 'muted' }, ` · ${formatGregorian(d)}`)), moodBadge(m)), h('p', { class: 'snip' }, m.text ? (m.text.length > 160 ? m.text.slice(0, 160) + '…' : m.text) : '(بدون متن)'), h('div', { class: 'row wrap tags' }, h('span', { class: 'tag cat' }, m.category), m.tags.map((t) => h('span', { class: 'tag' }, '#' + t)), m.attachments.length ? h('span', { class: 'tag' }, `📎 ${faDigits(m.attachments.length)}`) : null), extra && h('p', { class: 'why' }, extra));
}
const recent = (ctx) => [...ctx.archive.memories.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
// ---------- خانه ----------
const homeView = async (ctx) => {
    const wrap = h('div', { class: 'stack' });
    const ta = h('textarea', { rows: '3', placeholder: 'چه چیزی در ذهنت هست؟ سریع بنویس…', 'aria-label': 'ثبت سریع خاطره' });
    const save = h('button', { class: 'btn primary', type: 'button' }, 'ثبت');
    save.addEventListener('click', async () => {
        if (!ta.value.trim()) {
            toast('متنی نوشته نشده است', 'warn');
            return;
        }
        save.setAttribute('disabled', '');
        try {
            await ctx.archive.createMemory({ text: ta.value, source: 'quick' });
            ta.value = '';
            await ctx.archive.clearDraft();
            toast('خاطره ثبت شد');
            ctx.rerender();
        }
        catch (e) {
            toast(`ذخیره نشد: ${e.message}`, 'err', 8000);
        }
        finally {
            save.removeAttribute('disabled');
        }
    });
    wrap.append(h('div', { class: 'card' }, ta, h('div', { class: 'row between' }, h('a', { class: 'btn small', href: '#/new?mode=guided' }, 'ثبت هدایت‌شده'), save)));
    const q = h('input', { type: 'search', placeholder: 'جست‌وجوی سریع…', 'aria-label': 'جست‌وجو' });
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter')
        ctx.go(`search?q=${encodeURIComponent(q.value)}`); });
    wrap.append(q);
    const cats = ctx.categories();
    wrap.append(h('div', { class: 'row wrap' }, cats.map((c) => h('a', { class: 'chip cat', href: `#/search?cat=${encodeURIComponent(c)}` }, c))));
    const sum = await ctx.archive.storageSummary();
    const used = sum.usage !== undefined ? `${fmtBytes(sum.usage)}${sum.quota ? ' از ' + fmtBytes(sum.quota) : ''}` : fmtBytes(sum.attachmentBytes);
    wrap.append(h('p', { class: 'muted small' }, `${faDigits(sum.memories)} خاطره · فضای مصرفی ${used}`));
    const otd = onThisDay([...ctx.archive.memories.values()]);
    if (otd.length)
        wrap.append(h('section', null, h('h2', null, 'در چنین روزی'), otd.slice(0, 3).map((m) => memCard(ctx, m))));
    const r = recent(ctx).slice(0, 8);
    wrap.append(h('section', null, h('h2', null, 'آخرین خاطره‌ها'), r.length ? r.map((m) => memCard(ctx, m)) : h('div', { class: 'empty' }, 'هنوز خاطره‌ای ثبت نشده. اولین را همین حالا بنویس.')));
    return wrap;
};
function memoryForm(ctx, o) {
    const ex = o.existing;
    const A = ctx.archive;
    const text = h('textarea', { rows: o.mode === 'guided' ? '4' : '7', value: ex?.text ?? '', placeholder: 'متن خاطره…', 'aria-label': 'متن خاطره' });
    const ev = dateField({ value: ex ? new Date(ex.eventAt) : new Date(), time: true, label: 'زمان وقوع رویداد' });
    let mood = ex?.mood ?? null;
    const moodRow = h('div', { class: 'row wrap moods', role: 'radiogroup', 'aria-label': 'حال‌وهوا' });
    const drawMood = () => { clear(moodRow); MOODS.forEach((m) => moodRow.append(h('button', { type: 'button', class: `mood ${mood?.score === m.score ? 'on' : ''}`, role: 'radio', 'aria-checked': String(mood?.score === m.score), title: m.label, onclick: () => { mood = mood?.score === m.score ? null : { score: m.score, label: m.label }; drawMood(); } }, m.emoji, h('small', null, m.label)))); };
    drawMood();
    const cat = h('select', { 'aria-label': 'دسته‌بندی' }, ctx.categories().map((c) => h('option', { value: c, selected: (ex?.category ?? 'خاطرات روزانه') === c }, c)));
    const tags = h('input', { value: ex?.tags.join('، ') ?? '', placeholder: 'برچسب‌ها (با ویرگول جدا کنید)', 'aria-label': 'برچسب‌ها' });
    const people = h('input', { value: ex?.people.join('، ') ?? '', placeholder: 'اشخاص مرتبط', 'aria-label': 'اشخاص' });
    const events = h('input', { value: ex?.events.join('، ') ?? '', placeholder: 'رویدادهای مرتبط (مثلاً «سفر شمال»)', 'aria-label': 'رویدادها' });
    const decisions = h('textarea', { rows: '2', value: ex?.decisions ?? '', placeholder: 'تصمیمی که گرفتی (اختیاری)', 'aria-label': 'تصمیم' });
    const goals = h('textarea', { rows: '2', value: ex?.goals ?? '', placeholder: 'هدف مرتبط (اختیاری)', 'aria-label': 'هدف' });
    const outcomes = h('textarea', { rows: '2', value: ex?.outcomes ?? '', placeholder: 'نتیجه یا پیامد (اختیاری)', 'aria-label': 'نتیجه' });
    const links = new Set(ex?.links ?? []);
    const sugg = h('div', { class: 'stack' });
    const pending = [];
    const pendList = h('ul', { class: 'plist' });
    const drawPending = () => { clear(pendList); pending.forEach((f, i) => pendList.append(h('li', null, `${f.name} — ${fmtBytes(f.size)}`, h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'حذف از فهرست', onclick: () => { pending.splice(i, 1); drawPending(); } }, '✕')))); };
    const refreshSuggestions = () => {
        clear(sugg);
        const t = text.value;
        if (t.trim().length < 12)
            return;
        const sc = suggestCategory(t);
        if (sc && sc.category !== cat.value)
            sugg.append(h('div', { class: 'row wrap' }, h('span', { class: 'muted small' }, `پیشنهاد دسته (به‌دلیل: ${sc.because.slice(0, 3).join('، ')}):`), h('button', { type: 'button', class: 'chip', onclick: () => { if ([...cat.options].some((x) => x.value === sc.category))
                    cat.value = sc.category; refreshSuggestions(); } }, sc.category)));
        const existing = [...new Set([...A.memories.values()].flatMap((m) => m.tags))];
        const st = suggestTags(t, existing).filter((x) => !splitList(tags.value).includes(x));
        if (st.length)
            sugg.append(h('div', { class: 'row wrap' }, h('span', { class: 'muted small' }, 'برچسب پیشنهادی:'), st.map((x) => h('button', { type: 'button', class: 'chip', onclick: () => { tags.value = [...splitList(tags.value), x].join('، '); refreshSuggestions(); } }, '#' + x))));
        const sm = suggestMood(t);
        if (sm && !mood)
            sugg.append(h('div', { class: 'row wrap' }, h('span', { class: 'muted small' }, `حال‌وهوای پیشنهادی (از واژه‌های: ${sm.because.slice(0, 3).join('، ')}) — فقط با تأیید شما ثبت می‌شود:`), h('button', { type: 'button', class: 'chip', onclick: () => { mood = { score: sm.score, label: MOODS[sm.score - 1].label }; drawMood(); refreshSuggestions(); } }, MOODS[sm.score - 1].emoji + ' ' + MOODS[sm.score - 1].label)));
        const tmp = { id: ex?.id ?? '_new', text: t, tags: splitList(tags.value), people: splitList(people.value), decisions: '', goals: '', outcomes: '', events: [], links: [...links] };
        const rel = related(tmp, [...A.memories.values()], 3);
        if (rel.length)
            sugg.append(h('div', null, h('span', { class: 'muted small' }, 'خاطره‌های احتمالاً مرتبط (برای ارتباط‌دادن لمس کنید):'), rel.map((r) => h('button', { type: 'button', class: `chip block ${links.has(r.memory.id) ? 'on' : ''}`, onclick: () => { links.has(r.memory.id) ? links.delete(r.memory.id) : links.add(r.memory.id); refreshSuggestions(); } }, `${formatJalali(new Date(r.memory.eventAt))}: ${r.memory.text.slice(0, 40)}… (${r.why[0] ?? ''})`))));
    };
    let tmr = 0;
    const draftSave = () => { if (ex)
        return; window.clearTimeout(tmr); tmr = window.setTimeout(() => { if (text.value.trim())
        void A.setDraft({ text: text.value, tags: tags.value, people: people.value }); }, 700); };
    text.addEventListener('input', () => { draftSave(); window.clearTimeout(text._t); text._t = window.setTimeout(refreshSuggestions, 600); });
    const fileInputs = h('div', { class: 'stack' });
    if (!ex) {
        const mk = (label, accept, capture) => { const i = h('input', { type: 'file', accept, multiple: true, capture }); i.addEventListener('change', () => { [...(i.files ?? [])].forEach((f) => pending.push(f)); i.value = ''; drawPending(); }); return h('label', { class: 'btn small' }, label, i); };
        const rec = h('button', { type: 'button', class: 'btn small' }, '🎙 ضبط صدا');
        let mr = null;
        let chunks = [];
        rec.addEventListener('click', async () => {
            if (mr) {
                mr.stop();
                return;
            }
            if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
                toast('ضبط صدا در این مرورگر پشتیبانی نمی‌شود', 'warn');
                return;
            }
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                mr = new MediaRecorder(stream);
                chunks = [];
                mr.ondataavailable = (e) => chunks.push(e.data);
                mr.onstop = () => { stream.getTracks().forEach((t) => t.stop()); const type = mr.mimeType || 'audio/webm'; const ext = type.includes('mp4') ? 'm4a' : type.includes('ogg') ? 'ogg' : 'webm'; pending.push(new File(chunks, `ضبط-${Date.now()}.${ext}`, { type })); mr = null; rec.textContent = '🎙 ضبط صدا'; drawPending(); };
                mr.start();
                rec.textContent = '⏹ پایان ضبط';
            }
            catch {
                toast('دسترسی به میکروفون داده نشد. برای ضبط، مجوز میکروفون لازم است.', 'err', 6000);
            }
        });
        fileInputs.append(h('div', { class: 'row wrap' }, mk('🖼 عکس', 'image/*'), mk('🎬 ویدئو', 'video/*'), mk('🎵 صوت', 'audio/*'), mk('📄 فایل', '*/*'), rec), pendList);
    }
    const detailsBox = h('details', { open: !!(ex?.decisions || ex?.goals || ex?.outcomes) }, h('summary', null, 'تصمیم، هدف و نتیجه'), h('div', { class: 'stack' }, decisions, goals, outcomes));
    const err = h('p', { class: 'error', role: 'alert' });
    const saveBtn = h('button', { class: 'btn primary wide', type: 'button' }, ex ? 'ذخیرهٔ تغییرات' : 'ثبت خاطره');
    saveBtn.addEventListener('click', async () => {
        err.textContent = '';
        const when = ev.get();
        if (!when) {
            err.textContent = 'تاریخ وقوع معتبر نیست.';
            return;
        }
        if (!text.value.trim() && !pending.length && !ex) {
            err.textContent = 'متن یا پیوستی وارد کنید.';
            return;
        }
        saveBtn.setAttribute('disabled', '');
        try {
            const base = { text: text.value, mood, category: cat.value, tags: splitList(tags.value), people: splitList(people.value), events: splitList(events.value), decisions: decisions.value, goals: goals.value, outcomes: outcomes.value, links: [...links] };
            if (ex) {
                await A.updateMemory(ex.id, { ...base, eventAt: when.toISOString() });
                toast('ذخیره شد');
                ctx.go(`m/${ex.id}`);
                return;
            }
            const m = await A.createMemory({ ...base, eventAt: when, source: pending.length ? 'attachment' : o.mode === 'guided' ? 'guided' : 'quick' });
            for (const f of pending) {
                try {
                    const extra = {};
                    if (f.type.startsWith('image/')) {
                        const dim = await imgDims(f);
                        Object.assign(extra, dim);
                    }
                    await A.addAttachment(m.id, f, extra);
                }
                catch (e) {
                    toast(`پیوست «${f.name}» ذخیره نشد: ${e.message}`, 'err', 8000);
                }
            }
            await A.clearDraft();
            toast('خاطره ثبت شد');
            ctx.go(`m/${m.id}`);
        }
        catch (e) {
            err.textContent = `ذخیره نشد: ${e.message}`;
            if (/quota/i.test(String(e.name + e.message)))
                err.textContent += ' — فضای ذخیره‌سازی پر است؛ از تنظیمات ← فضا، پیشنهادهای پاک‌سازی را ببینید.';
            saveBtn.removeAttribute('disabled');
        }
    });
    return h('div', { class: 'stack' }, text, sugg, ev.el, h('div', null, h('span', { class: 'lbl' }, 'حال‌وهوا (اختیاری)'), moodRow), h('label', null, 'دسته‌بندی', cat), tags, people, events, detailsBox, fileInputs, err, saveBtn);
}
function imgDims(f) {
    return new Promise((res) => { const u = URL.createObjectURL(f); const i = new Image(); i.onload = () => { res({ width: i.naturalWidth, height: i.naturalHeight }); URL.revokeObjectURL(u); }; i.onerror = () => { res({}); URL.revokeObjectURL(u); }; i.src = u; });
}
const GUIDED = [
    { id: 'text', q: 'چه اتفاقی افتاد؟', ph: 'هر چه به ذهنت می‌رسد…' }, { id: 'people', q: 'چه کسانی همراهت بودند؟', ph: 'نام‌ها را با ویرگول جدا کن' },
    { id: 'mood', q: 'چه حسی داشتی؟' }, { id: 'decisions', q: 'تصمیمی گرفتی؟', ph: 'تصمیم' }, { id: 'goals', q: 'به هدفی مربوط می‌شود؟', ph: 'هدف' }, { id: 'outcomes', q: 'نتیجه یا پیامدش چه بود؟', ph: 'نتیجه' },
];
const newView = async (ctx, _a, q) => {
    const mode = q.get('mode') || 'quick';
    const wrap = h('div', { class: 'stack' });
    const tabs = h('div', { class: 'seg', role: 'tablist' }, [['quick', 'سریع'], ['guided', 'هدایت‌شده'], ['attachment', 'با پیوست']].map(([k, l]) => h('a', { class: mode === k ? 'on' : '', role: 'tab', href: `#/new?mode=${k}` }, l)));
    wrap.append(tabs);
    const draft = mode === 'guided' ? null : await ctx.archive.getDraft();
    if (mode === 'guided') {
        // پرسش‌ها همه اختیاری‌اند و قابل ردکردن
        const vals = {};
        let mood = null;
        let i = 0;
        const box = h('div', { class: 'card stack' });
        const ev = dateField({ time: true, label: 'زمان وقوع رویداد' });
        const draw = () => {
            clear(box);
            if (i >= GUIDED.length) {
                box.append(h('p', null, 'همهٔ پرسش‌ها تمام شد. زمان وقوع را بررسی و ثبت کنید.'), ev.el);
                const b = h('button', { class: 'btn primary wide', type: 'button' }, 'ثبت خاطره');
                b.addEventListener('click', async () => {
                    const when = ev.get();
                    if (!when) {
                        toast('تاریخ معتبر نیست', 'err');
                        return;
                    }
                    if (!Object.values(vals).some((v) => v.trim()) && !mood) {
                        toast('هیچ پاسخی وارد نشده', 'warn');
                        return;
                    }
                    try {
                        const m = await ctx.archive.createMemory({ text: vals.text, people: splitList(vals.people ?? ''), mood, decisions: vals.decisions, goals: vals.goals, outcomes: vals.outcomes, eventAt: when, source: 'guided', category: suggestCategory(vals.text ?? '')?.category ?? 'خاطرات روزانه' });
                        toast('خاطره ثبت شد');
                        ctx.go(`m/${m.id}`);
                    }
                    catch (e) {
                        toast(`ذخیره نشد: ${e.message}`, 'err', 8000);
                    }
                });
                box.append(b);
                return;
            }
            const g = GUIDED[i];
            box.append(h('p', { class: 'muted small' }, `پرسش ${faDigits(i + 1)} از ${faDigits(GUIDED.length)} — اختیاری`), h('h2', null, g.q));
            if (g.id === 'mood') {
                box.append(h('div', { class: 'row wrap moods' }, MOODS.map((m) => h('button', { type: 'button', class: `mood ${mood?.score === m.score ? 'on' : ''}`, onclick: () => { mood = { score: m.score, label: m.label }; draw(); } }, m.emoji, h('small', null, m.label)))));
            }
            else {
                const t = h('textarea', { rows: g.id === 'text' ? '5' : '2', value: vals[g.id] ?? '', placeholder: g.ph });
                t.addEventListener('input', () => { vals[g.id] = t.value; });
                box.append(t);
            }
            box.append(h('div', { class: 'row between' }, h('button', { class: 'btn', type: 'button', onclick: () => { i += 1; draw(); } }, 'رد کردن'), h('button', { class: 'btn primary', type: 'button', onclick: () => { i += 1; draw(); } }, 'بعدی')));
        };
        draw();
        wrap.append(box);
        return wrap;
    }
    if (draft?.text)
        wrap.append(h('div', { class: 'card note' }, 'پیش‌نویس ذخیره‌نشدهٔ قبلی بازیابی شد.', h('button', { class: 'btn small', type: 'button', onclick: async () => { await ctx.archive.clearDraft(); ctx.rerender(); } }, 'دور انداختن')));
    const form = memoryForm(ctx, { mode });
    if (draft?.text) {
        form.querySelector('textarea').value = draft.text;
    }
    wrap.append(form);
    return wrap;
};
const editView = (ctx, [id]) => {
    const m = ctx.archive.memories.get(id);
    if (!m)
        return h('div', { class: 'empty' }, 'خاطره پیدا نشد');
    return h('div', { class: 'stack' }, h('p', { class: 'muted small' }, 'متن اصلیِ اولیه همیشه در تاریخچهٔ تغییرات نگه‌داری می‌شود.'), memoryForm(ctx, { mode: 'quick', existing: m }));
};
// ---------- جزئیات ----------
const detailView = async (ctx, [id]) => {
    const A = ctx.archive;
    const m = A.memories.get(id);
    if (!m)
        return h('div', { class: 'empty' }, 'این خاطره پیدا نشد (شاید حذف شده باشد).');
    const ed = new Date(m.eventAt);
    const cd = new Date(m.createdAt);
    const ud = new Date(m.updatedAt);
    const w = h('div', { class: 'stack' });
    w.append(h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('div', null, h('div', { class: 'date big' }, formatJalali(ed, { time: true, seconds: true, weekday: true })), ctx.settings.showGregorian && h('small', { class: 'muted' }, `میلادی: ${formatGregorian(ed, { time: true, seconds: true })}`)), moodBadge(m)), h('p', { class: 'body' }, m.text || '(بدون متن)'), h('div', { class: 'row wrap tags' }, h('span', { class: 'tag cat' }, m.category), m.tags.map((t) => h('a', { class: 'tag', href: `#/search?tag=${encodeURIComponent(t)}` }, '#' + t)), m.people.map((p) => h('a', { class: 'tag p', href: `#/search?person=${encodeURIComponent(p)}` }, '👤 ' + p)), m.events.map((e) => h('span', { class: 'tag e' }, '📌 ' + e))), [['تصمیم', m.decisions], ['هدف', m.goals], ['نتیجه', m.outcomes]].filter(([, v]) => v).map(([k, v]) => h('p', null, h('b', null, k + ': '), v)), h('dl', { class: 'meta' }, h('dt', null, 'زمان ثبت'), h('dd', null, `${formatJalali(cd, { time: true, seconds: true })} (${m.tz})`), h('dt', null, 'آخرین ویرایش'), h('dd', null, formatJalali(ud, { time: true, seconds: true })), h('dt', null, 'منبع'), h('dd', null, { quick: 'ثبت سریع', guided: 'ثبت هدایت‌شده', attachment: 'ثبت با پیوست', import: 'درون‌ریزی', 'conflict-copy': 'نسخهٔ تعارض' }[m.context.source]), h('dt', null, 'هنگام ثبت'), h('dd', null, m.context.online ? 'آنلاین' : 'آفلاین')), h('div', { class: 'row wrap' }, h('a', { class: 'btn', href: `#/edit/${m.id}` }, 'ویرایش'), h('button', { class: 'btn', type: 'button', onclick: () => changeEventTime(ctx, m) }, 'اصلاح زمان وقوع'), h('button', { class: 'btn danger', type: 'button', onclick: async () => { if (await confirmBox('این خاطره و پیوست‌هایش از آرشیو حذف می‌شود.', { danger: true, confirmText: 'حذف', detail: 'حذف در صف Drive قرار می‌گیرد. پشتیبان‌های مستقل قبلی تغییر نمی‌کنند و نسخه‌های قدیمیِ Google Drive تضمینی برای پاک‌شدن فوری ندارند.' })) {
            await A.deleteMemory(m.id);
            toast('حذف شد');
            ctx.go('home');
        } } }, 'حذف'))));
    if (m.attachments.length) {
        const box = h('section', { class: 'stack' }, h('h2', null, 'پیوست‌ها'));
        for (const a of m.attachments)
            box.append(await attachmentView(ctx, m, a));
        w.append(box);
    }
    const rel = related(m, [...A.memories.values()], 4);
    if (rel.length)
        w.append(h('section', null, h('h2', null, 'ارتباط‌های پیشنهادی'), rel.map((r) => memCard(ctx, r.memory, 'چرا: ' + r.why.join(' · ')))));
    const linked = m.links.map((l) => A.memories.get(l)).filter(Boolean);
    if (linked.length)
        w.append(h('section', null, h('h2', null, 'ارتباط‌های ثبت‌شده'), linked.map((x) => memCard(ctx, x))));
    if (m.revisions.length || m.eventAtHistory.length) {
        w.append(h('details', { class: 'card' }, h('summary', null, 'تاریخچهٔ تغییرات'), h('p', { class: 'muted small' }, 'متن اصلی (اولیه):'), h('blockquote', null, m.originalText), m.revisions.map((r) => h('div', null, h('p', { class: 'muted small' }, `متن پیش از ویرایش در ${formatJalali(new Date(r.at), { time: true, seconds: true })}:`), h('blockquote', null, r.before))), m.eventAtHistory.map((c) => h('p', { class: 'small' }, `زمان وقوع در ${formatJalali(new Date(c.at), { time: true, seconds: true })} از «${formatJalali(new Date(c.from), { time: true })}» به «${formatJalali(new Date(c.to), { time: true })}» اصلاح شد.`))));
    }
    return w;
};
function changeEventTime(ctx, m) {
    const f = dateField({ value: new Date(m.eventAt), time: true, label: 'زمان وقوع جدید' });
    const s = openSheet('اصلاح زمان وقوع', h('div', { class: 'stack' }, f.el, h('p', { class: 'muted small' }, 'زمان ثبت تغییر نمی‌کند و اصلاح در تاریخچه می‌ماند.'), h('button', { class: 'btn primary', type: 'button', onclick: async () => { const d = f.get(); if (!d) {
            toast('تاریخ معتبر نیست', 'err');
            return;
        } await ctx.archive.updateMemory(m.id, { eventAt: d.toISOString() }); s.close(); ctx.rerender(); } }, 'ذخیره')));
}
async function attachmentView(ctx, m, a) {
    const box = h('div', { class: 'card stack' });
    box.append(h('div', { class: 'row between' }, h('b', null, a.name), h('small', { class: 'muted' }, fmtBytes(a.size))));
    const meta = [a.mime, a.width ? `${faDigits(a.width)}×${faDigits(a.height ?? 0)}` : '', a.lastModified ? `تاریخ فایل: ${formatJalali(new Date(a.lastModified))}` : ''].filter(Boolean).join(' · ');
    box.append(h('p', { class: 'muted small' }, meta));
    const holder = h('div');
    const show = h('button', { class: 'btn small', type: 'button' }, a.kind === 'file' ? 'آماده‌سازی دانلود' : 'نمایش / پخش');
    show.addEventListener('click', async () => {
        show.setAttribute('disabled', '');
        try {
            let bytes;
            try {
                bytes = await ctx.archive.getAttachmentBytes(a);
            }
            catch (e) {
                if (ctx.settings.online.drive && /موجود نیست/.test(e.message)) {
                    await ctx.engine().pullBlob(a.id);
                    bytes = await ctx.archive.getAttachmentBytes(a);
                }
                else
                    throw e;
            }
            const blob = new Blob([bytes], { type: a.mime });
            const url = URL.createObjectURL(blob);
            clear(holder);
            if (a.kind === 'image')
                holder.append(h('img', { src: url, alt: a.name, class: 'media' }));
            else if (a.kind === 'video')
                holder.append(h('video', { src: url, controls: true, class: 'media', playsinline: true }));
            else if (a.kind === 'audio')
                holder.append(h('audio', { src: url, controls: true }));
            holder.append(h('button', { class: 'btn small', type: 'button', onclick: () => download(blob, a.name) }, 'ذخیرهٔ نسخهٔ اصلی'));
            show.remove();
        }
        catch (e) {
            toast(`باز نشد: ${e.message}`, 'err', 7000);
            show.removeAttribute('disabled');
        }
    });
    const txt = h('textarea', { rows: '2', value: a.extractedText ?? '', placeholder: 'متنِ موجود در فایل (دستی یا با استخراج Gemini). آنچه اینجا ذخیره شود در جست‌وجو یافت می‌شود.', 'aria-label': 'متن استخراج‌شده' });
    const saveTxt = async () => { await ctx.archive.setAttachmentText(m.id, a.id, txt.value); toast('ذخیره شد'); };
    txt.addEventListener('change', saveTxt);
    const aiCfg = ctx.settings.ai;
    const canOcr = a.kind === 'image' && ctx.settings.online.externalAi && aiCfg.provider === 'gemini';
    const ocr = canOcr ? h('button', { class: 'btn small', type: 'button', onclick: async () => {
            if (!(await confirmBox(`خودِ تصویر «${a.name}» (${fmtBytes(a.size)}) به «${aiHost(aiCfg)}» ارسال می‌شود تا متن آن خوانده شود. فقط همین تصویر ارسال می‌شود. ادامه می‌دهید؟`, { confirmText: 'ارسال تصویر' })))
                return;
            try {
                const bytes = await ctx.archive.getAttachmentBytes(a);
                const r = await extractImageText({ ...aiCfg, apiKey: (await ctx.archive.getSecret()).aiKey }, bytes, a.mime);
                txt.value = r;
                toast('متن پیشنهادی آمد؛ آن را بخوانید، اصلاح کنید و «ذخیرهٔ متن» را بزنید', 'ok', 7000);
            }
            catch (e) {
                toast('استخراج ناموفق: ' + e.message, 'err', 8000);
            }
        } }, 'استخراج متن با Gemini (ارسال عکس)') : null;
    const saveBtn = h('button', { class: 'btn small', type: 'button', onclick: saveTxt }, 'ذخیرهٔ متن');
    box.append(show, holder, txt, ocr, saveBtn, h('button', { class: 'btn small danger', type: 'button', onclick: async () => { if (await confirmBox(`پیوست «${a.name}» حذف شود؟`, { danger: true, confirmText: 'حذف' })) {
            await ctx.archive.removeAttachment(m.id, a.id);
            ctx.rerender();
        } } }, 'حذف پیوست'));
    return box;
}
// ---------- جست‌وجو ----------
const searchView = (ctx, _a, q) => {
    const A = ctx.archive;
    const all = [...A.memories.values()];
    const f = { category: q.get('cat') ?? undefined, tag: q.get('tag') ?? undefined, person: q.get('person') ?? undefined };
    const input = h('input', { type: 'search', value: q.get('q') ?? '', placeholder: 'جست‌وجو در متن، برچسب، اشخاص، پیوست‌ها…', 'aria-label': 'عبارت جست‌وجو' });
    const results = h('div', { class: 'stack' });
    const catSel = h('select', { 'aria-label': 'دسته' }, h('option', { value: '' }, 'همهٔ دسته‌ها'), ctx.categories().map((c) => h('option', { value: c, selected: f.category === c }, c)));
    const moodSel = h('select', { 'aria-label': 'حال‌وهوا' }, h('option', { value: '' }, 'هر حال‌وهوا'), MOODS.map((m) => h('option', { value: m.score }, `${m.emoji} ${m.label}`)));
    const from = dateField({ value: null, optional: true, label: 'از تاریخ' });
    const to = dateField({ value: null, optional: true, label: 'تا تاریخ' });
    const att = h('select', { 'aria-label': 'پیوست' }, h('option', { value: '' }, 'با/بدون پیوست'), h('option', { value: 'any' }, 'دارای پیوست'), h('option', { value: 'image' }, 'عکس'), h('option', { value: 'video' }, 'ویدئو'), h('option', { value: 'audio' }, 'صوت'), h('option', { value: 'file' }, 'فایل'));
    const tagIn = h('input', { value: f.tag ?? '', placeholder: 'برچسب', 'aria-label': 'برچسب' });
    const perIn = h('input', { value: f.person ?? '', placeholder: 'شخص', 'aria-label': 'شخص' });
    const by = h('select', { 'aria-label': 'تاریخ مبنا' }, h('option', { value: 'event' }, 'بر پایهٔ زمان وقوع'), h('option', { value: 'created' }, 'بر پایهٔ زمان ثبت'));
    const run = () => {
        const ff = { category: catSel.value || undefined, tag: tagIn.value.trim() || undefined, person: perIn.value.trim() || undefined, by: by.value, hasAttachment: att.value === 'any' ? true : undefined, attachmentKind: att.value && att.value !== 'any' ? att.value : undefined, moodMin: moodSel.value ? +moodSel.value : undefined, moodMax: moodSel.value ? +moodSel.value : undefined };
        const fd = from.get();
        const td = to.get();
        if (fd)
            ff.from = fd;
        if (td) {
            td.setHours(23, 59, 59, 999);
            ff.to = td;
        }
        const hits = search(all, input.value, ff);
        clear(results);
        results.append(h('p', { class: 'muted small' }, `${faDigits(hits.length)} نتیجه`));
        if (!hits.length)
            results.append(h('div', { class: 'empty' }, all.length ? 'نتیجه‌ای پیدا نشد. عبارت یا فیلترها را تغییر دهید.' : 'هنوز خاطره‌ای ثبت نشده است.'));
        hits.slice(0, 100).forEach((hit) => results.append(memCard(ctx, hit.memory, hit.score ? `چرا پیدا شد: ${hit.why.join(' · ')}` + (input.value ? ` — «${snippet(hit.memory.text, input.value)}»` : '') : null)));
    };
    [input, catSel, moodSel, att, tagIn, perIn, by].forEach((e) => e.addEventListener('input', run));
    [from.el, to.el].forEach((e) => e.addEventListener('change', run));
    void applyFilters;
    run();
    return h('div', { class: 'stack' }, input, h('details', null, h('summary', null, 'فیلترهای دقیق'), h('div', { class: 'stack' }, catSel, tagIn, perIn, moodSel, att, by, from.el, to.el)), results);
};

return { moodBadge, memCard, homeView, newView, editView, detailView, searchView };
})();
__M["core/exporter.js"] = (() => {
const { MOODS } = __M["core/types.js"];
const { b64 } = __M["util/id.js"];
const { escapeHtml } = __M["util/text.js"];
const { formatGregorian, formatJalali } = __M["util/jalali.js"];
async function exportJson(a, includeFiles) {
    const memories = [];
    for (const m of [...a.memories.values()].sort((x, y) => x.eventAt.localeCompare(y.eventAt))) {
        const attachments = [];
        for (const at of m.attachments) {
            const o = { ...at };
            if (includeFiles) {
                try {
                    o.dataBase64 = b64(await a.getAttachmentBytes(at));
                }
                catch (e) {
                    o.error = String(e);
                }
            }
            attachments.push(o);
        }
        memories.push({ ...m, attachments });
    }
    const doc = { format: 'sene-export', version: 1, exportedAt: new Date().toISOString(), warning: 'این فایل رمزگذاری نشده است. با دقت نگهداری کنید.', profile: a.profile, people: [...a.people.values()], insights: [...a.insights.values()], memories };
    return new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
}
async function exportHtml(a, opts = {}) {
    const list = (opts.memories ?? [...a.memories.values()]).slice().sort((x, y) => x.eventAt.localeCompare(y.eventAt));
    const parts = [];
    for (const m of list) {
        const d = new Date(m.eventAt);
        const c = new Date(m.createdAt);
        const imgs = [];
        if (opts.embedImages)
            for (const at of m.attachments.filter((x) => x.kind === 'image' && x.size <= 1_500_000)) {
                try {
                    imgs.push(`<img alt="${escapeHtml(at.name)}" src="data:${escapeHtml(at.mime)};base64,${b64(await a.getAttachmentBytes(at))}">`);
                }
                catch { /* نادیده */ }
            }
        const rows = [['دسته', m.category], ['برچسب‌ها', m.tags.join('، ')], ['اشخاص', m.people.join('، ')], ['رویدادها', m.events.join('، ')], ['تصمیم', m.decisions], ['هدف', m.goals], ['نتیجه', m.outcomes]];
        parts.push(`<article><h2>${escapeHtml(formatJalali(d, { time: true, seconds: true, weekday: true }))} <small>(${formatGregorian(d, { time: true })})</small></h2>
<p class="meta">ثبت‌شده در ${escapeHtml(formatJalali(c, { time: true, seconds: true }))} — منطقهٔ زمانی ${escapeHtml(m.tz)}${m.mood ? ` — حال‌وهوا: ${MOODS[m.mood.score - 1].emoji} ${escapeHtml(m.mood.label)}` : ''}</p>
<div class="text">${escapeHtml(m.text).replace(/\n/g, '<br>')}</div>
<dl>${rows.filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(v)}</dd>`).join('')}</dl>
${m.attachments.length ? `<p class="meta">پیوست‌ها: ${m.attachments.map((x) => escapeHtml(x.name)).join('، ')}</p>` : ''}${imgs.join('')}</article>`);
    }
    return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(opts.title ?? 'آرشیو sene')}</title>
<style>body{font-family:Tahoma,system-ui,sans-serif;line-height:1.9;max-width:760px;margin:auto;padding:16px;color:#1b1b24}h1{font-size:1.4rem}article{border-top:1px solid #ccc;padding:12px 0;break-inside:avoid}h2{font-size:1.05rem;margin:.2rem 0}small{color:#666;font-weight:400}.meta{color:#555;font-size:.85rem;margin:.1rem 0}.text{margin:.6rem 0}dl{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:.9rem}dt{color:#555}dd{margin:0}img{max-width:100%;border-radius:6px;margin:4px 0}</style></head>
<body><h1>${escapeHtml(opts.title ?? 'آرشیو sene')}</h1><p class="meta">${list.length} خاطره — خروجی در ${escapeHtml(formatJalali(new Date(), { time: true }))}</p>${parts.join('\n')}</body></html>`;
}

return { exportJson, exportHtml };
})();
__M["ui/charts.js"] = (() => {
// نمودارهای SVG ساده — فقط از داده‌های واقعی؛ در نبود داده، حالت خالی نشان می‌دهند
const { faDigits } = __M["util/jalali.js"];
const NS = 'http://www.w3.org/2000/svg';
function s(tag, attrs = {}, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs))
        e.setAttribute(k, String(v));
    if (text !== undefined)
        e.textContent = text;
    return e;
}
function emptyChart(msg = 'هنوز دادهٔ کافی برای این نمودار ثبت نشده است') {
    const d = document.createElement('div');
    d.className = 'empty';
    d.textContent = msg;
    return d;
}
function barChart(data, o = { title: '' }) {
    if (!data.length || data.every((d) => d.value === 0))
        return emptyChart();
    const W = o.width ?? 320;
    const H = o.height ?? 170;
    const pad = 22;
    const max = o.max ?? Math.max(...data.map((d) => d.value), 1);
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': o.title });
    const bw = (W - pad * 2) / data.length;
    data.forEach((d, i) => {
        const bh = ((H - pad * 2) * d.value) / max;
        const x = W - pad - (i + 1) * bw + bw * 0.15; // راست‌چین
        svg.append(s('rect', { x, y: H - pad - bh, width: bw * 0.7, height: bh, rx: 3, class: 'bar' }));
        if (d.value)
            svg.append(s('text', { x: x + bw * 0.35, y: H - pad - bh - 3, 'text-anchor': 'middle', class: 'ct' }, faDigits(d.value % 1 ? d.value.toFixed(1) : d.value)));
        svg.append((data.length <= 8 || i % 2 === 0) ? s('text', { x: x + bw * 0.35, y: H - 6, 'text-anchor': 'middle', class: 'ct' }, d.label.length > 8 ? d.label.slice(0, 7) + '…' : d.label) : s('g'));
    });
    svg.append(s('line', { x1: pad, x2: W - pad, y1: H - pad, y2: H - pad, class: 'axis' }));
    return svg;
}
function lineChart(points, o) {
    if (points.length < 2)
        return emptyChart(points.length ? 'برای رسم نمودار دست‌کم دو ثبت لازم است' : undefined);
    const W = 320;
    const H = 180;
    const px = 26;
    const py = 22;
    const t0 = points[0].t;
    const t1 = points[points.length - 1].t || t0 + 1;
    const lo = o.min ?? Math.min(...points.map((p) => p.v));
    const hi = o.max ?? Math.max(...points.map((p) => p.v));
    const X = (t) => W - px - ((t - t0) / Math.max(1, t1 - t0)) * (W - px * 2); // زمان از راست به چپ
    const Y = (v) => H - py - ((v - lo) / Math.max(0.0001, hi - lo)) * (H - py * 2);
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': o.title });
    for (let v = Math.ceil(lo); v <= hi; v += 1) {
        svg.append(s('line', { x1: px, x2: W - px, y1: Y(v), y2: Y(v), class: 'grid' }));
        svg.append(s('text', { x: W - 6, y: Y(v) + 4, class: 'ct', 'text-anchor': 'end' }, faDigits(v)));
    }
    svg.append(s('polyline', { points: points.map((p) => `${X(p.t)},${Y(p.v)}`).join(' '), class: 'line', fill: 'none' }));
    points.forEach((p) => svg.append(s('circle', { cx: X(p.t), cy: Y(p.v), r: 3, class: 'dot' })));
    svg.append(s('text', { x: W - px, y: H - 4, class: 'ct', 'text-anchor': 'start' }, o.fmtT(t0)));
    svg.append(s('text', { x: px, y: H - 4, class: 'ct', 'text-anchor': 'end' }, o.fmtT(t1)));
    return svg;
}

return { emptyChart, barChart, lineChart };
})();
__M["ui/graph.js"] = (() => {
const { h } = __M["ui/dom.js"];
const { formatJalali } = __M["util/jalali.js"];
const KIND_LABEL = { memory: 'خاطره', person: 'شخص', event: 'رویداد', decision: 'تصمیم', goal: 'هدف' };
function buildGraph(ms) {
    const nodes = new Map();
    const edges = [];
    const node = (id, kind, label, memId) => { let n = nodes.get(id); if (!n) {
        n = { id, kind, label, memId, x: (Math.random() - 0.5) * 300, y: (Math.random() - 0.5) * 300, vx: 0, vy: 0, w: 1 };
        nodes.set(id, n);
    }
    else
        n.w += 1; return n; };
    for (const m of ms) {
        node(m.id, 'memory', m.text.slice(0, 18) || formatJalali(new Date(m.eventAt)), m.id);
        m.people.forEach((p) => { node(`p:${p}`, 'person', p); edges.push({ a: m.id, b: `p:${p}` }); });
        m.events.forEach((e) => { node(`e:${e}`, 'event', e); edges.push({ a: m.id, b: `e:${e}` }); });
        if (m.decisions) {
            node(`d:${m.id}`, 'decision', m.decisions.slice(0, 16), m.id);
            edges.push({ a: m.id, b: `d:${m.id}` });
        }
        if (m.goals) {
            node(`g:${m.id}`, 'goal', m.goals.slice(0, 16), m.id);
            edges.push({ a: m.id, b: `g:${m.id}` });
        }
        m.links.forEach((l) => { if (ms.some((x) => x.id === l))
            edges.push({ a: m.id, b: l }); });
    }
    return { nodes: [...nodes.values()], edges };
}
function layout(nodes, edges, iters = 220) {
    const idx = new Map(nodes.map((n) => [n.id, n]));
    for (let it = 0; it < iters; it += 1) {
        const cool = 1 - it / iters;
        for (let i = 0; i < nodes.length; i += 1)
            for (let j = i + 1; j < nodes.length; j += 1) {
                const a = nodes[i];
                const b = nodes[j];
                let dx = a.x - b.x;
                let dy = a.y - b.y;
                const d2 = dx * dx + dy * dy + 0.01;
                const d = Math.sqrt(d2);
                const f = 2600 / d2;
                dx /= d;
                dy /= d;
                a.vx += dx * f;
                a.vy += dy * f;
                b.vx -= dx * f;
                b.vy -= dy * f;
            }
        for (const e of edges) {
            const a = idx.get(e.a);
            const b = idx.get(e.b);
            if (!a || !b)
                continue;
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const d = Math.sqrt(dx * dx + dy * dy) || 1;
            const f = (d - 60) * 0.02;
            a.vx += (dx / d) * f;
            a.vy += (dy / d) * f;
            b.vx -= (dx / d) * f;
            b.vy -= (dy / d) * f;
        }
        for (const n of nodes) {
            n.vx -= n.x * 0.004;
            n.vy -= n.y * 0.004;
            n.x += Math.max(-12, Math.min(12, n.vx)) * cool;
            n.y += Math.max(-12, Math.min(12, n.vy)) * cool;
            n.vx *= 0.6;
            n.vy *= 0.6;
        }
    }
}
/** نمایش تعاملی: لمس گره = جزئیات، کشیدن گره = جابه‌جایی، کشیدن پس‌زمینه = حرکت، دکمه‌های +/− = بزرگ‌نمایی */
function renderGraph(ms, onSelect) {
    const { nodes, edges } = buildGraph(ms);
    if (!nodes.length)
        return h('div', { class: 'empty' }, 'خاطره‌ای برای ساخت نمودار وجود ندارد');
    layout(nodes, edges);
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'graph');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'نمودار ارتباطی');
    let vb = { x: -200, y: -200, w: 400, h: 400 };
    const setVB = () => svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
    setVB();
    const idx = new Map(nodes.map((n) => [n.id, n]));
    const lines = edges.map((e) => { const l = document.createElementNS(NS, 'line'); l.setAttribute('class', 'edge'); svg.append(l); return { e, l }; });
    const gs = nodes.map((n) => {
        const g = document.createElementNS(NS, 'g');
        g.setAttribute('class', `node ${n.kind}`);
        g.setAttribute('tabindex', '0');
        g.setAttribute('role', 'button');
        g.setAttribute('aria-label', `${KIND_LABEL[n.kind]}: ${n.label}`);
        const c = document.createElementNS(NS, 'circle');
        c.setAttribute('r', String(n.kind === 'memory' ? 7 : 6 + Math.min(6, n.w)));
        g.append(c);
        const t = document.createElementNS(NS, 'text');
        t.setAttribute('y', '-10');
        t.setAttribute('text-anchor', 'middle');
        t.textContent = n.label;
        g.append(t);
        svg.append(g);
        return { n, g };
    });
    const draw = () => {
        lines.forEach(({ e, l }) => { const a = idx.get(e.a); const b = idx.get(e.b); if (!a || !b)
            return; l.setAttribute('x1', String(a.x)); l.setAttribute('y1', String(a.y)); l.setAttribute('x2', String(b.x)); l.setAttribute('y2', String(b.y)); });
        gs.forEach(({ n, g }) => g.setAttribute('transform', `translate(${n.x} ${n.y})`));
    };
    draw();
    const pt = (ev) => { const r = svg.getBoundingClientRect(); return { x: vb.x + ((ev.clientX - r.left) / r.width) * vb.w, y: vb.y + ((ev.clientY - r.top) / r.height) * vb.h }; };
    let drag = null;
    svg.addEventListener('pointerdown', (ev) => {
        const g = ev.target.closest('g.node');
        const n = g ? gs.find((x) => x.g === g)?.n : undefined;
        drag = { n, sx: ev.clientX, sy: ev.clientY, moved: false, vb0: { ...vb } };
        svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener('pointermove', (ev) => {
        if (!drag)
            return;
        const dx = ev.clientX - drag.sx;
        const dy = ev.clientY - drag.sy;
        if (Math.abs(dx) + Math.abs(dy) > 4)
            drag.moved = true;
        if (!drag.moved)
            return;
        if (drag.n) {
            const p = pt(ev);
            drag.n.x = p.x;
            drag.n.y = p.y;
            draw();
        }
        else {
            const r = svg.getBoundingClientRect();
            vb.x = drag.vb0.x - (dx / r.width) * vb.w;
            vb.y = drag.vb0.y - (dy / r.height) * vb.h;
            setVB();
        }
    });
    svg.addEventListener('pointerup', () => { if (drag && !drag.moved && drag.n)
        onSelect(drag.n); drag = null; });
    svg.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') {
        const g = ev.target.closest('g.node');
        const n = g ? gs.find((x) => x.g === g)?.n : undefined;
        if (n)
            onSelect(n);
    } });
    const zoom = (f) => { const cx = vb.x + vb.w / 2; const cy = vb.y + vb.h / 2; vb.w *= f; vb.h *= f; vb.x = cx - vb.w / 2; vb.y = cy - vb.h / 2; setVB(); };
    return h('div', { class: 'graphwrap' }, svg, h('div', { class: 'zoom' }, h('button', { class: 'icon-btn', 'aria-label': 'بزرگ‌نمایی', onclick: () => zoom(0.75) }, '＋'), h('button', { class: 'icon-btn', 'aria-label': 'کوچک‌نمایی', onclick: () => zoom(1.33) }, '－')), h('div', { class: 'legend' }, Object.keys(KIND_LABEL).map((k) => h('span', { class: `lg ${k}` }, KIND_LABEL[k]))));
}

return { KIND_LABEL, buildGraph, layout, renderGraph };
})();
__M["ui/views/pro.js"] = (() => {
const { applyFilters } = __M["core/search.js"];
const { buildReport, countBy, findContradictions, generateInsights, monthKey, moodSeries, narrative, periodStats, reportPeriod, onThisDay } = __M["core/analysis.js"];
const { exportHtml } = __M["core/exporter.js"];
const { barChart, lineChart } = __M["ui/charts.js"];
const { renderGraph, KIND_LABEL } = __M["ui/graph.js"];
const { clear, dateField, h, openSheet, toast } = __M["ui/dom.js"];
const { dateToJalali, faDigits, formatGregorian, formatJalali, jalaliToDate, JALALI_MONTHS, jalaliMonthLength, WEEKDAYS, WEEKDAYS_SHORT, weekdayIndex, dayKey, weekdayIndex: wi } = __M["util/jalali.js"];
const { memCard } = __M["ui/views/memory.js"];
const { uid } = __M["util/id.js"];
const { platform } = __M["platform.js"];
const all = (c) => [...c.archive.memories.values()];
const sec = (t, ...k) => h('section', { class: 'card stack' }, h('h2', null, t), ...k);
const calendarView = (ctx) => {
    const ms = all(ctx);
    const today = new Date();
    let j = dateToJalali(today);
    let by = 'eventAt';
    let sel = dayKey(today);
    const wrap = h('div', { class: 'stack' });
    const draw = () => {
        clear(wrap);
        const byDay = new Map();
        ms.forEach((m) => { const k = dayKey(new Date(m[by])); byDay.set(k, [...(byDay.get(k) ?? []), m]); });
        const first = jalaliToDate(j.y, j.m, 1);
        const off = weekdayIndex(first);
        const len = jalaliMonthLength(j.y, j.m);
        const grid = h('div', { class: 'cal', role: 'grid' }, WEEKDAYS_SHORT.map((d, i) => h('div', { class: 'wd', title: WEEKDAYS[i] }, d)), Array.from({ length: off }, () => h('div')));
        for (let d = 1; d <= len; d += 1) {
            const dt = jalaliToDate(j.y, j.m, d);
            const k = dayKey(dt);
            const n = byDay.get(k)?.length ?? 0;
            grid.append(h('button', { type: 'button', class: `day ${k === sel ? 'sel' : ''} ${k === dayKey(today) ? 'today' : ''}`, 'aria-label': `${formatJalali(dt)}${n ? `، ${n} خاطره` : ''}`, onclick: () => { sel = k; draw(); } }, h('b', null, faDigits(d)), ctx.settings.showGregorian && h('small', null, String(dt.getDate())), n ? h('i', { class: 'dotc' }, faDigits(n)) : null));
        }
        const step = (n) => { let m = j.m + n; let y = j.y; if (m > 12) {
            m = 1;
            y += 1;
        } if (m < 1) {
            m = 12;
            y -= 1;
        } j = { y, m, d: 1 }; draw(); };
        wrap.append(h('div', { class: 'row between' }, h('button', { class: 'icon-btn', 'aria-label': 'ماه بعد', onclick: () => step(1) }, '›'), h('h2', null, `${JALALI_MONTHS[j.m - 1]} ${faDigits(j.y)}`), h('button', { class: 'icon-btn', 'aria-label': 'ماه قبل', onclick: () => step(-1) }, '‹')), h('div', { class: 'row between' }, h('select', { 'aria-label': 'مبنا', onchange: (e) => { by = e.target.value; draw(); } }, h('option', { value: 'eventAt', selected: by === 'eventAt' }, 'زمان وقوع'), h('option', { value: 'createdAt', selected: by === 'createdAt' }, 'زمان ثبت')), h('button', { class: 'btn small', onclick: () => { j = dateToJalali(today); sel = dayKey(today); draw(); } }, 'امروز')), grid);
        const list = byDay.get(sel) ?? [];
        wrap.append(h('h3', null, `خاطره‌های ${sel}`), list.length ? list.map((m) => memCard(ctx, m)) : h('div', { class: 'empty' }, 'در این روز خاطره‌ای نیست'));
    };
    draw();
    return wrap;
};
const timelineView = (ctx) => {
    const wrap = h('div', { class: 'stack' });
    const list = h('div', { class: 'stack' });
    const cat = h('select', { 'aria-label': 'دسته' }, h('option', { value: '' }, 'همهٔ دسته‌ها'), ctx.categories().map((c) => h('option', { value: c }, c)));
    const tag = h('input', { placeholder: 'برچسب', 'aria-label': 'برچسب' });
    const from = dateField({ value: null, optional: true, label: 'از' });
    const to = dateField({ value: null, optional: true, label: 'تا' });
    let limit = 40;
    const draw = () => {
        clear(list);
        const f = from.get();
        const t = to.get();
        if (t)
            t.setHours(23, 59, 59, 999);
        const ms = applyFilters(all(ctx), { category: cat.value || undefined, tag: tag.value.trim() || undefined, from: f ?? undefined, to: t ?? undefined }).sort((a, b) => b.eventAt.localeCompare(a.eventAt));
        if (!ms.length) {
            list.append(h('div', { class: 'empty' }, 'خاطره‌ای با این فیلترها نیست'));
            return;
        }
        let last = '';
        ms.slice(0, limit).forEach((m) => { const k = monthKey(new Date(m.eventAt)); if (k !== last) {
            last = k;
            const jd = dateToJalali(new Date(m.eventAt));
            list.append(h('h3', { class: 'stick' }, `${JALALI_MONTHS[jd.m - 1]} ${faDigits(jd.y)}`));
        } list.append(memCard(ctx, m)); });
        if (ms.length > limit)
            list.append(h('button', { class: 'btn', onclick: () => { limit += 40; draw(); } }, `نمایش بیشتر (${faDigits(ms.length - limit)} مورد دیگر)`));
    };
    [cat, tag].forEach((e) => e.addEventListener('input', draw));
    [from.el, to.el].forEach((e) => e.addEventListener('change', draw));
    wrap.append(h('details', null, h('summary', null, 'فیلترها'), h('div', { class: 'stack' }, cat, tag, from.el, to.el)), list);
    draw();
    return wrap;
};
const dashboardView = (ctx) => {
    const ms = all(ctx);
    const now = new Date();
    const jn = dateToJalali(now);
    const thisMonth = ms.filter((m) => monthKey(new Date(m.eventAt)) === `${jn.y}/${String(jn.m).padStart(2, '0')}`).length;
    const moods = ms.filter((m) => m.mood).map((m) => m.mood.score);
    const avg = moods.length ? moods.reduce((a, b) => a + b, 0) / moods.length : null;
    const stat = (v, l) => h('div', { class: 'stat' }, h('b', null, v), h('small', null, l));
    const months = new Map();
    for (let i = 11; i >= 0; i -= 1) {
        let m = jn.m - i;
        let y = jn.y;
        while (m < 1) {
            m += 12;
            y -= 1;
        }
        months.set(`${y}/${String(m).padStart(2, '0')}`, 0);
    }
    ms.forEach((m) => { const k = monthKey(new Date(m.eventAt)); if (months.has(k))
        months.set(k, months.get(k) + 1); });
    const wd = WEEKDAYS.map((l, i) => ({ label: l.slice(0, 4), value: ms.filter((m) => wi(new Date(m.eventAt)) === i).length }));
    const otd = onThisDay(ms);
    return h('div', { class: 'stack' }, h('div', { class: 'stats' }, stat(faDigits(ms.length), 'کل خاطره‌ها'), stat(faDigits(thisMonth), 'این ماه'), stat(avg ? faDigits(avg.toFixed(1)) : '—', 'میانگین حال‌وهوا'), stat(faDigits(ms.reduce((a, m) => a + m.attachments.length, 0)), 'پیوست‌ها')), sec('حال‌وهوای ثبت‌شده در طول زمان', lineChart(moodSeries(ms), { title: 'نمودار حال‌وهوا', min: 1, max: 5, fmtT: (t) => formatJalali(new Date(t)) })), sec('خاطره‌ها در ۱۲ ماه اخیر', barChart([...months].map(([k, v]) => ({ label: JALALI_MONTHS[+k.split('/')[1] - 1], value: v })), { title: 'خاطره در ماه' })), sec('بر اساس دسته', barChart(countBy(ms, (m) => m.category).slice(0, 8).map(([l, v]) => ({ label: l, value: v })), { title: 'دسته‌ها' })), sec('بر اساس روز هفته', barChart(wd, { title: 'روز هفته' })), sec('پرتکرارترین‌ها', h('p', null, h('b', null, 'برچسب‌ها: '), countBy(ms, (m) => m.tags).slice(0, 8).map(([t, c]) => `${t} (${faDigits(c)})`).join('، ') || '—'), h('p', null, h('b', null, 'اشخاص: '), countBy(ms, (m) => m.people).slice(0, 8).map(([t, c]) => `${t} (${faDigits(c)})`).join('، ') || '—')), otd.length ? sec('در چنین روزی', otd.slice(0, 3).map((m) => memCard(ctx, m))) : null);
};
const graphView = (ctx) => {
    const wrap = h('div', { class: 'stack' });
    const info = h('div', { class: 'card' }, 'روی یک گره بزنید.');
    const ms = all(ctx).sort((a, b) => b.eventAt.localeCompare(a.eventAt)).slice(0, 120);
    const g = renderGraph(ms, (n) => { clear(info); info.append(h('b', null, `${KIND_LABEL[n.kind]}: `), n.label, n.memId ? h('div', null, h('a', { class: 'btn small', href: `#/m/${n.memId}` }, 'باز کردن خاطره')) : n.kind === 'person' ? h('div', null, h('a', { class: 'btn small', href: `#/search?person=${encodeURIComponent(n.label)}` }, 'خاطره‌های این شخص')) : null); });
    wrap.append(h('p', { class: 'muted small' }, `ارتباط‌ها از اشخاص، رویدادها، تصمیم‌ها، اهداف و پیوندهای ثبت‌شده ساخته می‌شوند (حداکثر ${faDigits(120)} خاطرهٔ اخیر).`), g, info);
    return wrap;
};
const reportsView = (ctx) => {
    const wrap = h('div', { class: 'stack' });
    const out = h('div', { class: 'stack' });
    let current = null;
    const show = (r) => {
        current = r;
        clear(out);
        const s = r.stats;
        out.append(h('h2', null, r.title), h('p', { class: 'muted small' }, `از ${formatJalali(r.from)} تا ${formatJalali(r.to)}`), h('div', { class: 'stats' }, h('div', { class: 'stat' }, h('b', null, faDigits(s.count)), h('small', null, 'خاطره')), h('div', { class: 'stat' }, h('b', null, s.avgMood ? faDigits(s.avgMood.toFixed(1)) : '—'), h('small', null, 'میانگین حال‌وهوا')), h('div', { class: 'stat' }, h('b', null, faDigits(s.decisions)), h('small', null, 'تصمیم (' + faDigits(s.withOutcome) + ' دارای نتیجه)'))), s.count ? [h('p', null, h('b', null, 'دسته‌ها: '), s.categories.map(([k, v]) => `${k} (${faDigits(v)})`).join('، ')), h('p', null, h('b', null, 'برچسب‌ها: '), s.tags.map(([k, v]) => `${k} (${faDigits(v)})`).join('، ') || '—'), h('p', null, h('b', null, 'اشخاص: '), s.people.map(([k, v]) => `${k} (${faDigits(v)})`).join('، ') || '—'), barChart(s.categories.slice(0, 8).map(([l, v]) => ({ label: l, value: v })), { title: 'دسته‌ها' }), h('h3', null, 'روایت زمانی (از خاطره‌های واقعی)'), h('pre', { class: 'narr' }, narrative(r.memories)), r.memories.map((m) => memCard(ctx, m)),
            h('div', { class: 'row wrap' }, h('button', { class: 'btn', onclick: async () => platform.saveFile(new Blob([await exportHtml(ctx.archive, { memories: r.memories, title: r.title, embedImages: true })], { type: 'text/html' }), `sene-report-${Date.now()}.html`) }, 'ذخیرهٔ گزارش (HTML)'), h('button', { class: 'btn', onclick: () => printHtml(exportHtml(ctx.archive, { memories: r.memories, title: r.title })) }, 'چاپ / PDF'))] : h('div', { class: 'empty' }, 'در این بازه خاطره‌ای نیست'));
    };
    const mk = (k, l) => h('button', { class: 'btn small', onclick: () => show(buildReport(all(ctx), reportPeriod(k))) }, l);
    const from = dateField({ value: new Date(Date.now() - 30 * 86400000), label: 'از' });
    const to = dateField({ value: new Date(), label: 'تا' });
    const topic = h('input', { placeholder: 'موضوع (اختیاری، مثلاً «کار»)', 'aria-label': 'موضوع' });
    wrap.append(h('div', { class: 'row wrap' }, mk('day', 'امروز'), mk('week', 'هفته'), mk('month', 'ماه'), mk('year', 'سال')), h('details', null, h('summary', null, 'بازهٔ دلخواه / گزارش موضوعی'), h('div', { class: 'stack' }, from.el, to.el, topic, h('button', { class: 'btn primary', onclick: () => { const f = from.get(); const t = to.get(); if (!f || !t) {
            toast('تاریخ‌ها معتبر نیست', 'err');
            return;
        } t.setHours(23, 59, 59, 999); show(buildReport(all(ctx), { from: f, to: t, topic: topic.value || undefined, title: topic.value ? `گزارش موضوعی «${topic.value}»` : 'گزارش بازهٔ دلخواه' })); } }, 'ساخت گزارش'))), out);
    show(buildReport(all(ctx), reportPeriod('month')));
    void current;
    return wrap;
};
async function printHtml(p) {
    const html = await p;
    const f = h('iframe', { style: { position: 'fixed', width: '0', height: '0', border: '0' } });
    document.body.append(f);
    f.srcdoc = html;
    f.onload = () => { f.contentWindow?.focus(); f.contentWindow?.print(); setTimeout(() => f.remove(), 60000); };
}
const insightsView = (ctx) => {
    const A = ctx.archive;
    const wrap = h('div', { class: 'stack' });
    const draw = () => {
        clear(wrap);
        wrap.append(h('p', { class: 'muted small' }, 'برداشت‌ها با قواعد آماری ساده و به‌صورت محلی ساخته می‌شوند. اینها «برداشت» هستند، نه واقعیتِ ثبت‌شده؛ هم‌زمانی را علت قطعی نمی‌گیرند و هر مورد را می‌توانید تأیید، رد یا اصلاح کنید. برداشت ردشده دوباره پیشنهاد نمی‌شود.'));
        wrap.append(h('button', { class: 'btn primary', onclick: async () => {
                const known = new Set([...A.insights.values()].map((i) => i.signature));
                const ms = all(ctx);
                const drafts = [...generateInsights(ms), ...findContradictions(ms)].filter((d) => !known.has(d.signature));
                for (const d of drafts)
                    await A.saveInsight({ ...d, id: `insight:${uid()}`, createdAt: new Date().toISOString(), status: 'pending' });
                toast(drafts.length ? `${faDigits(drafts.length)} برداشت تازه` : 'برداشت تازه‌ای پیدا نشد (ممکن است داده کافی نباشد)', drafts.length ? 'ok' : 'warn');
                draw();
            } }, 'تحلیل آرشیو'));
        const by = (st) => [...A.insights.values()].filter((i) => st.includes(i.status)).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const card = (i) => h('div', { class: 'card stack' }, h('span', { class: 'tag' }, { pattern: 'الگو', contradiction: 'تناقض احتمالی', change: 'تغییر', link: 'ارتباط', suggestion: 'پیشنهاد' }[i.kind] + ' · ' + (i.source === 'rule-based' ? 'قاعده‌محور' : 'مدل خارجی')), h('p', null, i.corrected ?? i.text), i.corrected && h('p', { class: 'muted small' }, 'متن اولیه: ' + i.text), h('div', null, h('span', { class: 'muted small' }, 'شواهد:'), i.evidence.map((e) => h('a', { class: 'chip block', href: `#/m/${e.id}` }, `${formatJalali(new Date(e.date))}: ${e.snippet}`))), i.status === 'pending' || i.status === 'accepted' || i.status === 'corrected' ? h('div', { class: 'row wrap' }, i.status === 'pending' && h('button', { class: 'btn small', onclick: async () => { await A.saveInsight({ ...i, status: 'accepted' }); draw(); } }, 'تأیید'), h('button', { class: 'btn small', onclick: () => { const t = h('textarea', { rows: '3', value: i.corrected ?? i.text }); const s = openSheet('اصلاح برداشت', h('div', { class: 'stack' }, t, h('button', { class: 'btn primary', onclick: async () => { await A.saveInsight({ ...i, status: 'corrected', corrected: t.value.trim() }); s.close(); draw(); } }, 'ذخیره'))); } }, 'اصلاح'), h('button', { class: 'btn small danger', onclick: async () => { await A.saveInsight({ ...i, status: 'rejected' }); draw(); } }, 'رد')) : null);
        const pend = by(['pending']);
        const acc = by(['accepted', 'corrected']);
        wrap.append(h('h2', null, 'در انتظار بررسی'), pend.length ? pend.map(card) : h('div', { class: 'empty' }, 'برداشتی در انتظار نیست'), acc.length ? [h('h2', null, 'تأیید/اصلاح‌شده'), acc.map(card)] : null);
        const rej = by(['rejected']);
        if (rej.length)
            wrap.append(h('p', { class: 'muted small' }, `${faDigits(rej.length)} برداشت ردشده نگه‌داری می‌شود تا دوباره پیشنهاد نشود و هرگز به‌عنوان واقعیت استفاده نمی‌شود.`));
    };
    draw();
    return wrap;
};
const compareView = (ctx) => {
    const wrap = h('div', { class: 'stack' });
    const out = h('div', { class: 'stack' });
    const a1 = dateField({ value: new Date(Date.now() - 60 * 86400000), label: 'دورهٔ اول: از' });
    const a2 = dateField({ value: new Date(Date.now() - 31 * 86400000), label: 'تا' });
    const b1 = dateField({ value: new Date(Date.now() - 30 * 86400000), label: 'دورهٔ دوم: از' });
    const b2 = dateField({ value: new Date(), label: 'تا' });
    const go = () => {
        const d = [a1, a2, b1, b2].map((x) => x.get());
        if (d.some((x) => !x)) {
            toast('تاریخ‌ها معتبر نیست', 'err');
            return;
        }
        d[1].setHours(23, 59, 59, 999);
        d[3].setHours(23, 59, 59, 999);
        const A = periodStats(all(ctx), d[0], d[1]);
        const B = periodStats(all(ctx), d[2], d[3]);
        const row = (l, x, y) => h('tr', null, h('th', null, l), h('td', null, x), h('td', null, y));
        clear(out);
        out.append(h('table', { class: 'tbl' }, h('thead', null, h('tr', null, h('th'), h('th', null, 'دورهٔ اول'), h('th', null, 'دورهٔ دوم'))), h('tbody', null, row('تعداد خاطره', faDigits(A.count), faDigits(B.count)), row('میانگین حال‌وهوا', A.avgMood ? faDigits(A.avgMood.toFixed(1)) : '—', B.avgMood ? faDigits(B.avgMood.toFixed(1)) : '—'), row('تصمیم‌ها', faDigits(A.decisions), faDigits(B.decisions)), row('دسته‌های برتر', A.categories.slice(0, 3).map((x) => x[0]).join('، ') || '—', B.categories.slice(0, 3).map((x) => x[0]).join('، ') || '—'), row('برچسب‌های برتر', A.tags.slice(0, 3).map((x) => x[0]).join('، ') || '—', B.tags.slice(0, 3).map((x) => x[0]).join('، ') || '—'), row('اشخاص برتر', A.people.slice(0, 3).map((x) => x[0]).join('، ') || '—', B.people.slice(0, 3).map((x) => x[0]).join('، ') || '—'))), h('p', { class: 'muted small' }, 'این مقایسه فقط شمارش و میانگین داده‌های ثبت‌شده است و دلیل تفاوت‌ها را نشان نمی‌دهد.'));
    };
    wrap.append(a1.el, a2.el, b1.el, b2.el, h('button', { class: 'btn primary', onclick: go }, 'مقایسه'), out);
    void formatGregorian;
    return wrap;
};

return { calendarView, timelineView, dashboardView, graphView, reportsView, printHtml, insightsView, compareView };
})();
__M["ui/views/more.js"] = (() => {
const { search } = __M["core/search.js"];
const { askExternal, buildPrompt, aiHost } = __M["core/ai.js"];
const { clear, confirmBox, h, openSheet, toast } = __M["ui/dom.js"];
const { faDigits, formatJalali } = __M["util/jalali.js"];
const { countBy } = __M["core/analysis.js"];
const { memCard } = __M["ui/views/memory.js"];
const { onThisDay } = __M["core/analysis.js"];
const moreView = (ctx) => {
    const pro = ctx.settings.mode === 'pro';
    const item = (href, ic, t, d) => h('a', { class: 'card link', href: `#/${href}` }, h('span', { class: 'ic' }, ic), h('div', null, h('b', null, t), h('small', { class: 'muted' }, d)));
    return h('div', { class: 'stack' }, h('div', { class: 'seg' }, h('button', { class: ctx.settings.mode === 'simple' ? 'on' : '', onclick: async () => { await ctx.setSettings({ mode: 'simple' }); ctx.rerender(); } }, 'حالت ساده'), h('button', { class: pro ? 'on' : '', onclick: async () => { await ctx.setSettings({ mode: 'pro' }); ctx.rerender(); } }, 'حالت حرفه‌ای')), item('timeline', '🕰', 'خط زمانی', 'مرور خاطره‌ها به ترتیب زمان'), item('chat', '💬', 'گفت‌وگو با آرشیو', 'پرسش دربارهٔ گذشته؛ پاسخ از خاطره‌های واقعی'), item('profile', '🧭', 'پروفایل من', 'علایق، اهداف، ارزش‌ها و عادت‌ها'), item('people', '👥', 'اشخاص', 'تاریخچهٔ ارتباط با هر شخص'), pro && [item('dashboard', '📊', 'داشبورد تحلیلی', 'نمودارها و آمار'), item('graph', '🕸', 'نمودار ارتباطی', 'ارتباط خاطره‌ها، اشخاص، رویدادها'), item('reports', '📑', 'گزارش‌ها', 'روزانه تا سالانه، دلخواه و موضوعی'), item('insights', '🔍', 'برداشت‌ها', 'الگوها و تناقض‌های احتمالی'), item('compare', '⚖️', 'مقایسهٔ دوره‌ها', 'دو بازهٔ زندگی کنار هم')], item('settings', '⚙️', 'تنظیمات', 'ظاهر، امنیت، Drive، پشتیبان، یادآور'));
};
const FIELDS = [['interests', 'علایق'], ['goals', 'اهداف'], ['values', 'ارزش‌ها'], ['habits', 'عادت‌ها'], ['preferences', 'ترجیحات'], ['confirmed', 'اطلاعات تأییدشده توسط خودم']];
const profileView = (ctx) => {
    const A = ctx.archive;
    const inputs = new Map();
    const w = h('div', { class: 'stack' }, h('p', { class: 'muted small' }, 'هر مورد را در یک خط بنویسید. این بخش فقط چیزهایی است که خودتان وارد و تأیید می‌کنید.'));
    FIELDS.forEach(([k, l]) => { const t = h('textarea', { rows: '3', value: A.profile[k].join('\n'), 'aria-label': l }); inputs.set(k, t); w.append(h('label', null, l, t)); });
    const notes = h('textarea', { rows: '3', value: A.profile.notes, 'aria-label': 'یادداشت' });
    w.append(h('label', null, 'یادداشت آزاد', notes));
    w.append(h('button', { class: 'btn primary', onclick: async () => { const p = { ...A.profile, notes: notes.value }; inputs.forEach((t, k) => { p[k] = t.value.split('\n').map((x) => x.trim()).filter(Boolean); }); await A.saveProfile(p); toast('ذخیره شد'); } }, 'ذخیرهٔ پروفایل'));
    const inferred = [...A.insights.values()].filter((i) => i.status === 'accepted' || i.status === 'corrected');
    w.append(h('section', { class: 'card stack' }, h('h2', null, 'برداشت‌های پذیرفته‌شده (استنباط‌شده، جدا از اطلاعات من)'), inferred.length ? inferred.map((i) => h('p', null, '• ' + (i.corrected ?? i.text))) : h('p', { class: 'muted' }, 'هنوز برداشتی تأیید نشده است.')));
    return w;
};
const peopleView = (ctx) => {
    const A = ctx.archive;
    const ms = [...A.memories.values()];
    const names = countBy(ms, (m) => m.people);
    if (!names.length)
        return h('div', { class: 'empty' }, 'هنوز نام شخصی در خاطره‌ها ثبت نشده است.');
    const profOf = (n) => [...A.people.values()].find((p) => p.name === n);
    return h('div', { class: 'stack' }, names.map(([n, c]) => {
        const mine = ms.filter((m) => m.people.includes(n)).sort((a, b) => a.eventAt.localeCompare(b.eventAt));
        const p = profOf(n);
        return h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('b', null, '👤 ' + n), h('small', { class: 'muted' }, `${faDigits(c)} خاطره`)), p?.relation && h('p', null, 'نسبت: ' + p.relation), p?.notes && h('p', { class: 'muted' }, p.notes), h('p', { class: 'small muted' }, `اولین ذکر: ${formatJalali(new Date(mine[0].eventAt))} · آخرین: ${formatJalali(new Date(mine[mine.length - 1].eventAt))}`), h('div', { class: 'row wrap' }, h('a', { class: 'btn small', href: `#/search?person=${encodeURIComponent(n)}` }, 'تاریخچهٔ ارتباط'), h('button', { class: 'btn small', onclick: () => {
                const rel = h('input', { value: p?.relation ?? '', placeholder: 'نسبت (دوست، همکار، …)' });
                const nt = h('textarea', { rows: '3', value: p?.notes ?? '', placeholder: 'یادداشت' });
                const s = openSheet(`پروفایل ${n}`, h('div', { class: 'stack' }, rel, nt, h('button', { class: 'btn primary', onclick: async () => { await A.savePerson({ id: p?.id, name: n, relation: rel.value, notes: nt.value, since: p?.since ?? mine[0].eventAt }); s.close(); ctx.rerender(); } }, 'ذخیره')));
            } }, 'ویرایش پروفایل')));
    }));
};
const chatView = (ctx) => {
    const A = ctx.archive;
    const log = h('div', { class: 'stack' });
    const q = h('input', { placeholder: 'مثلاً: «چه زمانی دربارهٔ سفر نوشتم؟»', 'aria-label': 'پرسش' });
    const hasAi = ctx.settings.online.externalAi && ctx.settings.ai.endpoint && ctx.settings.ai.model;
    const ask = async () => {
        const text = q.value.trim();
        if (!text)
            return;
        q.value = '';
        const all = [...A.memories.values()];
        log.prepend(h('div', { class: 'card q' }, text));
        const ans = h('div', { class: 'card stack' });
        log.children[0].after(ans);
        if (/چند.*خاطره|تعداد.*خاطره/.test(text)) {
            ans.append(h('p', null, `${faDigits(all.length)} خاطره در آرشیو ثبت شده است.`));
            return;
        }
        if (/چنین روز/.test(text)) {
            const o = onThisDay(all);
            ans.append(h('p', null, o.length ? `${faDigits(o.length)} خاطره در چنین روزی (سال‌های دیگر):` : 'برای چنین روزی خاطره‌ای ثبت نشده است.'), o.map((m) => memCard(ctx, m)));
            return;
        }
        const hits = search(all, text).slice(0, 5);
        ans.append(h('p', { class: 'muted small' }, 'پاسخ بازیابی‌محور است: مرتبط‌ترین خاطره‌های واقعی نشان داده می‌شود، نه متنی که ساخته شده باشد.'), hits.length ? hits.map((x) => memCard(ctx, x.memory, 'چرا: ' + x.why.join(' · '))) : h('p', null, 'در آرشیو چیزی مرتبط پیدا نشد.'));
        if (hasAi && hits.length)
            ans.append(h('button', { class: 'btn small', onclick: async () => {
                    const { messages, preview } = buildPrompt(text, hits.map((x) => x.memory));
                    const ok = await confirmBox(`متن زیر به «${aiHost(ctx.settings.ai)}» ارسال می‌شود. ادامه می‌دهید؟`, { confirmText: 'ارسال', detail: preview.slice(0, 1500) + (preview.length > 1500 ? '…' : '') });
                    if (!ok)
                        return;
                    try {
                        const key = (await A.getSecret()).aiKey;
                        const r = await askExternal({ ...ctx.settings.ai, apiKey: key }, messages);
                        ans.append(h('div', { class: 'card note' }, h('b', null, 'پاسخ مدل خارجی (برداشت، نه واقعیت ثبت‌شده): '), h('p', null, r)));
                    }
                    catch (e) {
                        toast(e.message, 'err', 6000);
                    }
                } }, 'پرسیدن از مدل خارجی (با تأیید)'));
    };
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter')
        void ask(); });
    void clear;
    return h('div', { class: 'stack' }, h('div', { class: 'row' }, q, h('button', { class: 'btn primary', onclick: ask }, 'بپرس')), log, !hasAi && h('p', { class: 'muted small' }, 'مدل هوش مصنوعی خارجی خاموش است؛ جست‌وجوی محلی کار می‌کند. در تنظیمات می‌توانید یک سرویس اختیاری را با رضایت خودتان فعال کنید.'));
};

return { moreView, profileView, peopleView, chatView };
})();
__M["ui/views/settings.js"] = (() => {
const { createBackup, restoreBackup, verifyBackup } = __M["core/backup.js"];
const { exportHtml, exportJson } = __M["core/exporter.js"];
const { SLOTS, buildIcs } = __M["core/reminders.js"];
const { splitKey } = __M["sync/engine.js"];
const { askExternal, aiHost, GEMINI_DEFAULT_MODEL } = __M["core/ai.js"];
const { clear, confirmBox, fmtBytes, h, promptBox, toast } = __M["ui/dom.js"];
const { faDigits, formatJalali } = __M["util/jalali.js"];
const { platform } = __M["platform.js"];
const { printHtml } = __M["ui/views/pro.js"];
const settingsView = (ctx, _a, q) => {
    const open = q.get('s');
    const S = (id, title, ...body) => h('details', { class: 'card', open: open === id }, h('summary', null, title), h('div', { class: 'stack' }, ...body));
    const sel = (label, val, opts, on) => h('label', null, label, h('select', { onchange: (e) => on(e.target.value) }, opts.map(([v, l]) => h('option', { value: v, selected: v === val }, l))));
    const set = async (p) => { await ctx.setSettings(p); };
    const w = h('div', { class: 'stack' });
    // ----- ظاهر -----
    const s = ctx.settings;
    w.append(S('look', 'ظاهر و نمایش', sel('حالت برنامه', s.mode, [['simple', 'ساده'], ['pro', 'حرفه‌ای']], (v) => set({ mode: v })), sel('پوسته', s.theme, [['auto', 'خودکار (مطابق گوشی)'], ['light', 'روشن'], ['dark', 'تاریک']], (v) => set({ theme: v })), sel('رنگ‌بندی', s.accent, [['indigo', 'نیلی'], ['teal', 'فیروزه‌ای'], ['rose', 'گلی'], ['amber', 'کهربایی'], ['forest', 'سبز جنگلی']], (v) => set({ accent: v })), sel('فونت (از فونت‌های موجود روی دستگاه)', s.font, [['system', 'پیش‌فرض سیستم'], ['tahoma', 'Tahoma'], ['serif', 'نسخ / سریف'], ['mono', 'مونو']], (v) => set({ font: v })), h('label', null, `اندازهٔ متن: ${faDigits(s.fontSize)}٪`, h('input', { type: 'range', min: '80', max: '160', step: '5', value: s.fontSize, oninput: (e) => set({ fontSize: +e.target.value }) })), h('label', null, 'فاصلهٔ خطوط', h('input', { type: 'range', min: '1.3', max: '2.4', step: '0.1', value: s.lineHeight, oninput: (e) => set({ lineHeight: +e.target.value }) })), h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.showGregorian, onchange: (e) => set({ showGregorian: e.target.checked }) }), h('span', null, 'نمایش تاریخ میلادی کنار شمسی')), h('label', null, 'دستهٔ سفارشی جدید', h('div', { class: 'row' }, (() => { const i = h('input', { placeholder: 'نام دسته' }); return [i, h('button', { class: 'btn', onclick: async () => { const v = i.value.trim(); if (v && !ctx.categories().includes(v)) {
                await set({ customCategories: [...s.customCategories, v] });
                toast('دسته افزوده شد');
                i.value = '';
            } } }, 'افزودن')]; })()))));
    // ----- امنیت -----
    w.append(S('security', 'امنیت و قفل', sel('قفل خودکار پس از بی‌فعالیتی', String(s.lockMinutes), [['0', 'خاموش'], ['1', '۱ دقیقه'], ['2', '۲ دقیقه'], ['5', '۵ دقیقه'], ['15', '۱۵ دقیقه'], ['30', '۳۰ دقیقه']], (v) => set({ lockMinutes: +v })), h('button', { class: 'btn', onclick: () => ctx.lock() }, 'قفل کردن همین حالا'), h('p', { class: 'muted small' }, 'رمز اصلی در هیچ‌جا ذخیره نمی‌شود؛ کلید فقط هنگام باز بودن برنامه در حافظه می‌ماند. اثر انگشت در نسخهٔ وب پشتیبانی نمی‌شود (در نسخهٔ اندروید با افزونهٔ Capacitor اضافه می‌شود). تغییر رمز در نسخهٔ ۱ وجود ندارد؛ راه‌حل: پشتیبان بگیرید، در نصب تازه با رمز جدید بازیابی کنید.')));
    // ----- Drive -----
    const sy = ctx.sync;
    const clientId = h('input', { value: s.driveClientId, placeholder: 'xxxx.apps.googleusercontent.com', 'aria-label': 'Client ID' });
    const folder = h('input', { value: s.driveFolderName, 'aria-label': 'نام پوشه' });
    const conf = h('div', { class: 'stack' });
    void ctx.engine().conflicts().then((cs) => cs.forEach((c) => {
        const [, id] = splitKey(c.key);
        const m = ctx.archive.memories.get(id);
        conf.append(h('div', { class: 'card stack' }, h('b', null, { 'both-changed': 'هر دو نسخه تغییر کرده‌اند', 'local-deleted': 'اینجا حذف شده ولی روی Drive ویرایش شده', 'remote-deleted': 'روی Drive حذف شده ولی اینجا ویرایش شده' }[c.kind]), m && h('p', { class: 'small' }, m.text.slice(0, 120)), h('div', { class: 'row wrap' }, h('button', { class: 'btn small', onclick: async () => { await ctx.engine().resolve(c.key, 'local'); ctx.rerender(); } }, c.kind === 'local-deleted' ? 'حذف نهایی' : 'نگه‌داشتن نسخهٔ این دستگاه'), h('button', { class: 'btn small', onclick: async () => { await ctx.engine().resolve(c.key, 'remote'); ctx.rerender(); } }, c.kind === 'local-deleted' ? 'برگرداندن از Drive' : 'پذیرفتن نسخهٔ Drive'), c.kind === 'both-changed' && c.store === 'mem' && h('button', { class: 'btn small', onclick: async () => { await ctx.engine().resolve(c.key, 'both'); ctx.rerender(); } }, 'نگه‌داشتن هر دو'))));
    }));
    w.append(S('sync', 'همگام‌سازی Google Drive', h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.online.drive, onchange: (e) => set({ online: { ...s.online, drive: e.target.checked } }).then(() => ctx.rerender()) }), h('span', null, 'فعال‌سازی Drive (پیش‌فرض خاموش؛ فقط دادهٔ رمزگذاری‌شده ارسال می‌شود)')), h('label', null, 'Client ID (OAuth)', clientId), h('label', null, 'نام پوشهٔ مقصد در Drive', folder), h('p', { class: 'muted small' }, 'با دسترسی کمینهٔ drive.file فقط به پوشه و فایل‌هایی که خود sene ساخته دسترسی دارد. برای انتخاب پوشهٔ دیگر، نام جدید بنویسید تا پوشهٔ جدید ساخته شود.'), h('div', { class: 'row wrap' }, h('button', { class: 'btn', onclick: async () => { await set({ driveClientId: clientId.value.trim(), driveFolderName: folder.value.trim() || 'sene', driveFolderId: folder.value.trim() !== s.driveFolderName ? '' : s.driveFolderId }); toast('تنظیمات ذخیره شد'); } }, 'ذخیره'), h('button', { class: 'btn primary', onclick: async () => { await set({ driveClientId: clientId.value.trim(), online: { ...s.online, drive: true } }); await ctx.runSync(true); } }, 'اتصال و همگام‌سازی'), h('button', { class: 'btn', onclick: () => { ctx.auth.signOut(); toast('از Google خارج شدید؛ داده‌های محلی حفظ شد'); } }, 'قطع اتصال')), h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.autoSync, onchange: (e) => set({ autoSync: e.target.checked }) }), h('span', null, 'همگام‌سازی خودکار پس از هر تغییر')), h('p', null, `وضعیت: ${{ disabled: 'خاموش', idle: 'آماده', running: 'در حال اجرا', offline: 'آفلاین', error: 'خطا', 'needs-auth': 'نیاز به ورود' }[sy.state]}`, sy.error ? ` — ${sy.error}` : ''), h('p', { class: 'small muted' }, `عملیات در صف: ${faDigits(sy.pending)} · آخرین همگام‌سازی: ${sy.last ? formatJalali(new Date(sy.last), { time: true, seconds: true }) : 'هرگز'}`), h('p', { class: 'muted small' }, 'حذف: مورد از آرشیو محلی پاک می‌شود و فایل‌اش از پوشهٔ Drive حذف می‌شود (تنها یک نشانهٔ حذفِ بدون محتوا می‌ماند تا حذف روی دستگاه‌های دیگر هم اعمال شود). پشتیبان‌های مستقل و نسخه‌های قدیمی Google Drive خودکار تغییر نمی‌کنند و پاک‌شدن کامل ابری تضمین نمی‌شود.'), conf));
    // ----- پشتیبان -----
    const lastB = h('p', { class: 'small muted' }, '');
    void ctx.kv.get('meta', 'lastBackup').then((v) => { lastB.textContent = v ? `آخرین پشتیبان: ${formatJalali(new Date(v), { time: true })}` : 'هنوز پشتیبانی گرفته نشده است.'; });
    const fileIn = h('input', { type: 'file', accept: '.sene-backup,application/octet-stream' });
    fileIn.addEventListener('change', async () => {
        const f = fileIn.files?.[0];
        if (!f)
            return;
        fileIn.value = '';
        const v = await verifyBackup(f);
        if (!v.ok) {
            toast(`فایل پشتیبان معتبر نیست: ${v.problems.join('؛ ')}`, 'err', 8000);
            return;
        }
        const pw = await promptBox('رمز اصلیِ همان پشتیبان', { password: true, hint: `${faDigits(v.counts.mem)} خاطره و ${faDigits(v.counts.blob)} پیوست؛ ساخته‌شده در ${formatJalali(new Date(v.header.createdAt), { time: true })}` });
        if (pw === null)
            return;
        const chk = await verifyBackup(f, pw);
        if (!chk.ok) {
            toast(chk.problems.join('؛ '), 'err', 7000);
            return;
        }
        if (!(await confirmBox('پشتیبان به آرشیو فعلی افزوده می‌شود. چیزی حذف یا بازنویسیِ نسخهٔ جدیدتر نمی‌شود و مواردی که اینجا حذف کرده‌اید برنمی‌گردند.', { confirmText: 'بازیابی' })))
            return;
        try {
            const r = await restoreBackup(ctx.archive, f, pw);
            toast(`بازیابی شد: ${faDigits(r.added)} جدید، ${faDigits(r.updated)} به‌روز، ${faDigits(r.skippedExisting)} ردشده (نسخهٔ محلی جدیدتر)، ${faDigits(r.skippedDeleted)} حذف‌شدهٔ محلی`, 'ok', 9000);
            ctx.rerender();
        }
        catch (e) {
            toast(`بازیابی ناموفق: ${e.message}`, 'err', 8000);
        }
    });
    w.append(S('backup', 'پشتیبان‌گیری، بازیابی و خروجی', lastB, h('button', { class: 'btn primary', onclick: async () => { try {
            platform.saveFile(await createBackup(ctx.archive), `sene-${new Date().toISOString().slice(0, 10)}.sene-backup`);
            await ctx.kv.put('meta', 'lastBackup', new Date().toISOString());
            toast('پشتیبان رمزگذاری‌شده ساخته شد. آن را در جای امن (و ترجیحاً بیرون از گوشی) نگه دارید.', 'ok', 7000);
        }
        catch (e) {
            toast(e.message, 'err');
        } } }, 'ساخت پشتیبان رمزگذاری‌شده'), h('label', null, 'بازیابی از فایل پشتیبان', fileIn), h('hr'), h('button', { class: 'btn', onclick: async () => platform.saveFile(await exportJson(ctx.archive, false), 'sene-export.json') }, 'خروجی JSON (بدون فایل‌ها، رمزگذاری‌نشده)'), h('button', { class: 'btn', onclick: async () => { if (await confirmBox('خروجی JSON همراه فایل‌ها رمزگذاری نمی‌شود و ممکن است بسیار حجیم باشد.', { confirmText: 'ادامه' }))
            platform.saveFile(await exportJson(ctx.archive, true), 'sene-export-full.json'); } }, 'خروجی JSON کامل با فایل‌ها'), h('button', { class: 'btn', onclick: async () => platform.saveFile(new Blob([await exportHtml(ctx.archive, { embedImages: true })], { type: 'text/html' }), 'sene-archive.html') }, 'خروجی HTML خوانا'), h('button', { class: 'btn', onclick: () => printHtml(exportHtml(ctx.archive)) }, 'خروجی PDF (از طریق چاپ مرورگر → «ذخیره به‌صورت PDF»)'), h('p', { class: 'muted small' }, 'انتقال به گوشی دیگر: پشتیبان بگیرید، فایل را منتقل کنید، در گوشی دیگر روی صفحهٔ ورود «بازیابی از فایل پشتیبان» را بزنید. یا از همگام‌سازی Drive استفاده کنید. کلید/رمز داخل پشتیبان ذخیره نمی‌شود؛ بدون رمز، پشتیبان قابل بازیابی نیست.')));
    // ----- یادآور -----
    const times = SLOTS.map(([slot, name]) => h('label', null, `یادآوری ${name}`, h('div', { class: 'row' }, h('input', { type: 'time', value: s.reminders[slot] ?? '', onchange: (e) => set({ reminders: { ...ctx.settings.reminders, [slot]: e.target.value || null } }) }), h('button', { class: 'btn small', onclick: () => set({ reminders: { ...ctx.settings.reminders, [slot]: null } }).then(() => ctx.rerender()) }, 'خاموش'))));
    w.append(S('reminders', 'یادآورها', ...times, h('button', { class: 'btn', onclick: async () => { const r = await platform.requestNotifications(); toast(r === 'granted' ? 'اعلان‌ها مجاز شد' : r === 'unsupported' ? 'این مرورگر از اعلان پشتیبانی نمی‌کند' : 'مجوز اعلان داده نشد', r === 'granted' ? 'ok' : 'warn'); } }, 'درخواست مجوز اعلان'), h('button', { class: 'btn', onclick: () => { try {
            platform.saveFile(new Blob([buildIcs(ctx.settings.reminders)], { type: 'text/calendar' }), 'sene-reminders.ics');
            toast('فایل را باز کنید تا به تقویم گوشی افزوده شود');
        }
        catch (e) {
            toast(e.message, 'warn');
        } } }, 'افزودن یادآورها به تقویم گوشی (.ics)'), h('p', { class: 'muted small' }, 'محدودیت: مرورگر نمی‌تواند در پس‌زمینه و هنگام بسته بودن برنامه اعلان زمان‌بندی‌شده را تضمین کند. یادآور فقط وقتی sene باز است نمایش داده می‌شود (و یادآور از دست‌رفته هنگام باز کردن اعلام می‌شود). برای یادآوری مطمئن از فایل تقویم (.ics) استفاده کنید.')));
    // ----- هوش مصنوعی خارجی -----
    const prov = h('select', { 'aria-label': 'نوع سرویس' }, h('option', { value: 'gemini', selected: s.ai.provider === 'gemini' }, 'Gemini (کلید رایگان گوگل)'), h('option', { value: 'openai', selected: s.ai.provider !== 'gemini' }, 'سرویس سازگار با OpenAI (پیشرفته)'));
    const ep = h('input', { value: s.ai.endpoint, placeholder: 'https://…/v1/chat/completions', 'aria-label': 'نشانی سرویس' });
    const md = h('input', { value: s.ai.model, placeholder: 'نام مدل', 'aria-label': 'نام مدل' });
    const ky = h('input', { type: 'password', placeholder: 'کلید API (رمزگذاری‌شده ذخیره می‌شود)', 'aria-label': 'کلید API', autocomplete: 'off' });
    const epRow = h('div', null, ep);
    const syncProv = () => { epRow.hidden = prov.value === 'gemini'; if (prov.value === 'gemini' && !md.value)
        md.value = GEMINI_DEFAULT_MODEL; };
    prov.addEventListener('change', syncProv);
    syncProv();
    w.append(S('ai', 'هوش مصنوعی خارجی (اختیاری)', h('p', { class: 'muted small' }, 'همهٔ قابلیت‌های اصلی بدون آن کار می‌کنند. اگر فعال کنید، فقط با نشان‌دادن دقیق متن و تأیید شما و فقط به همین سرویس ارسال می‌شود. برای Gemini فقط کلید را در همین کادر بچسبانید؛ کلید را در چت یا فایل نگذارید.'), h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.online.externalAi, onchange: (e) => set({ online: { ...s.online, externalAi: e.target.checked } }) }), h('span', null, 'فعال‌سازی')), prov, epRow, md, ky, h('button', { class: 'btn primary', onclick: async () => {
            const provider = prov.value === 'gemini' ? 'gemini' : 'openai';
            await set({ ai: { endpoint: provider === 'gemini' ? '' : ep.value.trim(), model: md.value.trim() || (provider === 'gemini' ? GEMINI_DEFAULT_MODEL : ''), apiKey: '', provider } });
            if (ky.value) {
                await ctx.archive.setSecret({ aiKey: ky.value.trim() });
                ky.value = '';
            }
            toast('ذخیره شد');
        } }, 'ذخیره'), h('button', { class: 'btn', onclick: async () => {
            const cfg = ctx.settings.ai;
            if (cfg.provider !== 'gemini' && !cfg.endpoint) {
                toast('ابتدا ذخیره کنید', 'warn');
                return;
            }
            if (!(await confirmBox(`یک پیام آزمایشی کوتاه («سلام») به «${aiHost(cfg)}» ارسال می‌شود. هیچ خاطره‌ای ارسال نمی‌شود.`, { confirmText: 'ارسال آزمایشی' })))
                return;
            try {
                const r = await askExternal({ ...cfg, apiKey: (await ctx.archive.getSecret()).aiKey }, [{ role: 'user', content: 'فقط بنویس: سلام' }]);
                toast('اتصال موفق بود: ' + r.slice(0, 60), 'ok', 6000);
            }
            catch (e) {
                toast('اتصال ناموفق: ' + e.message, 'err', 8000);
            }
        } }, 'آزمایش اتصال')));
    // ----- فضا و سلامت -----
    const st = h('div', { class: 'stack' });
    const prob = h('div', { class: 'stack' });
    void ctx.archive.storageSummary().then(async (u) => {
        clear(st);
        st.append(h('p', null, `${faDigits(u.memories)} خاطره · ${faDigits(u.attachments)} پیوست (${fmtBytes(u.attachmentBytes)})`), u.usage !== undefined && h('p', null, `مصرف مرورگر: ${fmtBytes(u.usage)}${u.quota ? ` از حدود ${fmtBytes(u.quota)}` : ''} — ماندگاری تضمین‌شده: ${u.persisted ? 'بله' : 'خیر'}`));
        if (u.usage && u.quota && u.usage / u.quota > 0.8) {
            const big = [...ctx.archive.memories.values()].flatMap((m) => m.attachments.map((a) => ({ m, a }))).sort((x, y) => y.a.size - x.a.size).slice(0, 5);
            st.append(h('div', { class: 'card warn' }, h('b', null, 'فضا رو به اتمام است. پیشنهادها (هیچ‌چیز خودکار حذف نمی‌شود):'), h('p', null, 'پشتیبان بگیرید و سپس پیوست‌های سنگین زیر را (در صورت تمایل) حذف کنید:'), big.map(({ m, a }) => h('a', { class: 'chip block', href: `#/m/${m.id}` }, `${a.name} — ${fmtBytes(a.size)}`))));
        }
    });
    w.append(S('health', 'فضای ذخیره‌سازی و سلامت داده', st, h('button', { class: 'btn', onclick: async () => toast((await platform.requestPersistentStorage()) ? 'مرورگر ماندگاری ذخیره‌سازی را داد' : 'مرورگر ماندگاری را تضمین نکرد', 'ok') }, 'درخواست ذخیره‌سازی ماندگار'), h('div', { class: 'row wrap' }, h('button', { class: 'btn', onclick: () => runCheck(false) }, 'بررسی سریع یکپارچگی'), h('button', { class: 'btn', onclick: () => runCheck(true) }, 'بررسی کامل (فایل‌ها هم)')), prob, h('p', { class: 'muted small' }, 'IndexedDB ذخیره‌سازی دائمی تضمین‌شده نیست: مرورگر ممکن است در کمبود فضا، پاک‌کردن اطلاعات سایت یا بی‌استفاده‌ماندن طولانی داده را پاک کند. حتماً پشتیبان منظم یا همگام‌سازی Drive داشته باشید.')));
    async function runCheck(deep) {
        clear(prob);
        prob.append(h('p', null, 'در حال بررسی…'));
        const r = await ctx.archive.integrityCheck(deep);
        clear(prob);
        if (!r.problems.length) {
            prob.append(h('p', { class: 'ok' }, `✓ ${faDigits(r.checked)} مورد بررسی شد و مشکلی نبود.`));
            return;
        }
        prob.append(h('p', { class: 'error' }, `${faDigits(r.problems.length)} مشکل:`), r.problems.map((p) => h('div', { class: 'card' }, p.problem, h('small', { class: 'muted' }, ' ' + p.key))));
        if (ctx.settings.online.drive)
            prob.append(h('button', { class: 'btn', onclick: async () => {
                    if (!(await confirmBox('نسخهٔ خراب محلی کنار گذاشته و نسخهٔ سالم از Drive (در صورت وجود) دریافت می‌شود.', { confirmText: 'تلاش برای بازیابی' })))
                        return;
                    for (const p of r.problems) {
                        const [store, id] = splitKey(p.key);
                        if (store === 'mem' || store === 'ent') {
                            await ctx.kv.del(store, id);
                            await ctx.kv.del('sync', p.key);
                            await ctx.kv.del('queue', p.key);
                        }
                        else if (store === 'blob') {
                            await ctx.kv.del('blob', id);
                            await ctx.kv.del('sync', p.key);
                        }
                    }
                    await ctx.archive.load();
                    await ctx.runSync(true);
                    ctx.rerender();
                } }, 'بازیابی نسخهٔ سالم از Drive'));
    }
    w.append(S('about', 'دربارهٔ sene', h('p', null, 'sene نسخهٔ ۱.۰ — آرشیو خصوصی زندگی. داده‌ها در این دستگاه و با رمز شما رمزگذاری می‌شوند.'), h('p', { class: 'muted small' }, 'امنیت مطلق تضمین نمی‌شود: اگر رمز ضعیف باشد یا دستگاه آلوده باشد، رمزگذاری کمکی نمی‌کند.')));
    return w;
};
void null;

return { settingsView };
})();
__M["ui/app.js"] = (() => {
// پوستهٔ برنامه: مسیریابی، چیدمان، قفل خودکار، وضعیت اتصال/همگام‌سازی، یادآورها و ظاهر
const { IdbKV, MemoryKV } = __M["core/kv.js"];
const { Vault } = __M["core/vault.js"];
const { Archive } = __M["core/archive.js"];
const { DEFAULT_CATEGORIES, DEFAULT_SETTINGS } = __M["core/types.js"];
const { GoogleAuth } = __M["sync/google-auth.js"];
const { SyncEngine, newDeviceId } = __M["sync/engine.js"];
const { AuthError, GoogleDriveApi, NetworkError } = __M["sync/drive.js"];
const { dueReminders } = __M["core/reminders.js"];
const { platform } = __M["platform.js"];
const { clear, h, toast } = __M["ui/dom.js"];
const { faDigits } = __M["util/jalali.js"];
const { lockScreen } = __M["ui/views/lock.js"];
const { homeView, newView, detailView, editView, searchView } = __M["ui/views/memory.js"];
const { calendarView, timelineView, dashboardView, graphView, reportsView, insightsView, compareView } = __M["ui/views/pro.js"];
const { moreView, profileView, peopleView, chatView } = __M["ui/views/more.js"];
const { settingsView } = __M["ui/views/settings.js"];
const FONTS = {
    system: 'system-ui, "Segoe UI", Roboto, "Noto Sans Arabic", "Noto Naskh Arabic", sans-serif',
    tahoma: 'Tahoma, "DejaVu Sans", Verdana, sans-serif',
    serif: '"Noto Naskh Arabic", "Traditional Arabic", "Times New Roman", serif',
    mono: 'ui-monospace, "DejaVu Sans Mono", Menlo, monospace',
};
const ROUTES = {
    home: { view: homeView, title: 'sene', tab: 'home' }, search: { view: searchView, title: 'جست‌وجو', tab: 'search' },
    new: { view: newView, title: 'ثبت خاطره', tab: 'new' }, m: { view: detailView, title: 'خاطره' }, edit: { view: editView, title: 'ویرایش خاطره' },
    calendar: { view: calendarView, title: 'تقویم', tab: 'calendar' }, timeline: { view: timelineView, title: 'خط زمانی', tab: 'more' },
    dashboard: { view: dashboardView, title: 'داشبورد', tab: 'more' }, graph: { view: graphView, title: 'نمودار ارتباطی', tab: 'more' },
    reports: { view: reportsView, title: 'گزارش‌ها', tab: 'more' }, insights: { view: insightsView, title: 'برداشت‌ها', tab: 'more' },
    compare: { view: compareView, title: 'مقایسهٔ دوره‌ها', tab: 'more' }, profile: { view: profileView, title: 'پروفایل من', tab: 'more' },
    people: { view: peopleView, title: 'اشخاص', tab: 'more' }, chat: { view: chatView, title: 'گفت‌وگو با آرشیو', tab: 'more' },
    more: { view: moreView, title: 'بیشتر', tab: 'more' }, settings: { view: settingsView, title: 'تنظیمات', tab: 'more' },
};
class App {
    kv;
    vault;
    archive;
    settings = { ...DEFAULT_SETTINGS };
    auth = new GoogleAuth(() => this.settings.driveClientId || window.SENE_CONFIG?.googleClientId || '');
    sync = { state: 'disabled', pending: 0, conflicts: 0 };
    root;
    viewEl;
    titleEl;
    statusEl;
    tabsEl;
    lockTimer = 0;
    hiddenAt = 0;
    syncTimer = 0;
    tick = 0;
    unlockedAt = 0;
    eng;
    navToken = 0;
    constructor(kv, root) {
        this.kv = kv;
        this.root = root;
    }
    static async start(root) {
        let kv;
        try {
            kv = await IdbKV.open();
        }
        catch (e) {
            root.append(h('div', { class: 'fatal' }, h('h1', null, 'ذخیره‌سازی در دسترس نیست'), h('p', null, 'مرورگر شما اجازهٔ استفاده از IndexedDB را نمی‌دهد (شاید حالت خصوصی یا ذخیره‌سازی مسدود است). sene بدون ذخیره‌سازی محلی نمی‌تواند اطلاعات را نگه دارد.'), h('p', { class: 'muted' }, String(e?.message ?? e))));
            return null;
        }
        const app = new App(kv, root);
        await app.boot();
        return app;
    }
    async boot() {
        this.vault = new Vault(this.kv);
        let did = await this.kv.get('meta', 'deviceId');
        if (!did) {
            did = newDeviceId();
            await this.kv.put('meta', 'deviceId', did);
        }
        this.archive = new Archive(this.kv, this.vault, did);
        this.settings = await this.archive.loadSettings();
        this.applyAppearance();
        window.addEventListener('online', () => { this.refreshStatus(); this.scheduleSync(500); });
        window.addEventListener('offline', () => this.refreshStatus());
        ['pointerdown', 'keydown', 'touchstart'].forEach((e) => document.addEventListener(e, () => this.armLock(), { passive: true }));
        document.addEventListener('visibilitychange', () => {
            if (document.hidden)
                this.hiddenAt = Date.now();
            else if (this.vault.unlocked && this.settings.lockMinutes > 0 && this.hiddenAt && Date.now() - this.hiddenAt > this.settings.lockMinutes * 60000)
                this.lock();
        });
        window.addEventListener('hashchange', () => { if (this.vault.unlocked)
            this.renderRoute(); });
        this.archive.onChange(() => { this.refreshStatus(); this.scheduleSync(4000); });
        this.showLock();
    }
    // ---------- ظاهر ----------
    applyAppearance() {
        const s = this.settings;
        const d = document.documentElement;
        const dark = s.theme === 'dark' || (s.theme === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
        d.dataset.theme = dark ? 'dark' : 'light';
        d.dataset.accent = s.accent;
        d.style.setProperty('--font', FONTS[s.font]);
        d.style.fontSize = `${s.fontSize}%`;
        d.style.setProperty('--lh', String(s.lineHeight));
        document.querySelector('meta[name=theme-color]')?.setAttribute('content', dark ? '#14131c' : '#f6f4fa');
    }
    async setSettings(patch) {
        this.settings = { ...this.settings, ...patch };
        await this.archive.saveSettings(this.settings);
        this.applyAppearance();
        this.armLock();
        this.setupReminders();
        await this.refreshStatus();
    }
    categories() { return [...DEFAULT_CATEGORIES, ...this.settings.customCategories]; }
    // ---------- قفل ----------
    showLock() { clear(this.root); this.root.append(lockScreen(this, () => this.onUnlocked())); }
    lock() {
        this.vault.lock();
        this.archive.unloadMemoryCache();
        this.eng = undefined;
        window.clearTimeout(this.lockTimer);
        window.clearInterval(this.tick);
        window.clearTimeout(this.syncTimer);
        this.showLock();
    }
    armLock() {
        window.clearTimeout(this.lockTimer);
        if (!this.vault.unlocked || !this.settings.lockMinutes)
            return;
        this.lockTimer = window.setTimeout(() => this.lock(), this.settings.lockMinutes * 60000);
    }
    async onUnlocked() {
        this.unlockedAt = Date.now();
        this.settings = await this.archive.loadSettings();
        const { corrupted } = await this.archive.load();
        this.buildShell();
        this.armLock();
        this.setupReminders();
        if (!location.hash || location.hash === '#/')
            location.hash = '#/home';
        await this.refreshStatus();
        await this.renderRoute();
        if (corrupted.length)
            toast(`${faDigits(corrupted.length)} مورد خراب یا دست‌کاری‌شده شناسایی شد. در تنظیمات ← سلامت داده بررسی کنید.`, 'err', 8000);
        if (this.settings.online.drive && this.settings.autoSync && navigator.onLine)
            this.scheduleSync(800);
    }
    // ---------- چیدمان ----------
    buildShell() {
        clear(this.root);
        this.titleEl = h('h1', { id: 'title' }, 'sene');
        this.statusEl = h('div', { class: 'status', 'aria-live': 'polite' });
        this.viewEl = h('main', { id: 'view', tabindex: '-1' });
        this.tabsEl = h('nav', { class: 'tabs', 'aria-label': 'ناوبری اصلی' });
        this.root.append(h('header', { class: 'top' }, this.titleEl, this.statusEl, h('button', { class: 'icon-btn', 'aria-label': 'قفل برنامه', onclick: () => this.lock() }, '🔒')), this.viewEl, this.tabsEl);
    }
    drawTabs(active) {
        clear(this.tabsEl);
        const items = [['home', '🏠', 'خانه'], ['search', '🔎', 'جست‌وجو'], ['new', '＋', 'ثبت'], ['calendar', '📅', 'تقویم'], ['more', '☰', 'بیشتر']];
        for (const [id, ic, label] of items)
            this.tabsEl.append(h('a', { href: `#/${id}`, class: `tab ${active === id ? 'on' : ''} ${id === 'new' ? 'plus' : ''}`, 'aria-current': active === id ? 'page' : null }, h('span', { class: 'ic', 'aria-hidden': 'true' }, ic), h('span', null, label)));
    }
    path() { return (location.hash.replace(/^#\/?/, '').split('?')[0]) || 'home'; }
    query() { return new URLSearchParams(location.hash.split('?')[1] ?? ''); }
    go(p) { location.hash = `#/${p}`; }
    rerender() { void this.renderRoute(); }
    async renderRoute() {
        if (!this.vault.unlocked)
            return;
        const tok = ++this.navToken;
        const [name, ...args] = this.path().split('/');
        const r = ROUTES[name] ?? ROUTES.home;
        this.titleEl.textContent = r.title;
        this.drawTabs(r.tab);
        try {
            const el = await r.view(this, args.map(decodeURIComponent), this.query());
            if (tok !== this.navToken)
                return;
            clear(this.viewEl);
            this.viewEl.append(el);
            this.viewEl.scrollTop = 0;
            window.scrollTo(0, 0);
        }
        catch (e) {
            clear(this.viewEl);
            this.viewEl.append(h('div', { class: 'card err' }, 'خطا در نمایش این صفحه: ', String(e?.message ?? e)));
        }
    }
    // ---------- وضعیت ----------
    async refreshStatus() {
        if (!this.vault.unlocked)
            return;
        const pending = (await this.archive.queue()).length;
        const conflicts = (await this.kv.all('conflict')).length;
        const last = await this.kv.get('meta', 'lastSync');
        const base = this.sync.state === 'running' ? 'running' : !this.settings.online.drive ? 'disabled' : !navigator.onLine ? 'offline' : this.sync.state === 'error' || this.sync.state === 'needs-auth' ? this.sync.state : 'idle';
        this.sync = { ...this.sync, state: base, pending, conflicts, last: last?.at ?? this.sync.last };
        if (!this.statusEl)
            return;
        clear(this.statusEl);
        const net = navigator.onLine ? ['online', 'آنلاین'] : ['offline', 'آفلاین'];
        const sync = { disabled: ['off', 'همگام‌سازی خاموش'], idle: ['ok', pending ? `${faDigits(pending)} در صف` : 'همگام'], running: ['run', 'در حال همگام‌سازی…'], offline: ['warn', pending ? `${faDigits(pending)} در انتظار اینترنت` : 'آفلاین'], error: ['err', 'خطای همگام‌سازی'], 'needs-auth': ['warn', 'نیاز به ورود Google'] }[this.sync.state];
        this.statusEl.append(h('span', { class: `chip ${net[0]}`, title: 'وضعیت اتصال' }, net[1]), h('a', { class: `chip ${sync[0]}`, href: '#/settings?s=sync', title: this.sync.error ?? 'وضعیت همگام‌سازی' }, sync[1] + (conflicts ? ` · ${faDigits(conflicts)} تعارض` : '')));
    }
    // ---------- همگام‌سازی ----------
    engine() {
        if (!this.eng) {
            const api = new GoogleDriveApi(() => this.auth.getToken(false));
            this.eng = new SyncEngine(this.archive, api, { folderName: this.settings.driveFolderName || 'sene', folderId: this.settings.driveFolderId || undefined, onFolder: (id) => { void this.setSettings({ driveFolderId: id }); } });
            this.eng.onProgress = (m) => { this.sync.progress = m; };
        }
        return this.eng;
    }
    scheduleSync(ms) {
        window.clearTimeout(this.syncTimer);
        if (!this.vault.unlocked || !this.settings.online.drive || !this.settings.autoSync || !navigator.onLine)
            return;
        this.syncTimer = window.setTimeout(() => { void this.runSync(false); }, ms);
    }
    async runSync(interactive = false) {
        if (!this.settings.online.drive)
            return;
        if (this.sync.state === 'running')
            return;
        this.sync = { ...this.sync, state: 'running', error: undefined };
        await this.refreshStatus();
        try {
            if (interactive && !this.auth.connected)
                await this.auth.getToken(true);
            this.eng = undefined; // تنظیمات پوشه ممکن است تغییر کرده باشد
            const r = await this.engine().run();
            this.sync = { ...this.sync, state: 'idle', last: r.at };
            if (r.errors.length) {
                this.sync.state = 'error';
                this.sync.error = r.errors[0].message;
            }
            if (interactive)
                toast(`همگام‌سازی انجام شد: ${faDigits(r.uploaded)} ارسال، ${faDigits(r.downloaded)} دریافت${r.conflicts ? `، ${faDigits(r.conflicts)} تعارض` : ''}`, r.errors.length ? 'warn' : 'ok');
        }
        catch (e) {
            this.sync.state = e instanceof AuthError ? 'needs-auth' : e instanceof NetworkError ? 'offline' : 'error';
            this.sync.error = e.message;
            if (interactive)
                toast(e.message, 'err', 6000);
        }
        await this.refreshStatus();
        if (['settings', 'home'].includes(this.path().split('/')[0]))
            this.rerender();
    }
    // ---------- یادآورها ----------
    setupReminders() {
        window.clearInterval(this.tick);
        const r = this.settings.reminders;
        if (!r.morning && !r.evening && !r.night)
            return;
        const check = async () => {
            if (!this.vault.unlocked)
                return;
            const fired = (await this.kv.get('meta', 'remindersFired')) ?? {};
            const due = dueReminders(this.settings.reminders, new Date(), fired);
            if (!due.length)
                return;
            const now = new Date();
            const day = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
            for (const d of due)
                fired[d.slot] = day;
            await this.kv.put('meta', 'remindersFired', fired);
            const text = due[due.length - 1].text;
            toast(`🔔 ${text}`, 'ok', 9000);
            void platform.notify('sene', text);
        };
        this.tick = window.setInterval(check, 30000);
        void check();
    }
}


return { App, MemoryKV };
})();
__M["main.js"] = (() => {
const { App } = __M["ui/app.js"];
async function registerSW() {
    if (!('serviceWorker' in navigator))
        return;
    try {
        await navigator.serviceWorker.register('sw.js');
    }
    catch (e) {
        console.warn('Service Worker ثبت نشد', e);
    }
}
window.addEventListener('error', (e) => { const b = document.getElementById('boot'); if (b)
    b.textContent = `خطا: ${e.message}`; });
const root = document.getElementById('app');
document.getElementById('boot')?.remove();
void registerSW();
void App.start(root);

return {  };
})();

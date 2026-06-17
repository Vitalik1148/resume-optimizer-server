import 'dotenv/config';
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import { jsonrepair } from 'jsonrepair';

const app = express();
const PORT = process.env.PORT || 3000;
const DEFAULT_ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
    'https://resume-optimizer-diplom.vercel.app',
    'https://resume-optimizer-diplom-vitalik4384-2488s-projects.vercel.app',
];
const DEFAULT_JOB_TEXT_ALLOWED_HOSTS = ['hh.ru', 'hh.kz', 'hh.uz', 'hh.kg'];
const MAX_JOB_TEXT_LENGTH = 20000;
const RATE_LIMIT_WINDOW_MS = Math.min(
    Math.max(Number.parseInt(process.env.RATE_LIMIT_WINDOW_SECONDS || '60', 10) || 60, 1),
    3600,
) * 1000;
const JOB_TEXT_RATE_LIMIT = Math.min(
    Math.max(Number.parseInt(process.env.JOB_TEXT_RATE_LIMIT || '30', 10) || 30, 1),
    1000,
);
const OPTIMIZE_RATE_LIMIT = Math.min(
    Math.max(Number.parseInt(process.env.OPTIMIZE_RATE_LIMIT || '10', 10) || 10, 1),
    1000,
);
const allowedOrigins = new Set(parseCsv(process.env.ALLOWED_ORIGINS || '').length
    ? parseCsv(process.env.ALLOWED_ORIGINS)
    : DEFAULT_ALLOWED_ORIGINS);
const jobTextAllowedHosts = new Set(parseCsv(process.env.JOB_TEXT_ALLOWED_HOSTS || '').length
    ? parseCsv(process.env.JOB_TEXT_ALLOWED_HOSTS)
    : DEFAULT_JOB_TEXT_ALLOWED_HOSTS);
const rateLimitBuckets = new Map();

app.set('trust proxy', 1);

function parseCsv(value) {
    return String(value || '')
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
}

function isOriginAllowed(origin) {
    return allowedOrigins.has(String(origin || '').trim().toLowerCase());
}

function setCorsHeaders(req, res, next) {
    const origin = req.headers.origin;
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (!origin) {
        if (req.method === 'OPTIONS') return res.status(204).end();
        return next();
    }

    if (!isOriginAllowed(origin)) {
        if (req.method === 'OPTIONS') return res.status(403).end();
        return res.status(403).json({ error: 'Origin not allowed' });
    }

    res.setHeader('Access-Control-Allow-Origin', origin);
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
}

function clientKey(req) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    return forwarded || req.ip || req.socket?.remoteAddress || 'unknown';
}

function createRateLimiter({ name, max }) {
    return (req, res, next) => {
        const key = `${name}:${clientKey(req)}`;
        const now = Date.now();
        const bucket = rateLimitBuckets.get(key);

        if (!bucket || bucket.resetAt <= now) {
            rateLimitBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
            return next();
        }

        bucket.count += 1;
        if (bucket.count > max) {
            const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
            res.setHeader('Retry-After', String(retryAfter));
            return res.status(429).json({ error: 'Too many requests' });
        }

        return next();
    };
}

function hostMatchesAllowedHost(host, allowedHost) {
    return host === allowedHost || host.endsWith(`.${allowedHost}`);
}

function validateJobTextSource(jobUrl) {
    const parsed = new URL(jobUrl);
    const host = parsed.hostname.toLowerCase();
    const allowed = [...jobTextAllowedHosts].some((allowedHost) => hostMatchesAllowedHost(host, allowedHost));
    if (!allowed) {
        const err = new Error('Unsupported job URL host');
        err.status = 400;
        throw err;
    }
}

function normalizeJobText(value) {
    const text = sanitizeText(value);
    if (!text) return '';
    if (text.length > MAX_JOB_TEXT_LENGTH) {
        const err = new Error(`Job text is too long. Maximum length is ${MAX_JOB_TEXT_LENGTH} characters`);
        err.status = 413;
        throw err;
    }
    return text;
}

// --- MIDDLEWARE ---
app.use(setCorsHeaders);
app.use(express.json({ limit: '1mb' }));
const jobTextRateLimit = createRateLimiter({ name: 'job-text', max: JOB_TEXT_RATE_LIMIT });
const optimizeRateLimit = createRateLimiter({ name: 'optimize', max: OPTIMIZE_RATE_LIMIT });

app.use('/optimize', (req, res, next) => {
    if (req.method === 'POST') {
        const hasAuth = Boolean(getBearerToken(req));
        const contentLength = req.headers['content-length'] || 'unknown';
        console.log(`[OPT] HTTP POST /optimize received (auth=${hasAuth ? 'present' : 'missing'}, contentLength=${contentLength})`);
    }
    next();
});

// --- SUPABASE CLIENT (Service Role — полный доступ к БД) ---
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

const ADMIN_EMAILS = new Set(
    (process.env.ADMIN_EMAILS || '')
        .split(',')
        .map((email) => email.trim().toLowerCase())
        .filter(Boolean)
);
const AVATAR_BUCKET = 'avatars';
const AVATAR_URL_MARKER = '/storage/v1/object/public/avatars/';
const optimizationJobs = new Map();
const ACTIVE_JOB_STATUSES = new Set(['processing']);

function getBearerToken(req) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (!/^Bearer$/i.test(scheme || '') || !token) return '';
    return token.trim();
}

function isAdminEmail(email) {
    return ADMIN_EMAILS.has(String(email || '').trim().toLowerCase());
}

async function requireAuthenticatedUser(req, res, next) {
    try {
        const token = getBearerToken(req);
        if (!token) {
            return res.status(401).json({ error: 'Missing Authorization bearer token' });
        }

        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        req.auth = { token, user };
        next();
    } catch (err) {
        next(err);
    }
}

async function requireAdmin(req, res, next) {
    await requireAuthenticatedUser(req, res, () => {
        if (ADMIN_EMAILS.size === 0) {
            return res.status(503).json({ error: 'ADMIN_EMAILS is not configured on the server' });
        }

        if (!isAdminEmail(req.auth.user.email)) {
            return res.status(403).json({ error: 'Admin access required' });
        }

        next();
    });
}

function asyncRoute(handler) {
    return (req, res, next) => {
        Promise.resolve(handler(req, res, next)).catch(next);
    };
}

function parsePositiveInt(value, fallback, max = 100) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed < 1) return fallback;
    return Math.min(parsed, max);
}

function sanitizeText(value, fallback = '') {
    const text = String(value || '').trim();
    return text || fallback;
}

function hasCyrillicText(value) {
    return /[\u0400-\u04FF]/.test(String(value || ''));
}

function buildRussianAuditFeedback(feedback) {
    const cleanFeedback = sanitizeText(feedback).slice(0, 700);
    if (!cleanFeedback) return '';
    if (hasCyrillicText(cleanFeedback)) return cleanFeedback;

    const lower = cleanFeedback.toLowerCase();
    if (lower.includes('critical mismatch') || lower.includes('mismatch') || lower.includes('not qualified')) {
        return 'Критическое несоответствие: требования вакансии сильно расходятся с исходным резюме. Без добавления неподтвержденного опыта или навыков нельзя безопасно довести оптимизированную версию до проходного score.';
    }
    if (lower.includes('hallucination') || lower.includes('fabricat') || lower.includes('invent')) {
        return 'Аудит нашел неподтвержденные добавления: в оптимизированной версии появились навыки, опыт или достижения, которых нет в исходном резюме.';
    }
    if (lower.includes('unsupported') || lower.includes('not present') || lower.includes('zero mention')) {
        return 'Аудит отклонил оптимизацию, потому что часть требований вакансии не подтверждается исходным резюме.';
    }
    if (lower.includes('generic') || lower.includes('robotic') || lower.includes('ai-sounding')) {
        return 'Аудит отклонил оптимизацию из-за слишком общего или неестественного текста. Нужно переписать формулировки ближе к фактам из резюме.';
    }

    return 'Аудит отклонил оптимизацию: результат не набрал проходной score и требует правок по соответствию вакансии и фактам исходного резюме.';
}

function extractAvatarFileNameFromUrl(imageUrl) {
    if (!imageUrl || typeof imageUrl !== 'string') return '';
    const trimmedUrl = imageUrl.trim();
    if (!trimmedUrl) return '';

    try {
        const parsed = new URL(trimmedUrl);
        const markerIndex = parsed.pathname.indexOf(AVATAR_URL_MARKER);
        if (markerIndex !== -1) {
            return decodeURIComponent(parsed.pathname.slice(markerIndex + AVATAR_URL_MARKER.length)).trim();
        }
        const pathParts = parsed.pathname.split('/');
        return decodeURIComponent(pathParts[pathParts.length - 1] || '').trim();
    } catch {
        const cleanPath = trimmedUrl.split('?')[0].split('#')[0];
        const pathParts = cleanPath.split('/');
        return decodeURIComponent(pathParts[pathParts.length - 1] || '').trim();
    }
}

function isStorageFolder(entry) {
    return Boolean(entry?.name) && !entry.id && !entry.metadata;
}

async function listStorageEntries(path = '') {
    const pageSize = 1000;
    const entries = [];
    let offset = 0;

    while (true) {
        const { data, error } = await supabase.storage
            .from(AVATAR_BUCKET)
            .list(path, {
                limit: pageSize,
                offset,
                sortBy: { column: 'updated_at', order: 'desc' },
            });

        if (error) throw error;
        entries.push(...(data || []));

        if (!data || data.length < pageSize) break;
        offset += pageSize;
    }

    return entries;
}

async function listAvatarFiles(path = '') {
    const entries = await listStorageEntries(path);
    const files = [];

    for (const entry of entries) {
        if (!entry?.name || entry.name === '.emptyFolderPlaceholder') continue;

        const fullName = path ? `${path}/${entry.name}` : entry.name;

        if (isStorageFolder(entry)) {
            files.push(...await listAvatarFiles(fullName));
            continue;
        }

        files.push({
            ...entry,
            name: fullName,
            baseName: entry.name,
            folder: path,
        });
    }

    return files.sort((a, b) => {
        const aTime = Date.parse(a.updated_at || a.created_at || 0);
        const bTime = Date.parse(b.updated_at || b.created_at || 0);
        return bTime - aTime;
    });
}

function extractResumeProfile(resume) {
    const profile = resume?.content?.profile || {};
    return {
        name: profile.name || 'Без имени',
        role: profile.role || 'Роль не указана',
        contact: profile.contact || '',
        imageUrl: profile.imageUrl || '',
        summary: profile.summary || '',
    };
}

function createJobRecord(resumeId, userId) {
    const id = `job_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const now = new Date().toISOString();
    const record = {
        id,
        resumeId,
        userId,
        status: 'processing',
        attempts: 0,
        auditScore: null,
        auditThreshold: null,
        auditFeedback: '',
        failureReason: '',
        message: 'Оптимизация запущена',
        createdAt: now,
        updatedAt: now,
    };
    optimizationJobs.set(id, record);
    return record;
}

function updateJobRecord(jobId, patch) {
    if (!jobId || !optimizationJobs.has(jobId)) return;
    const nextRecord = {
        ...optimizationJobs.get(jobId),
        ...patch,
        updatedAt: new Date().toISOString(),
    };
    optimizationJobs.set(jobId, nextRecord);

    if (patch.status === 'failed') {
        console.warn(
            `[OPT][ADMIN_LOG] job=${nextRecord.id} user=${nextRecord.userId || 'unknown'} resume=${nextRecord.resumeId || 'unknown'} reason=${nextRecord.failureReason || nextRecord.message || 'failed'}`,
        );
    }
}

function isActiveOptimizationJob(job) {
    return ACTIVE_JOB_STATUSES.has(String(job?.status || '').toLowerCase());
}

function getLiveOptimizationJobs(limit = null) {
    const jobs = [...optimizationJobs.values()]
        .filter(isActiveOptimizationJob)
        .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

    return limit ? jobs.slice(0, limit) : jobs;
}

function getRecentOptimizationJobs({ limit = null, userId = null } = {}) {
    let jobs = [...optimizationJobs.values()];

    if (userId) {
        jobs = jobs.filter((job) => job.userId === userId);
    }

    jobs.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    const sliced = limit ? jobs.slice(0, limit) : jobs;
    return sliced.map((job) => ({ ...job }));
}

function countOptimizationJobsByStatus(status) {
    return [...optimizationJobs.values()]
        .filter((job) => String(job.status || '').toLowerCase() === status)
        .length;
}

function buildAuditFailureMessage(score, threshold, feedback) {
    const scoreText = score === null || score === undefined ? 'не удалось получить' : `${score}/${threshold}`;
    const feedbackText = buildRussianAuditFeedback(feedback);
    return feedbackText
        ? `Оптимизация не сохранена: аудит дал score ${scoreText}. Причина: ${feedbackText}`
        : `Оптимизация не сохранена: аудит дал score ${scoreText}, ниже порога ${threshold}.`;
}

async function getUsersByIdMap(userIds) {
    const uniqueIds = [...new Set((userIds || []).filter(Boolean))];
    const entries = await Promise.all(uniqueIds.map(async (id) => {
        const { data, error } = await supabase.auth.admin.getUserById(id);
        if (error || !data?.user) return [id, null];
        return [id, data.user];
    }));
    return new Map(entries);
}

async function getResumeCountsByUser(userIds) {
    const uniqueIds = [...new Set((userIds || []).filter(Boolean))];
    const counts = new Map(uniqueIds.map((id) => [id, { resumes: 0, aiVersions: 0 }]));
    if (uniqueIds.length === 0) return counts;

    const { data, error } = await supabase
        .from('resumes')
        .select('user_id, parent_id')
        .in('user_id', uniqueIds);

    if (error) throw error;

    (data || []).forEach((row) => {
        const current = counts.get(row.user_id) || { resumes: 0, aiVersions: 0 };
        current.resumes += 1;
        if (row.parent_id) current.aiVersions += 1;
        counts.set(row.user_id, current);
    });

    return counts;
}

function shapeUser(user, counts = { resumes: 0, aiVersions: 0 }) {
    return {
        id: user.id,
        email: user.email || '',
        created_at: user.created_at || null,
        last_sign_in_at: user.last_sign_in_at || null,
        deleted_at: user.deleted_at || null,
        banned_until: user.banned_until || null,
        is_deleted: Boolean(user.deleted_at),
        is_banned: Boolean(user.banned_until && new Date(user.banned_until) > new Date()),
        user_metadata: user.user_metadata || {},
        app_metadata: user.app_metadata || {},
        resume_count: counts.resumes || 0,
        ai_version_count: counts.aiVersions || 0,
    };
}

async function enrichResumes(rows) {
    const usersById = await getUsersByIdMap((rows || []).map((row) => row.user_id));
    return (rows || []).map((resume) => {
        const owner = usersById.get(resume.user_id);
        return {
            ...resume,
            owner_email: owner?.email || 'unknown',
            profile: extractResumeProfile(resume),
            type: resume.parent_id ? 'ai' : 'base',
        };
    });
}

async function removeAvatarIfUnused(fileName, excludedResumeIds = []) {
    if (!fileName) return { removed: false, reason: 'empty' };
    const excluded = new Set(excludedResumeIds);

    const { data: resumes, error } = await supabase
        .from('resumes')
        .select('id, content');

    if (error) throw error;

    const stillReferenced = (resumes || []).some((row) => {
        if (excluded.has(row.id)) return false;
        return extractAvatarFileNameFromUrl(row?.content?.profile?.imageUrl) === fileName;
    });

    if (stillReferenced) return { removed: false, reason: 'referenced' };

    const { error: storageError } = await supabase.storage
        .from(AVATAR_BUCKET)
        .remove([fileName]);

    if (storageError) throw storageError;
    return { removed: true };
}

async function deleteResumeById(resumeId) {
    const { data: resume, error: fetchError } = await supabase
        .from('resumes')
        .select('id, content')
        .eq('id', resumeId)
        .single();

    if (fetchError || !resume) {
        const err = new Error('Resume not found');
        err.status = 404;
        throw err;
    }

    const avatarFileName = extractAvatarFileNameFromUrl(resume?.content?.profile?.imageUrl);

    const { error: unlinkError } = await supabase
        .from('resumes')
        .update({ parent_id: null })
        .eq('parent_id', resumeId);

    if (unlinkError) throw unlinkError;

    const { error: deleteError } = await supabase
        .from('resumes')
        .delete()
        .eq('id', resumeId);

    if (deleteError) throw deleteError;

    const avatarCleanup = await removeAvatarIfUnused(avatarFileName, [resumeId]);
    return { deleted: true, avatarCleanup };
}

// --- ПРОМПТЫ ---
const OPTIMIZER_PROMPT = `
You are a resume optimization expert. Your goal is to subtly adapt the resume so it passes ATS (Applicant Tracking Systems) for a specific job posting.

CRITICAL IDENTITY RULE (HIGHEST PRIORITY):
- You MUST preserve the candidate's actual profession, job titles, and career field.
- If the candidate is a "Fullstack Developer" and the job posting is for "SMM Manager" — you still keep them as a developer. You do NOT rewrite them into an SMM specialist.
- NEVER change the person's professional identity, title, or core field of expertise.
- If the job and resume are in different fields, focus on highlighting TRANSFERABLE SKILLS that naturally exist in the resume.

CONTENT RULES:
- When describing experiences, show concrete results: focus on impact (Action -> Result), not just tasks.
- Include specific technologies within achievement descriptions.
- Feature keywords matching job requirements ONLY IF they genuinely exist in the original resume.
- You CAN add general terms inferable from context (e.g. if user did text processing -> add "NLP"; if used React -> add "Frontend").
- Remove obvious skills (Excel, Word, VS Code, Jira, Zoom) unless specifically required by the job.
- Exclude: age, hobbies, marital status.
- Try to preserve the original writing style but make it punchier.

STRICT RULES - NEVER VIOLATE:
- NEVER change job titles, company names, education, or dates from the original.
- NEVER replace the candidate's real skills with skills from the job posting that they don't have.
- ONLY add technologies/skills if they are strongly implied by the original context.
- If a language, framework, library, methodology, database, cloud, tool, or metric is not explicitly present in the original resume, DO NOT add it.
- It is better to miss a job keyword than to fabricate a skill.
- Do not add generic tech keywords such as HTML, CSS, JavaScript, Git, REST API, SOLID, SQL, ASP.NET, Angular, Vue, Blazor, Python, AI, or 1C unless they are present in the original resume.
- NEVER fabricate job titles, companies, degrees, or metrics.
- NEVER invent achievements not in original.
- NEVER use common AI-marker words: "delve", "spearheaded", "synergy", "tapestry", "democratize", "game-changer".
- Do NOT use markdown bolding (**text**) inside the JSON values.
- Return ONLY valid JSON matching the EXACT SAME structure as the input.
`;

const AUDITOR_PROMPT = `
You are a strict Resume Verification Specialist and AI Detector.
Compare the ORIGINAL resume with the OPTIMIZED version and the JOB description.

SCORING GUIDE (0-100):
- 100: Perfect. All content traceable to original, strong impact, no hallucinations.
- 80-99: Acceptable inferences (e.g. user knows SQL -> added PostgreSQL). Good match.
- 60-79: Questionable additions or "AI-sounding" text (buzzwords).
- 0-59: SEVERE FABRICATION (fake jobs, fake degrees, made-up metrics) or completely generic text.

CHECK FOR:
1. HALLUCINATIONS: Did the optimizer invent a skill/job that isn't hinted at in the original?
2. AI TELLS: Are there words like "delve", "landscape", "testament"? Is the tone too robotic?
3. ATS MATCH: Are key requirements from the job included?

Return JSON: { "score": number, "passed": boolean, "feedback": "Specific advice on what to fix" }
The feedback value MUST be written in Russian only. Do not use English in feedback.
Set 'passed' to true ONLY if score >= 85.
`;

// --- УТИЛИТЫ ---
function extractJson(text) {
    if (!text || typeof text !== 'string') throw new Error("AI returned empty content");

    // Убираем markdown-обёртки типа ```json ... ```
    text = text.replace(/```json\s*/gi, '').replace(/```\s*$/gi, '').trim();

    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start === -1) throw new Error("JSON markers ({}) not found");
    let jsonStr = text.substring(start, end + 1);

    // 1. Пробуем стандартный парсинг
    try {
        return JSON.parse(jsonStr);
    } catch (e) { /* продолжаем */ }

    // 2. Пробуем jsonrepair (специализированная библиотека для починки JSON от LLM)
    try {
        console.warn("[JSON] Standard parse failed, trying jsonrepair...");
        const repaired = jsonrepair(jsonStr);
        return JSON.parse(repaired);
    } catch (e) {
        console.warn("[JSON] jsonrepair failed, trying manual repair...");
    }

    // 3. Ручная починка (fallback)
    try {
        let repaired = jsonStr
            .replace(/\n/g, ' ').replace(/\r/g, ' ')
            .replace(/,\s*([\]}])/g, '$1')
            .replace(/"\s*"/g, '", "')
            .replace(/}\s*{/g, '}, {');

        if ((repaired.match(/"/g) || []).length % 2 !== 0) repaired += '"';

        let openB = (repaired.match(/\{/g) || []).length;
        let closeB = (repaired.match(/\}/g) || []).length;
        while (openB > closeB) { repaired += '}'; closeB++; }

        let openA = (repaired.match(/\[/g) || []).length;
        let closeA = (repaired.match(/\]/g) || []).length;
        while (openA > closeA) { repaired += ']'; closeA++; }

        return JSON.parse(repaired);
    } catch (finalErr) {
        console.error("[JSON] All repair methods failed. Preview:", jsonStr.substring(0, 300));
        throw new Error(`Critical JSON error: ${finalErr.message}`);
    }
}

function cleanJsonValues(obj) {
    if (typeof obj === "string") {
        return obj.replace(/\*\*/g, "").replace(/^\* /g, "").replace(/Situation:|Task:|Action:|Result:/gi, "").trim();
    } else if (Array.isArray(obj)) {
        return obj.map(cleanJsonValues);
    } else if (obj !== null && typeof obj === "object") {
        const newObj = {};
        for (const key in obj) newObj[key] = cleanJsonValues(obj[key]);
        return newObj;
    }
    return obj;
}

const LLM_PROVIDER_CONFIGS = [
    {
        name: "Gemini",
        apiKeyVars: ["LLM_API_KEY", "GEMINI_API_KEY"],
        endpointVars: ["LLM_ENDPOINT", "GEMINI_ENDPOINT"],
        modelVars: ["LLM_MODEL", "GEMINI_MODEL"],
        defaultEndpoint: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        defaultModel: "gemini-2.5-flash",
    },
    {
        name: "Cerebras",
        apiKeyVars: ["LLM_FALLBACK_API_KEY", "CEREBRAS_API_KEY"],
        endpointVars: ["LLM_FALLBACK_ENDPOINT", "CEREBRAS_ENDPOINT"],
        modelVars: ["LLM_FALLBACK_MODEL", "CEREBRAS_MODEL"],
        defaultEndpoint: "https://api.cerebras.ai/v1/chat/completions",
        defaultModel: "qwen-3-235b-a22b-instruct-2507",
    },
    {
        name: "OpenRouter Free",
        apiKeyVars: ["LLM_EMERGENCY_API_KEY", "OPENROUTER_API_KEY"],
        endpointVars: ["LLM_EMERGENCY_ENDPOINT", "OPENROUTER_ENDPOINT"],
        modelVars: ["LLM_EMERGENCY_MODEL", "OPENROUTER_MODEL"],
        defaultEndpoint: "https://openrouter.ai/api/v1/chat/completions",
        defaultModel: "openrouter/free",
    },
];

const LLM_REQUEST_RETRIES = parsePositiveInt(process.env.LLM_REQUEST_RETRIES, 1, 3);

function firstEnvValue(names) {
    for (const name of names) {
        const value = process.env[name];
        if (value && value.trim()) return value.trim();
    }
    return "";
}

function getConfiguredLlmProviders() {
    return LLM_PROVIDER_CONFIGS
        .map((provider) => ({
            ...provider,
            apiKey: firstEnvValue(provider.apiKeyVars),
            endpoint: firstEnvValue(provider.endpointVars) || provider.defaultEndpoint,
            model: firstEnvValue(provider.modelVars) || provider.defaultModel,
        }))
        .filter((provider) => provider.apiKey);
}

function shouldUseLlmJsonMode() {
    const value = String(process.env.LLM_RESPONSE_FORMAT || process.env.LLM_JSON_MODE || "").trim().toLowerCase();
    return ["1", "true", "yes", "json", "json_object"].includes(value);
}

function buildLlmHeaders(provider) {
    const headers = {
        "Authorization": `Bearer ${provider.apiKey}`,
        "Content-Type": "application/json",
    };

    if (provider.name === "OpenRouter Free") {
        const referer = firstEnvValue(["LLM_HTTP_REFERER", "OPENROUTER_HTTP_REFERER"]);
        const title = firstEnvValue(["LLM_APP_TITLE", "OPENROUTER_APP_TITLE"]) || "ResumeAI";
        if (referer) headers["HTTP-Referer"] = referer;
        if (title) headers["X-Title"] = title;
    }

    return headers;
}

function buildLlmRequestBody(provider, payload) {
    const body = {
        ...payload,
        model: provider.model,
    };

    // Disabled by default for wider compatibility with free OpenAI-compatible APIs.
    if (shouldUseLlmJsonMode()) {
        body.response_format = { type: "json_object" };
    }

    return body;
}

function normalizeLlmContent(content) {
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
        return content
            .map((part) => {
                if (typeof part === "string") return part;
                if (typeof part?.text === "string") return part.text;
                if (typeof part?.content === "string") return part.content;
                return "";
            })
            .filter(Boolean)
            .join("\n");
    }
    return "";
}

function getLlmMessageText(messageObj) {
    const content = normalizeLlmContent(messageObj?.content);
    if (content.trim()) return content;

    const reasoning = normalizeLlmContent(messageObj?.reasoning_content);
    if (reasoning.trim()) return reasoning;

    return "";
}

async function readLlmJsonResponse(response) {
    const raw = await response.text();
    if (!raw.trim()) return {};

    try {
        return JSON.parse(raw);
    } catch {
        throw new Error(`Non-JSON API response (${response.status}): ${raw.slice(0, 200)}`);
    }
}

function formatLlmApiError(response, data) {
    const apiError = data?.error;
    if (apiError) {
        if (typeof apiError === "string") return apiError;
        return apiError.message || apiError.code || JSON.stringify(apiError).slice(0, 200);
    }
    return `HTTP ${response.status}`;
}

async function callLlmJsonTask(taskName, payload, parseMessage, options = {}) {
    const providers = getConfiguredLlmProviders();
    if (providers.length === 0) {
        throw new Error("LLM providers are not configured. Set LLM_API_KEY for Gemini, then optional fallback keys.");
    }

    const unavailableProviders = options.unavailableProviders || new Map();
    const errors = [];
    for (const provider of providers) {
        const unavailableReason = unavailableProviders.get(provider.name);
        if (unavailableReason) {
            const message = `${provider.name}: skipped (${unavailableReason})`;
            errors.push(message);
            console.warn(`[OPT] Skipping ${provider.name} for ${taskName}: ${unavailableReason}`);
            continue;
        }

        try {
            console.log(`[OPT] Calling ${provider.name} for ${taskName} (${provider.model})...`);
            const response = await fetchWithRetry(provider.endpoint, {
                method: "POST",
                headers: buildLlmHeaders(provider),
                body: JSON.stringify(buildLlmRequestBody(provider, payload)),
            }, LLM_REQUEST_RETRIES);

            const data = await readLlmJsonResponse(response);
            if (!response.ok || data.error) {
                const apiError = new Error(formatLlmApiError(response, data));
                apiError.status = response.status;
                throw apiError;
            }

            const messageObj = data.choices?.[0]?.message;
            if (!messageObj) {
                throw new Error("Missing choices[0].message in LLM response");
            }

            return {
                provider,
                result: parseMessage(messageObj, data, provider),
            };
        } catch (err) {
            const message = err?.message || String(err);
            if (err?.status === 429 || /\b429\b/.test(message)) {
                unavailableProviders.set(provider.name, "rate-limited by API (HTTP 429)");
            }
            errors.push(`${provider.name}: ${message}`);
            console.error(`[OPT] ✗ ${provider.name} failed for ${taskName}:`, message);
        }
    }

    throw new Error(`All LLM providers failed for ${taskName}: ${errors.join(" | ")}`);
}

async function fetchWithRetry(url, options, retries = 3) {
    let lastError = new Error(`Request failed after ${retries} retries`);
    for (let i = 0; i < retries; i++) {
        try {
            const res = await fetch(url, options);
            if (!res.ok && (res.status >= 500 || res.status === 429)) {
                lastError = new Error(`HTTP ${res.status}`);
                lastError.status = res.status;
                if (i >= retries - 1) throw lastError;
                const delay = 3000 * (i + 1);
                console.log(`[Retry] Attempt ${i + 1} failed (status ${res.status}), waiting ${delay / 1000}s...`);
                await new Promise((resolve) => setTimeout(resolve, delay));
                continue;
            }
            return res;
        } catch (err) {
            lastError = err;
            if (i >= retries - 1) break;
            console.warn(`[Retry] Attempt ${i + 1} error:`, err.message);
        }
    }
    throw lastError;
}

function stripHtml(html = "") {
    return String(html)
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<\/(p|div|li|ul|ol|br|h[1-6]|tr)>/gi, "\n")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/[ \t]{2,}/g, " ")
        .replace(/\n[ \t]+/g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

function normalizeJobUrl(rawUrl) {
    const value = String(rawUrl || "").trim();
    if (!value) throw new Error("Ссылка на вакансию не указана");
    const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;

    try {
        return new URL(withProtocol).toString();
    } catch {
        throw new Error("Некорректная ссылка на вакансию");
    }
}

function extractHhVacancyId(jobUrl) {
    try {
        const parsed = new URL(jobUrl);
        const host = parsed.hostname.toLowerCase();
        const isHhHost =
            host === "hh.ru" ||
            host.endsWith(".hh.ru") ||
            host === "hh.kz" ||
            host.endsWith(".hh.kz") ||
            host === "hh.uz" ||
            host.endsWith(".hh.uz") ||
            host === "hh.kg" ||
            host.endsWith(".hh.kg");

        if (!isHhHost) return "";
        return parsed.pathname.match(/\/vacancy\/(\d+)/)?.[1] || "";
    } catch {
        return "";
    }
}

function formatSalary(salary) {
    if (!salary) return "";
    const parts = [];
    if (salary.from) parts.push(`от ${salary.from}`);
    if (salary.to) parts.push(`до ${salary.to}`);
    if (salary.currency) parts.push(salary.currency);
    if (salary.gross === true) parts.push("до вычета налогов");
    if (salary.gross === false) parts.push("на руки");
    return parts.join(" ");
}

function buildHhJobText(vacancy) {
    const description = stripHtml(vacancy.description || vacancy.branded_description || "");
    const skills = Array.isArray(vacancy.key_skills)
        ? vacancy.key_skills.map((skill) => skill?.name).filter(Boolean).join(", ")
        : "";

    return [
        vacancy.name ? `Название: ${vacancy.name}` : "",
        vacancy.employer?.name ? `Компания: ${vacancy.employer.name}` : "",
        vacancy.area?.name ? `Город: ${vacancy.area.name}` : "",
        formatSalary(vacancy.salary) ? `Зарплата: ${formatSalary(vacancy.salary)}` : "",
        vacancy.experience?.name ? `Опыт: ${vacancy.experience.name}` : "",
        vacancy.employment?.name ? `Занятость: ${vacancy.employment.name}` : "",
        vacancy.schedule?.name ? `График: ${vacancy.schedule.name}` : "",
        skills ? `Ключевые навыки: ${skills}` : "",
        description ? `Описание:\n${description}` : "",
    ].filter(Boolean).join("\n\n").trim();
}

function getHhApiErrorMessage(status, payload) {
    const details = Array.isArray(payload?.errors)
        ? payload.errors.map((error) => [error.type, error.value].filter(Boolean).join(": ")).filter(Boolean).join(", ")
        : "";
    return payload?.description || details || `статус ${status}`;
}

async function fetchHhVacancyText(vacancyId) {
    const userAgent = process.env.HH_USER_AGENT || "ResumeOptimizerDiplom/1.0";
    const response = await fetchWithRetry(`https://api.hh.ru/vacancies/${vacancyId}`, {
        method: "GET",
        headers: {
            "Accept": "application/json",
            "Accept-Language": "ru-RU,ru;q=0.9",
            "User-Agent": userAgent,
            "HH-User-Agent": userAgent,
        },
    }, 2);

    const rawBody = await response.text();
    let payload = null;
    try {
        payload = rawBody ? JSON.parse(rawBody) : null;
    } catch {
        payload = null;
    }

    if (!response.ok) {
        const error = new Error(`HH API вернул ${response.status}: ${getHhApiErrorMessage(response.status, payload)}`);
        error.status = response.status;
        throw error;
    }

    const jobText = buildHhJobText(payload);
    if (jobText.length < 80) {
        throw new Error("HH API вернул слишком короткое описание вакансии");
    }

    return jobText;
}

async function fetchReaderJobText(jobUrl) {
    const response = await fetchWithRetry(`https://r.jina.ai/${jobUrl}`, {
        method: "GET",
        headers: {
            "Accept": "text/plain",
            "User-Agent": "ResumeOptimizerDiplom/1.0",
        },
    }, 2);

    const text = (await response.text()).trim();
    if (!response.ok) {
        throw new Error(`парсер вакансии вернул статус ${response.status}`);
    }

    if (
        !text ||
        /Warning:\s*Target URL returned error\s*(403|451|429|503)/i.test(text) ||
        text.includes("Unavailable For Legal Reasons") ||
        text.includes("Access Denied") ||
        text.includes("Just a moment...") ||
        text.includes("Произошла ошибка. Попробуйте перезагрузить страницу") ||
        text.includes("Доступ ограничен")
    ) {
        throw new Error("сайт вакансии заблокировал автоматическое чтение");
    }

    return text;
}

async function fetchJobTextFromUrl(rawJobUrl) {
    const jobUrl = normalizeJobUrl(rawJobUrl);
    validateJobTextSource(jobUrl);
    const hhVacancyId = extractHhVacancyId(jobUrl);

    if (hhVacancyId) {
        try {
            return { jobText: await fetchHhVacancyText(hhVacancyId), source: "hh-api" };
        } catch (hhError) {
            try {
                return { jobText: await fetchReaderJobText(jobUrl), source: "jina-reader" };
            } catch (readerError) {
                throw new Error(
                    `Не удалось получить вакансию с HH.ru автоматически (${hhError.message}; запасной парсер: ${readerError.message}). Вставьте текст вакансии вручную в поле "Текст вакансии".`
                );
            }
        }
    }

    return { jobText: await fetchReaderJobText(jobUrl), source: "jina-reader" };
}

// --- ТЯЖЁЛАЯ ФОНОВАЯ РАБОТА (С АВТО-РЕТРАЯМИ ДО ПРОХОЖДЕНИЯ АУДИТА) ---
const MAX_ATTEMPTS = parsePositiveInt(process.env.OPT_MAX_ATTEMPTS, 2, 5);        // Максимум попыток
const MIN_AUDIT_SCORE = parsePositiveInt(process.env.OPT_MIN_AUDIT_SCORE, 85, 100);    // Порог прохождения аудита

function getOptimizationTemperature() {
    const parsed = Number.parseFloat(process.env.OPT_TEMPERATURE || "0.15");
    if (!Number.isFinite(parsed)) return 0.15;
    return Math.min(Math.max(parsed, 0), 0.3);
}

async function processOptimization(resumeId, jobText, options = {}) {
    const { jobId = '' } = options;

    console.log(`[OPT] ▶ Starting optimization for resume ${resumeId} (max ${MAX_ATTEMPTS} attempts, threshold: ${MIN_AUDIT_SCORE})`);
    const startTime = Date.now();

    try {
        const configuredProviders = getConfiguredLlmProviders();
        if (configuredProviders.length === 0) {
            const message = "LLM providers are not configured. Add LLM_API_KEY for Gemini, then optional fallback keys.";
            console.error(`[OPT] ✗ ${message}`);
            updateJobRecord(jobId, {
                status: 'failed',
                message,
                failureReason: message,
            });
            return;
        }
        console.log(`[OPT] LLM provider chain: ${configuredProviders.map((provider) => provider.name).join(" -> ")}`);

        // 1. Получаем оригинальное резюме из Supabase
        const { data: resume, error: fetchErr } = await supabase
            .from("resumes")
            .select("content, title, user_id")
            .eq("id", resumeId)
            .single();

        if (fetchErr || !resume) {
            console.error("[OPT] ✗ Failed to fetch resume:", fetchErr);
            const message = 'Исходное резюме не найдено или недоступно';
            updateJobRecord(jobId, {
                status: 'failed',
                message,
                failureReason: fetchErr?.message || message,
            });
            return;
        }

        let optimized = null;
        let auditResult = null;
        let auditPassed = false;
        let bestAuditResult = null;
        let lastAuditFeedback = '';
        let attempt = 0;
        const unavailableProviders = new Map();

        // === ЦИКЛ РЕТРАЕВ: ОПТИМИЗАЦИЯ → АУДИТ → ПОВТОР ЕСЛИ НЕ ПРОШЛО ===
        while (attempt < MAX_ATTEMPTS) {
            attempt++;
            updateJobRecord(jobId, {
                attempts: attempt,
                message: `Попытка ${attempt}/${MAX_ATTEMPTS}`,
            });
            const temperature = getOptimizationTemperature();
            console.log(`\n[OPT] ═══ Attempt ${attempt}/${MAX_ATTEMPTS} (temperature: ${temperature}) ═══`);

            // --- ОПТИМИЗАЦИЯ ---
            try {
                const auditFeedbackBlock = lastAuditFeedback
                    ? `\n\nPREVIOUS AUDIT FAILED. Fix these issues without adding new facts:\n${lastAuditFeedback.slice(0, 1200)}`
                    : '';
                const optCall = await callLlmJsonTask("optimization", {
                    messages: [
                        { role: "system", content: OPTIMIZER_PROMPT + "\nOutput strictly valid JSON only. Do not wrap in markdown blocks like ```json." },
                        { role: "user", content: `JOB:\n${jobText.slice(0, 3000)}\n\nRESUME:\n${JSON.stringify(resume.content)}${auditFeedbackBlock}` },
                    ],
                    temperature: temperature,
                    max_tokens: 16000,
                }, (messageObj) => {
                    const optimizedText = getLlmMessageText(messageObj);
                    if (!optimizedText.trim()) throw new Error("AI returned empty optimization content");
                    return cleanJsonValues(extractJson(optimizedText));
                }, { unavailableProviders });
                optimized = optCall.result;
                const optTime = ((Date.now() - startTime) / 1000).toFixed(1);
                console.log(`[OPT] ✓ Optimization done by ${optCall.provider.name} (${optTime}s)`);
            } catch (optErr) {
                console.error(`[OPT] ✗ Failed to optimize with configured providers (attempt ${attempt}):`, optErr.message);
                continue;
            }

            // --- АУДИТ ---
            try {
                const auditCall = await callLlmJsonTask("audit", {
                    messages: [
                        { role: "system", content: AUDITOR_PROMPT + "\nOutput strictly valid JSON only." },
                        { role: "user", content: `Original: ${JSON.stringify(resume.content)}\nOptimized: ${JSON.stringify(optimized)}\nJob: ${jobText.slice(0, 1000)}` },
                    ],
                    max_tokens: 2000,
                }, (messageObj) => {
                    const auditText = getLlmMessageText(messageObj);
                    if (!auditText.trim()) throw new Error("AI returned empty audit content");
                    return {
                        rawText: auditText,
                        json: extractJson(auditText),
                    };
                }, { unavailableProviders });
                auditResult = auditCall.result.json;
                console.log(`[OPT] Raw audit from ${auditCall.provider.name} (first 200 chars): ${auditCall.result.rawText.slice(0, 200)}`);
            } catch (auditErr) {
                console.error(`[OPT] ✗ Failed to audit with configured providers (attempt ${attempt}):`, auditErr.message);
                continue;
            }
            const auditTime = ((Date.now() - startTime) / 1000).toFixed(1);
            console.log(`[OPT] Audit score: ${auditResult.score} (${auditTime}s) — ${auditResult.score >= MIN_AUDIT_SCORE ? '✅ PASSED' : '❌ FAILED, retrying...'}`);
            if (!bestAuditResult || Number(auditResult.score || 0) > Number(bestAuditResult.score || 0)) {
                bestAuditResult = auditResult;
            }

            // Если аудит прошёл — выходим из цикла
            if (auditResult.score >= MIN_AUDIT_SCORE) {
                auditPassed = true;
                updateJobRecord(jobId, {
                    auditScore: auditResult.score,
                    auditThreshold: MIN_AUDIT_SCORE,
                    auditFeedback: auditResult.feedback || '',
                    message: 'Аудит пройден, сохраняем результат',
                });
                break;
            }

            lastAuditFeedback = buildRussianAuditFeedback(auditResult.feedback)
                || `Оценка аудита ${auditResult.score}; уберите неподтвержденные добавления и оставьте только факты из исходного резюме.`;

            // Если последняя попытка — не продолжаем
            if (attempt >= MAX_ATTEMPTS) {
                console.warn(`[OPT] ⚠ All ${MAX_ATTEMPTS} attempts exhausted. Best score: ${bestAuditResult?.score || auditResult.score}. Not saving failed optimization.`);
            }
        }

        // --- СОХРАНЕНИЕ В SUPABASE (только если аудит пройден) ---
        if (!optimized || !auditPassed) {
            const bestScore = bestAuditResult?.score ?? auditResult?.score ?? null;
            const auditFeedback = buildRussianAuditFeedback(bestAuditResult?.feedback || auditResult?.feedback || lastAuditFeedback || '');
            const failureMessage = buildAuditFailureMessage(bestScore, MIN_AUDIT_SCORE, auditFeedback);
            console.error(`[OPT] ✗ No optimization passed audit after ${attempt} attempt(s). Best score: ${bestScore ?? 'n/a'}. Aborting save. ${auditFeedback ? `Feedback: ${auditFeedback}` : ''}`);
            updateJobRecord(jobId, {
                status: 'failed',
                auditScore: bestScore,
                auditThreshold: MIN_AUDIT_SCORE,
                auditFeedback,
                failureReason: failureMessage,
                message: failureMessage,
            });
            return;
        }

        const scoreLabel = '';
        console.log(`[OPT] Saving optimized resume to database...`);
        const { data: newResume, error: insertErr } = await supabase.from("resumes").insert({
            user_id: resume.user_id,
            parent_id: resumeId,
            title: `${resume.title} (Optimized)${scoreLabel}`,
            content: optimized,
        }).select("id").single();

        if (insertErr) {
            console.error("[OPT] ✗ Failed to save:", insertErr);
            updateJobRecord(jobId, {
                status: 'failed',
                auditScore: auditResult?.score || null,
                auditThreshold: MIN_AUDIT_SCORE,
                failureReason: insertErr.message || 'Ошибка сохранения оптимизированной версии',
                message: 'Ошибка сохранения оптимизированной версии',
            });
            return;
        }

        const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`[OPT] ✅ Done! Resume ID: ${newResume.id} (${attempt} attempt(s), ${totalTime}s, audit: ${auditResult?.score})`);
        updateJobRecord(jobId, {
            status: 'completed',
            attempts: attempt,
            auditScore: auditResult?.score || null,
            auditThreshold: MIN_AUDIT_SCORE,
            auditFeedback: auditResult?.feedback || '',
            resultResumeId: newResume.id,
            message: `Готово за ${totalTime}s`,
        });

    } catch (err) {
        const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
        console.error(`[OPT] ✗ Fatal error after ${totalTime}s:`, err.message);
        updateJobRecord(jobId, {
            status: 'failed',
            failureReason: err.message || 'Фатальная ошибка оптимизации',
            message: err.message || 'Фатальная ошибка оптимизации',
        });
    }
}

// --- ROUTES ---

// Health check (Railway проверяет этот маршрут)
app.get('/', (req, res) => {
    res.json({ status: 'ok', service: 'resume-optimizer' });
});

app.get('/admin/me', requireAuthenticatedUser, (req, res) => {
    res.json({
        isAdmin: isAdminEmail(req.auth.user.email),
        email: req.auth.user.email,
        adminEmailsConfigured: ADMIN_EMAILS.size > 0,
    });
});

app.get('/admin/summary', requireAdmin, asyncRoute(async (req, res) => {
    const [{ data: usersData, error: usersError }, resumesCount, aiCount, avatarFiles, recentResumes] = await Promise.all([
        supabase.auth.admin.listUsers({ page: 1, perPage: 1 }),
        supabase.from('resumes').select('id', { count: 'exact', head: true }),
        supabase.from('resumes').select('id', { count: 'exact', head: true }).not('parent_id', 'is', null),
        listAvatarFiles(),
        supabase.from('resumes')
            .select('*')
            .order('updated_at', { ascending: false })
            .limit(8),
    ]);

    if (usersError) throw usersError;
    if (resumesCount.error) throw resumesCount.error;
    if (aiCount.error) throw aiCount.error;
    if (recentResumes.error) throw recentResumes.error;

    res.json({
        metrics: {
            users: usersData.total || usersData.users?.length || 0,
            resumes: resumesCount.count || 0,
            aiVersions: aiCount.count || 0,
            avatars: avatarFiles.length,
            activeJobs: getLiveOptimizationJobs().length,
            failedJobs: countOptimizationJobsByStatus('failed'),
        },
        recentActivity: await enrichResumes(recentResumes.data || []),
        liveJobs: getLiveOptimizationJobs(8),
        recentJobs: getRecentOptimizationJobs({ limit: 8 }),
    });
}));

app.get('/admin/users', requireAdmin, asyncRoute(async (req, res) => {
    const page = parsePositiveInt(req.query.page, 1, 500);
    const limit = parsePositiveInt(req.query.limit, 20, 100);
    const search = sanitizeText(req.query.search).toLowerCase();

    const adminPage = search ? 1 : page;
    const adminLimit = search ? 1000 : limit;
    const { data, error } = await supabase.auth.admin.listUsers({ page: adminPage, perPage: adminLimit });
    if (error) throw error;

    let users = data.users || [];
    if (search) {
        users = users.filter((user) => (
            user.email?.toLowerCase().includes(search) ||
            user.id.toLowerCase().includes(search)
        ));
    }

    const total = search ? users.length : (data.total || users.length);
    const pagedUsers = search ? users.slice((page - 1) * limit, page * limit) : users;
    const counts = await getResumeCountsByUser(pagedUsers.map((user) => user.id));

    res.json({
        users: pagedUsers.map((user) => shapeUser(user, counts.get(user.id))),
        pagination: {
            page,
            limit,
            total,
            lastPage: Math.max(1, Math.ceil(total / limit)),
        },
    });
}));

app.post('/admin/users', requireAdmin, asyncRoute(async (req, res) => {
    const email = sanitizeText(req.body.email).toLowerCase();
    const password = sanitizeText(req.body.password);
    const userMetadata = req.body.user_metadata && typeof req.body.user_metadata === 'object'
        ? req.body.user_metadata
        : {};

    if (!email || !email.includes('@')) {
        return res.status(400).json({ error: 'Valid email is required' });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { data, error } = await supabase.auth.admin.createUser({
        email,
        password,
        user_metadata: userMetadata,
        email_confirm: true,
    });

    if (error) throw error;
    res.status(201).json({ user: shapeUser(data.user) });
}));

app.patch('/admin/users/:id', requireAdmin, asyncRoute(async (req, res) => {
    const attributes = {};

    if (Object.prototype.hasOwnProperty.call(req.body, 'email')) {
        const email = sanitizeText(req.body.email).toLowerCase();
        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Valid email is required' });
        }
        attributes.email = email;
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'password')) {
        const password = sanitizeText(req.body.password);
        if (password && password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        if (password) attributes.password = password;
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'user_metadata')) {
        if (req.body.user_metadata && typeof req.body.user_metadata !== 'object') {
            return res.status(400).json({ error: 'user_metadata must be an object' });
        }
        attributes.user_metadata = req.body.user_metadata || {};
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'ban_duration')) {
        const banDuration = sanitizeText(req.body.ban_duration);
        attributes.ban_duration = banDuration || 'none';
    }

    if (Object.keys(attributes).length === 0) {
        return res.status(400).json({ error: 'Nothing to update' });
    }

    const { data, error } = await supabase.auth.admin.updateUserById(req.params.id, attributes);
    if (error) throw error;
    const counts = await getResumeCountsByUser([req.params.id]);
    res.json({ user: shapeUser(data.user, counts.get(req.params.id)) });
}));

app.delete('/admin/users/:id', requireAdmin, asyncRoute(async (req, res) => {
    const userId = req.params.id;
    if (userId === req.auth.user.id) {
        return res.status(400).json({ error: 'You cannot delete the admin account currently in use' });
    }

    const { data: userResumes, error: resumeError } = await supabase
        .from('resumes')
        .select('id, content')
        .eq('user_id', userId);

    if (resumeError) throw resumeError;

    const resumeIds = (userResumes || []).map((resume) => resume.id);
    const avatarFileNames = [...new Set(
        (userResumes || [])
            .map((resume) => extractAvatarFileNameFromUrl(resume?.content?.profile?.imageUrl))
            .filter(Boolean)
    )];

    if (resumeIds.length > 0) {
        const { error: unlinkError } = await supabase
            .from('resumes')
            .update({ parent_id: null })
            .in('parent_id', resumeIds);
        if (unlinkError) throw unlinkError;

        const { error: deleteResumesError } = await supabase
            .from('resumes')
            .delete()
            .in('id', resumeIds);
        if (deleteResumesError) throw deleteResumesError;
    }

    const avatarCleanup = [];
    for (const fileName of avatarFileNames) {
        avatarCleanup.push({ fileName, ...(await removeAvatarIfUnused(fileName, resumeIds)) });
    }

    const { error: deleteUserError } = await supabase.auth.admin.deleteUser(userId);
    if (deleteUserError) throw deleteUserError;

    res.json({ deleted: true, resumeCount: resumeIds.length, avatarCleanup });
}));

app.get('/admin/resumes', requireAdmin, asyncRoute(async (req, res) => {
    const page = parsePositiveInt(req.query.page, 1, 500);
    const limit = parsePositiveInt(req.query.limit, 20, 100);
    const search = sanitizeText(req.query.search);
    const type = sanitizeText(req.query.type, 'all');
    const userId = sanitizeText(req.query.userId);
    const from = (page - 1) * limit;
    const to = from + limit - 1;

    let query = supabase
        .from('resumes')
        .select('*', { count: 'exact' })
        .order('updated_at', { ascending: false })
        .range(from, to);

    if (search) query = query.ilike('title', `%${search.replace(/[%_]/g, '')}%`);
    if (userId) query = query.eq('user_id', userId);
    if (type === 'base') query = query.is('parent_id', null);
    if (type === 'ai') query = query.not('parent_id', 'is', null);

    const { data, error, count } = await query;
    if (error) throw error;

    res.json({
        resumes: await enrichResumes(data || []),
        pagination: {
            page,
            limit,
            total: count || 0,
            lastPage: Math.max(1, Math.ceil((count || 0) / limit)),
        },
    });
}));

app.post('/admin/resumes', requireAdmin, asyncRoute(async (req, res) => {
    const userId = sanitizeText(req.body.userId);
    const title = sanitizeText(req.body.title, 'Новое резюме');
    const parentId = sanitizeText(req.body.parent_id) || null;
    const content = req.body.content && typeof req.body.content === 'object' ? req.body.content : {};

    if (!userId) return res.status(400).json({ error: 'userId is required' });

    const { data: userData, error: userError } = await supabase.auth.admin.getUserById(userId);
    if (userError || !userData?.user) return res.status(404).json({ error: 'User not found' });

    if (parentId) {
        const { data: parentResume, error: parentError } = await supabase
            .from('resumes')
            .select('id, user_id')
            .eq('id', parentId)
            .single();

        if (parentError || !parentResume) return res.status(404).json({ error: 'Parent resume not found' });
        if (parentResume.user_id !== userId) {
            return res.status(400).json({ error: 'Parent resume must belong to the same user' });
        }
    }

    const { data, error } = await supabase
        .from('resumes')
        .insert({ user_id: userId, title, parent_id: parentId, content })
        .select('*')
        .single();

    if (error) throw error;
    const [resume] = await enrichResumes([data]);
    res.status(201).json({ resume });
}));

app.patch('/admin/resumes/:id', requireAdmin, asyncRoute(async (req, res) => {
    const update = {};

    if (Object.prototype.hasOwnProperty.call(req.body, 'title')) {
        update.title = sanitizeText(req.body.title, 'Без названия');
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'parent_id')) {
        const parentId = sanitizeText(req.body.parent_id) || null;
        if (parentId === req.params.id) {
            return res.status(400).json({ error: 'Resume cannot be its own parent' });
        }
        if (parentId) {
            const { data: currentResume, error: currentError } = await supabase
                .from('resumes')
                .select('id, user_id')
                .eq('id', req.params.id)
                .single();
            if (currentError || !currentResume) return res.status(404).json({ error: 'Resume not found' });

            const { data: parentResume, error: parentError } = await supabase
                .from('resumes')
                .select('id, user_id')
                .eq('id', parentId)
                .single();
            if (parentError || !parentResume) return res.status(404).json({ error: 'Parent resume not found' });
            if (parentResume.user_id !== currentResume.user_id) {
                return res.status(400).json({ error: 'Parent resume must belong to the same user' });
            }
        }
        update.parent_id = parentId;
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'content')) {
        if (!req.body.content || typeof req.body.content !== 'object' || Array.isArray(req.body.content)) {
            return res.status(400).json({ error: 'content must be a JSON object' });
        }
        update.content = req.body.content;
    }

    if (Object.keys(update).length === 0) {
        return res.status(400).json({ error: 'Nothing to update' });
    }

    update.updated_at = new Date().toISOString();

    const { data, error } = await supabase
        .from('resumes')
        .update(update)
        .eq('id', req.params.id)
        .select('*')
        .single();

    if (error) throw error;
    const [resume] = await enrichResumes([data]);
    res.json({ resume });
}));

app.delete('/admin/resumes/:id', requireAdmin, asyncRoute(async (req, res) => {
    res.json(await deleteResumeById(req.params.id));
}));

app.get('/admin/storage/avatars', requireAdmin, asyncRoute(async (req, res) => {
    const page = parsePositiveInt(req.query.page, 1, 500);
    const limit = parsePositiveInt(req.query.limit, 30, 100);
    const search = sanitizeText(req.query.search).toLowerCase();

    const [files, { data: resumes, error: resumesError }] = await Promise.all([
        listAvatarFiles(),
        supabase
            .from('resumes')
            .select('id, title, user_id, content'),
    ]);

    if (resumesError) throw resumesError;

    const filtered = (files || []).filter((file) => (
        !search ||
        file.name.toLowerCase().includes(search) ||
        file.baseName?.toLowerCase().includes(search)
    ));
    const paged = filtered.slice((page - 1) * limit, page * limit);

    const avatars = paged.map((file) => {
        const references = (resumes || []).filter((resume) => (
            extractAvatarFileNameFromUrl(resume?.content?.profile?.imageUrl) === file.name
        ));
        const { data: publicData } = supabase.storage.from(AVATAR_BUCKET).getPublicUrl(file.name);
        return {
            ...file,
            publicUrl: publicData.publicUrl,
            referenceCount: references.length,
            references: references.map((resume) => ({
                id: resume.id,
                title: resume.title,
                user_id: resume.user_id,
            })),
        };
    });

    res.json({
        avatars,
        pagination: {
            page,
            limit,
            total: filtered.length,
            lastPage: Math.max(1, Math.ceil(filtered.length / limit)),
        },
    });
}));

app.delete('/admin/storage/avatars/:path', requireAdmin, asyncRoute(async (req, res) => {
    const fileName = decodeURIComponent(req.params.path || '').trim();
    if (!fileName) return res.status(400).json({ error: 'Avatar path is required' });

    const { data: resumes, error } = await supabase
        .from('resumes')
        .select('id, title, user_id, content');

    if (error) throw error;

    const references = (resumes || []).filter((resume) => (
        extractAvatarFileNameFromUrl(resume?.content?.profile?.imageUrl) === fileName
    ));
    const force = req.query.force === '1';

    if (references.length > 0 && !force) {
        return res.status(409).json({
            error: 'Avatar is still referenced by resumes',
            references: references.map((resume) => ({ id: resume.id, title: resume.title, user_id: resume.user_id })),
        });
    }

    const { error: removeError } = await supabase.storage.from(AVATAR_BUCKET).remove([fileName]);
    if (removeError) throw removeError;
    res.json({ deleted: true, fileName, references: references.length });
}));

app.get('/admin/jobs', requireAdmin, asyncRoute(async (req, res) => {
    const { data: completedVersions, error } = await supabase
        .from('resumes')
        .select('*')
        .not('parent_id', 'is', null)
        .order('updated_at', { ascending: false })
        .limit(30);

    if (error) throw error;

    res.json({
        liveJobs: getLiveOptimizationJobs(),
        recentJobs: getRecentOptimizationJobs({ limit: 50 }),
        completedVersions: await enrichResumes(completedVersions || []),
    });
}));

app.get('/optimization-jobs', requireAuthenticatedUser, asyncRoute(async (req, res) => {
    const limit = parsePositiveInt(req.query.limit, 20, 50);
    res.json({
        jobs: getRecentOptimizationJobs({
            userId: req.auth.user.id,
            limit,
        }),
    });
}));

// Извлекает текст вакансии на сервере, чтобы браузер не упирался в 403/CORS у HH.ru
app.post('/job-text', requireAuthenticatedUser, jobTextRateLimit, asyncRoute(async (req, res) => {
    const { jobUrl } = req.body;

    if (!jobUrl) {
        return res.status(400).json({ error: 'Missing jobUrl' });
    }

    try {
        const result = await fetchJobTextFromUrl(jobUrl);
        res.json(result);
    } catch (err) {
        console.error('[JOB] Failed to fetch job text:', err.message);
        res.status(err.status || 422).json({ error: err.message || 'Не удалось получить текст вакансии' });
    }
}));

// Основной маршрут: принимает задачу и запускает в фоне
app.post('/optimize', requireAuthenticatedUser, optimizeRateLimit, asyncRoute(async (req, res) => {
    const { resumeId, jobText } = req.body;
    const cleanJobText = normalizeJobText(jobText);

    if (!resumeId || !cleanJobText) {
        return res.status(400).json({ error: 'Missing resumeId or jobText' });
    }

    if (cleanJobText.length < 80) {
        return res.status(400).json({ error: 'Job text is too short' });
    }

    const { data: resume, error: resumeError } = await supabase
        .from('resumes')
        .select('id, user_id')
        .eq('id', resumeId)
        .single();

    if (resumeError || !resume) {
        return res.status(404).json({ error: 'Resume not found' });
    }

    if (resume.user_id !== req.auth.user.id) {
        return res.status(403).json({ error: 'You can optimize only your own resumes' });
    }

    const job = createJobRecord(resumeId, req.auth.user.id);
    console.log(`[OPT] Accepted job ${job.id} for resume ${resumeId} (user=${req.auth.user.email || req.auth.user.id}, jobTextLength=${cleanJobText.length})`);

    // Запускаем тяжёлую работу В ФОНЕ — не ждём!
    processOptimization(resumeId, cleanJobText, { jobId: job.id, requestedBy: req.auth.user.id }).catch(err => {
        console.error('[OPT] Unhandled error:', err);
        updateJobRecord(job.id, {
            status: 'failed',
            failureReason: err.message || 'Unhandled optimization error',
            message: err.message || 'Unhandled optimization error',
        });
    });

    // Мгновенно возвращаем ответ клиенту
    res.status(202).json({
        jobId: job.id,
        status: 'processing_started',
        message: 'Оптимизация запущена. Результат появится в дашборде через несколько минут.'
    });
}));

app.use((err, req, res, next) => {
    console.error('[SERVER] Unhandled route error:', err);
    if (res.headersSent) return next(err);
    const status = err.status || err.statusCode || 500;
    res.status(status).json({
        error: status >= 500 ? 'Internal server error' : (err.message || 'Request failed'),
    });
});

// --- START SERVER ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Resume Optimizer Server running on port ${PORT}`);
});

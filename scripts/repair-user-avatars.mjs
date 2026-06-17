#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

const AVATAR_BUCKET = 'avatars';
const AVATAR_URL_MARKER = '/storage/v1/object/public/avatars/';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

function parseArgs(argv) {
  const parsed = {
    userId: '',
    dryRun: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--dry-run') {
      parsed.dryRun = true;
      continue;
    }
    if (token === '--help' || token === '-h') {
      parsed.help = true;
      continue;
    }
    if (token === '--user-id') {
      parsed.userId = (argv[i + 1] || '').trim();
      i += 1;
    }
  }

  return parsed;
}

function printUsage() {
  console.log('Usage: node server/scripts/repair-user-avatars.mjs --user-id <uuid> [--dry-run]');
  console.log('Example: node server/scripts/repair-user-avatars.mjs --user-id a9db35c9-c36a-45de-84e9-f0738ed54606 --dry-run');
}

function extractAvatarFileNameFromUrl(imageUrl) {
  if (!imageUrl || typeof imageUrl !== 'string') return '';
  const trimmedUrl = imageUrl.trim();
  if (!trimmedUrl) return '';

  try {
    const parsed = new URL(trimmedUrl);
    const markerIndex = parsed.pathname.indexOf(AVATAR_URL_MARKER);
    if (markerIndex !== -1) {
      return decodeURIComponent(
        parsed.pathname.slice(markerIndex + AVATAR_URL_MARKER.length),
      ).trim();
    }
    const pathParts = parsed.pathname.split('/');
    return decodeURIComponent(pathParts[pathParts.length - 1] || '').trim();
  } catch {
    const cleanPath = trimmedUrl.split('?')[0].split('#')[0];
    const pathParts = cleanPath.split('/');
    return decodeURIComponent(pathParts[pathParts.length - 1] || '').trim();
  }
}

function sortByLatestUpdated(a, b) {
  const aTime = Date.parse(a.updated_at || a.created_at || 0);
  const bTime = Date.parse(b.updated_at || b.created_at || 0);
  return bTime - aTime;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value || '');
}

async function listAllAvatarFiles(supabase) {
  const pageSize = 100;
  const allFiles = [];
  let offset = 0;

  while (true) {
    const { data, error } = await supabase.storage
      .from(AVATAR_BUCKET)
      .list('', {
        limit: pageSize,
        offset,
        sortBy: { column: 'updated_at', order: 'desc' },
      });

    if (error) throw error;
    allFiles.push(...(data || []));

    if (!data || data.length < pageSize) break;
    offset += pageSize;

    if (offset > 10000) break;
  }

  return allFiles;
}

function pickLatestUserAvatarFile(files, userId) {
  return files
    .filter((file) => (
      file?.name
      && file.name !== '.emptyFolderPlaceholder'
      && ((file.name.startsWith(`${userId}-`)) || (file.name.startsWith(`${userId} -`)))
    ))
    .sort(sortByLatestUpdated)[0] || null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printUsage();
    process.exit(0);
  }

  if (!args.userId) {
    console.error('ERROR: --user-id is required');
    printUsage();
    process.exit(1);
  }

  if (!isUuid(args.userId)) {
    console.error('ERROR: --user-id must be a valid UUID');
    process.exit(1);
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in server/.env');
    process.exit(1);
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey);
  const modeLabel = args.dryRun ? 'DRY-RUN' : 'EXECUTE';
  console.log(`[repair-user-avatars] mode=${modeLabel}, user=${args.userId}`);

  const { data: resumes, error: resumesError } = await supabase
    .from('resumes')
    .select('id, title, content')
    .eq('user_id', args.userId);

  if (resumesError) {
    console.error('ERROR: failed to fetch resumes:', resumesError.message);
    process.exit(1);
  }

  if (!resumes || resumes.length === 0) {
    console.log('No resumes found for this user. Nothing to repair.');
    process.exit(0);
  }

  const avatarFiles = await listAllAvatarFiles(supabase);
  const avatarFileSet = new Set(avatarFiles.map((file) => file.name));
  const fallbackFile = pickLatestUserAvatarFile(avatarFiles, args.userId);
  const fallbackPublicUrl = fallbackFile
    ? supabase.storage.from(AVATAR_BUCKET).getPublicUrl(fallbackFile.name).data.publicUrl
    : '';

  const stats = {
    total: resumes.length,
    withImage: 0,
    broken: 0,
    repaired: 0,
    skippedNoImage: 0,
    skippedValid: 0,
    skippedNoFallback: 0,
    failed: 0,
  };

  for (const resume of resumes) {
    const currentImageUrl = resume?.content?.profile?.imageUrl || '';
    if (!currentImageUrl) {
      stats.skippedNoImage += 1;
      continue;
    }

    stats.withImage += 1;
    const currentFileName = extractAvatarFileNameFromUrl(currentImageUrl);
    const fileExists = currentFileName && avatarFileSet.has(currentFileName);
    if (fileExists) {
      stats.skippedValid += 1;
      continue;
    }

    stats.broken += 1;
    if (!fallbackPublicUrl) {
      console.warn(`[skip:no-fallback] resume=${resume.id} title="${resume.title}"`);
      stats.skippedNoFallback += 1;
      continue;
    }

    const updatedContent = {
      ...(resume.content || {}),
      profile: {
        ...(resume?.content?.profile || {}),
        imageUrl: fallbackPublicUrl,
      },
    };

    if (args.dryRun) {
      console.log(
        `[dry-run] repair resume=${resume.id} title="${resume.title}" `
        + `from="${currentFileName || 'invalid-url'}" to="${fallbackFile.name}"`,
      );
      stats.repaired += 1;
      continue;
    }

    const { error: updateError } = await supabase
      .from('resumes')
      .update({ content: updatedContent })
      .eq('id', resume.id)
      .eq('user_id', args.userId);

    if (updateError) {
      stats.failed += 1;
      console.error(`[failed] resume=${resume.id}: ${updateError.message}`);
      continue;
    }

    stats.repaired += 1;
    console.log(
      `[repaired] resume=${resume.id} title="${resume.title}" `
      + `from="${currentFileName || 'invalid-url'}" to="${fallbackFile.name}"`,
    );
  }

  console.log('\n=== Repair Summary ===');
  console.log(`mode: ${modeLabel}`);
  console.log(`user: ${args.userId}`);
  console.log(`total resumes: ${stats.total}`);
  console.log(`resumes with image: ${stats.withImage}`);
  console.log(`broken image refs: ${stats.broken}`);
  console.log(`repaired: ${stats.repaired}`);
  console.log(`skipped (no image): ${stats.skippedNoImage}`);
  console.log(`skipped (valid refs): ${stats.skippedValid}`);
  console.log(`skipped (no fallback): ${stats.skippedNoFallback}`);
  console.log(`failed updates: ${stats.failed}`);
  if (fallbackFile) {
    console.log(`fallback avatar: ${fallbackFile.name}`);
  } else {
    console.log('fallback avatar: <not found>');
  }
}

main().catch((error) => {
  console.error('FATAL:', error);
  process.exit(1);
});


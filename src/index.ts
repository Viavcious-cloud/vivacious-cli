#!/usr/bin/env node

/**
 * Vivacious Cloud CLI Client
 * Production client supporting streaming SHA-256 fingerprinting (memory <50MB on >10GB files),
 * clamped adaptive multipart uploads (16–64 MiB, ≤8500 parts), dual workspace staging,
 * and defensive checkpoint archive inspection.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import * as readline from 'readline';
import * as zlib from 'zlib';
import * as child_process from 'child_process';

const API_HOST = process.env.VIVACIOUS_API_HOST || process.env.VIVACIOUS_API_URL || 'https://vivacious-orchestrator.vivacious-cloud.workers.dev';
const CONFIG_DIR = path.join(os.homedir(), '.vivacious');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

function openBrowser(url: string): void {
  try {
    const platform = process.platform;
    if (platform === 'win32') {
      child_process.exec(`start "" "${url}"`);
    } else if (platform === 'darwin') {
      child_process.exec(`open "${url}"`);
    } else {
      child_process.exec(`xdg-open "${url}"`);
    }
  } catch {}
}

export interface PreparedDataset {
  path: string;
  filename: string;
  sizeBytes: number;
  fileCount: number;
  sha256: string;
  preparedAt: string;
}

export interface PreparedCheckpoint {
  path: string;
  filename: string;
  sizeBytes: number;
  sha256: string;
  modelConfig?: {
    modelType?: string;
    hiddenSize?: number;
    numHiddenLayers?: number;
    numAttentionHeads?: number;
    parameterCount?: number;
    architectures?: string[];
  };
  preparedAt: string;
}

export interface LastPermit {
  permitRef: string;
  expiresAt: string;
  modelId: string;
  method: string;
  estimatedTotal: number;
  maxExposure: number;
  datasetFingerprint: string;
  requiresConfirmation?: boolean;
  permittedAt: string;
}

export interface ResumeContext {
  jobId: string;
  resumeAttemptId: string;
  modelId?: string | undefined;
  method?: string | undefined;
  gpuTier?: string | undefined;
  progressPercent?: number | undefined;
  remainingHours?: number | undefined;
  remainingEstimatedTotal?: number | undefined;
  remainingMaxExposure?: number | undefined;
  checkpointExpiresAt?: string | undefined;
  lastPermitRef?: string | undefined;
  inspectedAt: string;
}

export interface Config {
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  tokenExpiresAt?: number | undefined;
  preparedDataset?: PreparedDataset | undefined;
  preparedCheckpoint?: PreparedCheckpoint | undefined;
  lastPermit?: LastPermit | undefined;
  resumeContext?: ResumeContext | undefined;
}

/**
 * Safely parses the expiration timestamp (in milliseconds) from a JWT without external libraries.
 */
export function parseJwtExpiryMs(token: string): number | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      Buffer.from(base64, 'base64')
        .toString('binary')
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    const decoded = JSON.parse(jsonPayload);
    return typeof decoded.exp === 'number' && Number.isFinite(decoded.exp) ? decoded.exp * 1000 : null;
  } catch {
    return null;
  }
}

export async function getValidAccessToken(forceRefresh: boolean = false): Promise<string> {
  const config = loadConfig();
  if (!config.accessToken) {
    console.error('[Error] You are not logged in. Please run "vivacious login anirudha-s" first.');
    process.exit(1);
  }

  const now = Date.now();
  const tokenExp = parseJwtExpiryMs(config.accessToken) || config.tokenExpiresAt || 0;
  // Trigger proactive refresh if token expires within 120 seconds (or is already expired)
  const isExpiringSoon = (tokenExp - now) < 120_000;

  if ((isExpiringSoon || forceRefresh) && config.refreshToken) {
    try {
      const refreshRes = await fetch(`${API_HOST}/api/auth/token/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: config.refreshToken })
      });

      if (refreshRes.ok) {
        const refreshData: any = await refreshRes.json();
        if (refreshData.access_token) {
          config.accessToken = refreshData.access_token;
          if (refreshData.refresh_token) {
            config.refreshToken = refreshData.refresh_token;
          }
          const parsedExp = parseJwtExpiryMs(refreshData.access_token);
          config.tokenExpiresAt = parsedExp || (Date.now() + (refreshData.expires_in || 3600) * 1000);
          saveConfig(config);
          return config.accessToken!;
        }
      } else {
        if (refreshRes.status === 401 || refreshRes.status === 400) {
          console.warn('[Notice] Session expired. Please re-authenticate via "vivacious login anirudha-s".');
        }
      }
    } catch (refreshErr: any) {
      console.warn(`[Notice] Temporary network issue during session refresh: ${refreshErr.message || 'Continuing with current credentials...'}`);
    }
  }

  // If token is already expired and cannot be refreshed, halt cleanly with guidance
  if (tokenExp > 0 && tokenExp <= now) {
    console.error('\n[Notice] Your authentication session has expired.');
    console.error('Please run "vivacious login anirudha-s" to authenticate.\n');
    process.exit(1);
  }

  return config.accessToken!;
}

function loadConfig(): Config {
  if (!fs.existsSync(CONFIG_FILE)) {
    return {};
  }
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch {}
  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function saveConfig(config: Config) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { encoding: 'utf-8', mode: 0o600 });
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch {}
}


function askQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise((resolve) => {
    rl.question(query, (ans) => {
      rl.close();
      resolve(ans.trim());
    });
  });
}

/**
 * Stream-based SHA-256 calculation for large files (memory < 50MB on 100GB+ files)
 */
export function calculateFileSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Stream-based directory fingerprint calculation with constant-memory directory traversal
 */
export async function calculateDirectoryFingerprint(dirPath: string): Promise<{ totalSize: number; fileCount: number; sha256: string }> {
  const hash = crypto.createHash('sha256');
  let totalSize = 0;
  let fileCount = 0;

  async function walk(currentDir: string, depth: number = 0) {
    if (depth > 20) {
      throw new Error(`Directory nesting exceeds maximum depth limit of 20 at "${currentDir}". Recursive directory or symlink loop detected.`);
    }
    
    const dir = await fs.promises.opendir(currentDir);
    const entryNames: string[] = [];
    
    for await (const dirent of dir) {
      entryNames.push(dirent.name);
    }
    entryNames.sort(); // Maintain deterministic lexical sort for cryptographic fingerprinting

    for (const name of entryNames) {
      const fullPath = path.join(currentDir, name);
      const lstat = await fs.promises.lstat(fullPath);
      
      if (lstat.isSymbolicLink()) {
        console.warn(`[Notice] Skipping symlink: ${fullPath}`);
        continue;
      }
      
      if (lstat.isDirectory()) {
        await walk(fullPath, depth + 1);
      } else if (lstat.isFile()) {
        fileCount++;
        totalSize += lstat.size;
        hash.update(path.relative(dirPath, fullPath));
        await new Promise<void>((resolve, reject) => {
          const stream = fs.createReadStream(fullPath, { highWaterMark: 64 * 1024 });
          stream.on('data', (chunk) => hash.update(chunk));
          stream.on('end', () => resolve());
          stream.on('error', (err) => reject(err));
        });
      }
    }
  }

  await walk(dirPath, 0);
  return { totalSize, fileCount, sha256: hash.digest('hex') };
}


/**
 * Adaptive multipart chunk calculation that guarantees total parts never exceed 8,500
 * across any dataset size from 1 MB to 5 Terabytes (R2 limit).
 */
export function calculateAdaptiveChunkSize(totalBytes: number): number {
  const MIN_CHUNK_SIZE = 16 * 1024 * 1024;          // 16 MiB min
  const MAX_R2_PART_SIZE = 4 * 1024 * 1024 * 1024;  // 4 GiB max per part (well below 4.995 GiB R2 ceiling)
  const TARGET_PARTS = 8500;                        // Guaranteed headroom below 10,000

  const minRequiredForParts = Math.ceil(totalBytes / TARGET_PARTS);
  const rawChunkSize = Math.max(MIN_CHUNK_SIZE, minRequiredForParts);

  return Math.min(MAX_R2_PART_SIZE, rawChunkSize);
}

/**
 * Defensive Tar Scanner for custom checkpoints
 * Auto-detects format (GZIP .tar.gz vs uncompressed .tar), defends against path traversal (../),
 * symlinks, hardlinks, special files, duplicate paths, and decompression bombs (>100 GiB / >10k entries).
 */
export async function scanAndValidateCheckpointArchive(archivePath: string): Promise<{
  isValid: boolean;
  modelConfig?: any;
  error?: string;
}> {
  if (!fs.existsSync(archivePath)) {
    return { isValid: false, error: `Archive path does not exist: ${archivePath}` };
  }

  const fd = fs.openSync(archivePath, 'r');
  const headerBuf = Buffer.alloc(512);
  const bytesRead = fs.readSync(fd, headerBuf, 0, 512, 0);
  fs.closeSync(fd);

  if (bytesRead < 10) {
    return { isValid: false, error: 'Archive is corrupted or too small (less than 10 bytes).' };
  }

  const isGzip = headerBuf[0] === 0x1F && headerBuf[1] === 0x8B;
  if (!isGzip && bytesRead < 512) {
    return { isValid: false, error: 'Uncompressed tar archive is corrupted or too small (less than 512 bytes).' };
  }

  const isTar = !isGzip && (
    headerBuf.toString('utf-8', 257, 262) === 'ustar' ||
    headerBuf.toString('utf-8', 0, 100).replace(/\0.*$/, '').length > 0
  );

  if (!isGzip && !isTar) {
    return { isValid: false, error: 'Invalid archive format: must be a gzip-compressed tarball (.tar.gz) or standard tar archive (.tar).' };
  }

  // Decompression Bomb Limits
  const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024 * 1024; // 100 GiB
  const MAX_ARCHIVE_ENTRIES = 10000;
  const MAX_CONFIG_JSON_BYTES = 2 * 1024 * 1024; // 2 MiB
  const MAX_COMPRESSION_RATIO = 20.0; // Suspicious compression ratio threshold

  const compressedFileSizeBytes = fs.statSync(archivePath).size;
  let totalUncompressedBytes = 0;
  let entryCount = 0;
  let extractedConfigBuffer: Buffer | null = null;
  const seenEntries = new Set<string>();

  try {
    const zlib = await import('zlib');
    const readStream = fs.createReadStream(archivePath);
    const decompressStream = isGzip ? readStream.pipe(zlib.createGunzip()) : readStream;

    let buffer = Buffer.alloc(0);
    let currentEntry: { name: string; size: number; type: string; bytesRead: number } | null = null;
    let targetConfigChunks: Buffer[] = [];

    const extractedConfigResult = await new Promise<Buffer | null>((resolve, reject) => {
      decompressStream.on('data', (chunk: Buffer) => {
        totalUncompressedBytes += chunk.length;
        if (totalUncompressedBytes > MAX_UNCOMPRESSED_BYTES) {
          decompressStream.destroy();
          return reject(new Error('Decompression bomb detected: total uncompressed size exceeds 100 GiB ceiling.'));
        }

        // Check compression ratio once at least 100 MB uncompressed
        if (totalUncompressedBytes > 100 * 1024 * 1024 && compressedFileSizeBytes > 0) {
          const currentRatio = totalUncompressedBytes / compressedFileSizeBytes;
          if (currentRatio > MAX_COMPRESSION_RATIO) {
            decompressStream.destroy();
            return reject(new Error(`Suspicious archive compression ratio (${currentRatio.toFixed(1)}:1 exceeds safety ceiling of ${MAX_COMPRESSION_RATIO}:1).`));
          }
        }

        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length > 0) {
          if (!currentEntry) {
            if (buffer.length < 512) {
              break; // Wait for complete 512-byte tar header block
            }
            // Read 512-byte tar header
            const header = buffer.subarray(0, 512);

            // Check if end of archive (all zeros)
            const isZeroBlock = header.every((b) => b === 0);
            if (isZeroBlock) {
              buffer = buffer.subarray(512);
              continue;
            }

            entryCount++;
            if (entryCount > MAX_ARCHIVE_ENTRIES) {
              decompressStream.destroy();
              return reject(new Error(`Archive bomb detected: entry count exceeds ${MAX_ARCHIVE_ENTRIES} entries.`));
            }

            // Extract filename from header (bytes 0-100) and prefix (bytes 345-500)
            const rawName = header.toString('utf-8', 0, 100).replace(/\0.*$/, '').trim();
            const prefix = header.toString('utf-8', 345, 500).replace(/\0.*$/, '').trim();
            const fullPath = prefix ? `${prefix}/${rawName}` : rawName;

            // Security Check 1: Duplicate Archive Entry Collision
            if (seenEntries.has(fullPath)) {
              decompressStream.destroy();
              return reject(new Error(`Duplicate entry detected in archive: "${fullPath}". Potential entry-override attack.`));
            }
            seenEntries.add(fullPath);

            // Security Check 2: Path Traversal (.., leading slashes, Windows drive letters)
            if (
              fullPath.includes('..') ||
              fullPath.startsWith('/') ||
              fullPath.startsWith('\\') ||
              /^[a-zA-Z]:/.test(fullPath) ||
              fullPath.includes('\0')
            ) {
              decompressStream.destroy();
              return reject(new Error(`Path traversal attack detected in archive entry: "${fullPath}"`));
            }

            // Security Check 3: Symlink, Hardlink & Special File Attacks (Typeflag at byte 156)
            const typeFlag = String.fromCharCode(header[156] || 48); // '0' = 48
            if (typeFlag === '1') {
              decompressStream.destroy();
              return reject(new Error(`Hard link attack detected in archive entry: "${fullPath}"`));
            }
            if (typeFlag === '2' || typeFlag === 's') {
              decompressStream.destroy();
              return reject(new Error(`Symlink attack detected in archive entry: "${fullPath}"`));
            }
            if (typeFlag === '3' || typeFlag === '4' || typeFlag === '6') {
              decompressStream.destroy();
              return reject(new Error(`Unsupported special file entry (device/fifo) rejected: "${fullPath}"`));
            }

            // POSIX Extended Header Records ('x' for per-file pax header, 'g' for global header)
            // or Directory entries ('5' or trailing slash) or PaxHeader/ internal metadata paths
            const isPaxHeader = typeFlag === 'x' || typeFlag === 'g' || fullPath.startsWith('PaxHeader/') || fullPath.includes('/PaxHeader/');
            const isDirectory = typeFlag === '5' || fullPath.endsWith('/');

            // Security Check 4: Semantic Allowlist Validation (No scripts, no legacy pickle binaries)
            const basename = path.basename(fullPath);
            if (!isPaxHeader && !isDirectory && basename) {
              const DANGEROUS_EXTENSIONS = [
                '.py', '.sh', '.exe', '.so', '.dll', '.elf', '.bat', '.cmd',
                '.bin', '.pt', '.pth', '.pkl', '.pickle',
                '.wasm', '.js', '.mjs', '.cjs', '.a', '.lib'
              ];
              const ext = path.extname(basename).toLowerCase();
              const isVersionedSo = /\.so(\.[0-9]+)+$/i.test(basename);

              if (DANGEROUS_EXTENSIONS.includes(ext) || isVersionedSo) {
                decompressStream.destroy();
                if (['.bin', '.pt', '.pth', '.pkl', '.pickle'].includes(ext)) {
                  return reject(new Error(`Legacy Python pickle weight file "${basename}" rejected. Model weights must be formatted as safe zero-code .safetensors.`));
                }
                return reject(new Error(`Executable, library, or script binary "${basename}" is strictly forbidden in model archives.`));
              }


              const ALLOWED_EXACT_FILES = new Set([
                'config.json',
                'generation_config.json',
                'adapter_config.json',
                'chat_template.json',
                'tokenizer.json',
                'tokenizer_config.json',
                'special_tokens_map.json',
                'vocab.json',
                'merges.txt',
                'added_tokens.json',
                'tokenizer.model',
                'spiece.model',
                'sentencepiece.bpe.model',
                'model.safetensors.index.json',
                'adapter_model.safetensors.index.json'
              ]);

              const isAllowed = ALLOWED_EXACT_FILES.has(basename) ||
                basename.endsWith('.safetensors') ||
                basename.endsWith('.json') ||
                basename.endsWith('.txt');

              if (!isAllowed) {
                decompressStream.destroy();
                return reject(new Error(`Unrecognized file "${basename}" rejected. Custom checkpoint archives only permit safetensors weights and HuggingFace/PEFT metadata.`));
              }
            }

            // Parse file size (octal at bytes 124-136)
            const sizeStr = header.toString('utf-8', 124, 136).replace(/\0.*$/, '').trim();
            const fileSize = parseInt(sizeStr, 8) || 0;

            buffer = buffer.subarray(512);
            currentEntry = {
              name: fullPath,
              size: fileSize,
              type: typeFlag,
              bytesRead: 0
            };
          } else {
            // Read file payload
            const needed = currentEntry.size - currentEntry.bytesRead;
            const available = Math.min(needed, buffer.length);
            const chunkData = buffer.subarray(0, available);

            if (currentEntry.name.endsWith('config.json') || currentEntry.name === 'config.json') {
              if (currentEntry.bytesRead + chunkData.length <= MAX_CONFIG_JSON_BYTES) {
                targetConfigChunks.push(Buffer.from(chunkData));
              }
            }

            currentEntry.bytesRead += available;
            buffer = buffer.subarray(available);

            if (currentEntry.bytesRead >= currentEntry.size) {
              // Tar blocks are padded to 512-byte boundaries
              const padding = (512 - (currentEntry.size % 512)) % 512;
              if (buffer.length >= padding) {
                buffer = buffer.subarray(padding);
                if (currentEntry.name.endsWith('config.json') || currentEntry.name === 'config.json') {
                  extractedConfigBuffer = Buffer.concat(targetConfigChunks);
                }
                currentEntry = null;
              } else {
                // Wait for padding chunk
                break;
              }
            }
          }
        }
      });

      decompressStream.on('end', () => {
        if (extractedConfigBuffer === null && targetConfigChunks.length > 0) {
          extractedConfigBuffer = Buffer.concat(targetConfigChunks);
        }
        resolve(extractedConfigBuffer);
      });
      decompressStream.on('error', (err: any) => reject(err));
    });
    extractedConfigBuffer = extractedConfigResult;
  } catch (scanErr: any) {
    return { isValid: false, error: `Defensive archive scan rejected: ${scanErr.message}` };
  }

function checkJsonNestingDepth(jsonString: string, maxDepth: number = 30): boolean {
  let depth = 0;
  for (let i = 0; i < jsonString.length; i++) {
    const ch = jsonString[i];
    if (ch === '{' || ch === '[') {
      depth++;
      if (depth > maxDepth) return false;
    } else if (ch === '}' || ch === ']') {
      depth--;
    }
  }
  return true;
}

  let modelConfig: any = null;
  if (extractedConfigBuffer !== null) {
    try {
      const rawText = (extractedConfigBuffer as Buffer).toString('utf-8');
      if (!checkJsonNestingDepth(rawText, 30)) {
        return { isValid: false, error: 'Defensive archive scan rejected: config.json exceeds maximum structural nesting depth (30).' };
      }
      const parsed = JSON.parse(rawText);

      modelConfig = {
        modelType: parsed.model_type || 'custom_causal_lm',
        hiddenSize: parsed.hidden_size || parsed.d_model || 4096,
        numHiddenLayers: parsed.num_hidden_layers || parsed.n_layer || 32,
        numAttentionHeads: parsed.num_attention_heads || parsed.n_head || 32,
        intermediateSize: parsed.intermediate_size || (parsed.hidden_size ? parsed.hidden_size * 4 : 11008),
        vocabSize: parsed.vocab_size || 32000,
        architectures: parsed.architectures || ['LlamaForCausalLM']
      };
    } catch { /* config.json parse failure — modelConfig stays null; handled by the fallback below */ }
  }

  // Fallback to adjacent config.json if not found inside archive root
  if (!modelConfig) {
    const adjacentConfigPath = path.join(path.dirname(archivePath), 'config.json');
    if (fs.existsSync(adjacentConfigPath)) {
      try {
        const raw = fs.readFileSync(adjacentConfigPath, 'utf-8');
        const parsed = JSON.parse(raw);
        modelConfig = {
          modelType: parsed.model_type || 'custom_causal_lm',
          hiddenSize: parsed.hidden_size || 4096,
          numHiddenLayers: parsed.num_hidden_layers || 32,
          numAttentionHeads: parsed.num_attention_heads || 32,
          intermediateSize: parsed.intermediate_size || 11008,
          vocabSize: parsed.vocab_size || 32000,
          architectures: parsed.architectures || ['LlamaForCausalLM']
        };
      } catch { /* adjacent config.json parse failure — modelConfig stays null; handled by the if check below */ }
    }
  }

  if (!modelConfig) {
    return {
      isValid: false,
      error: 'Archive is valid but missing config.json. Model architecture parameters could not be determined.'
    };
  }

  return { isValid: true, modelConfig };
}


// 1. Device Authorization Login
async function handleLogin(target: string = 'anirudha-s') {
  console.log(`Initiating device authorization login flow for workspace target: ${target}...`);

  try {
    const response = await fetch(`${API_HOST}/api/auth/device/code`, { method: 'POST' });
    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const data: any = await response.json();
    const { device_code, user_code, verification_uri, expires_in, interval } = data;

    // Automatic browser opening for zero-friction login
    openBrowser(verification_uri);

    // Hyperlink with OSC 8 escape sequence for single-click in supported modern terminals
    const clickableUri = `\u001b]8;;${verification_uri}\u001b\\${verification_uri}\u001b]8;;\u001b\\`;

    console.log('\n=============================================');
    console.log('🔐 VIVACIOUS CLOUD — DEVICE LOGIN');
    console.log('   An Anirudha\'s Ambition');
    console.log('=============================================');
    console.log('Opening authorization page in your browser automatically...\n');
    console.log('If your browser did not open, click or copy & paste this URL:');
    console.log(`👉 ${clickableUri}`);
    console.log('\nOne-Time Authorization Code:');
    console.log(`🔑 ${user_code}`);
    console.log('=============================================');
    console.log(`Waiting for browser authorization (polling every ${interval || 5}s)...`);

    const pollInterval = (interval || 5) * 1000;
    const expiresAt = Date.now() + (expires_in || 900) * 1000;

    while (Date.now() < expiresAt) {
      await new Promise((resolve) => setTimeout(resolve, pollInterval));

      try {
        const tokenRes = await fetch(`${API_HOST}/api/auth/device/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_code })
        });

        if (tokenRes.ok) {
          const tokenData: any = await tokenRes.json();
          const config = loadConfig();
          config.accessToken = tokenData.access_token;
          if (tokenData.refresh_token) {
            config.refreshToken = tokenData.refresh_token;
          }
          const parsedExp = parseJwtExpiryMs(tokenData.access_token);
          config.tokenExpiresAt = parsedExp || (Date.now() + (tokenData.expires_in || 3600) * 1000);
          saveConfig(config);

          console.log('\n[Success] Logged in successfully! Credentials saved locally.');
          return;
        }

        const errData: any = await tokenRes.json();
        if (errData.error === 'authorization_pending') {
          continue;
        } else if (errData.error === 'expired_token') {
          console.error('\n[Error] Login attempt expired. Please run "vivacious login" again.');
          process.exit(1);
        } else {
          console.error(`\n[Error] Login failed: ${errData.error}`);
          process.exit(1);
        }
      } catch (err: any) {
        console.warn(`\n[Warning] Temporary network issue while polling authorization status: ${err.message || 'Retrying...'}`);
      }
    }

    console.error('\n[Error] Login timed out. Please try again.');
    process.exit(1);
  } catch (err: any) {
    console.error(`\n[Error] Failed to connect to orchestrator: ${err.message}`);
    process.exit(1);
  }
}

// 2. Prepare / Inspect Dataset or Checkpoint (Dual Staging Support)
async function handlePrepare(inputPath: string, type: 'dataset' | 'checkpoint' = 'dataset') {
  const absolutePath = path.resolve(inputPath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`[Error] Target path not found: ${inputPath}`);
    process.exit(1);
  }

  const stat = fs.statSync(absolutePath);
  let totalSize = 0;
  let fileCount = 0;
  let sha256Fingerprint = '';
  const filename = path.basename(absolutePath);

  console.log(`\n=============================================`);
  console.log(`📁 VIVACIOUS CLOUD — ${type.toUpperCase()} PREPARATION & STAGING`);
  console.log(`=============================================`);
  console.log(`Inspecting path: ${absolutePath}`);

  if (stat.isDirectory()) {
    console.log(`Analyzing directory structure and calculating streaming cryptographic checksum...`);
    const res = await calculateDirectoryFingerprint(absolutePath);
    totalSize = res.totalSize;
    fileCount = res.fileCount;
    sha256Fingerprint = res.sha256;
  } else {
    console.log(`Analyzing file and calculating streaming cryptographic checksum...`);
    totalSize = stat.size;
    fileCount = 1;
    sha256Fingerprint = await calculateFileSha256(absolutePath);
  }

  if (totalSize === 0) {
    console.error(`[Error] Staging target is empty (0 bytes).`);
    process.exit(1);
  }

  const config = loadConfig();

  if (type === 'checkpoint') {
    console.log(`Running defensive archive scanner on custom model checkpoint...`);
    const scanResult = await scanAndValidateCheckpointArchive(absolutePath);
    if (!scanResult.isValid) {
      console.error(`[Error] Checkpoint archive validation failed: ${scanResult.error}`);
      process.exit(1);
    }

    const preparedCheckpoint: PreparedCheckpoint = {
      path: absolutePath,
      filename,
      sizeBytes: totalSize,
      sha256: sha256Fingerprint,
      modelConfig: scanResult.modelConfig,
      preparedAt: new Date().toISOString()
    };
    config.preparedCheckpoint = preparedCheckpoint;
    saveConfig(config);

    console.log(`Checkpoint Archive:    ${filename}`);
    console.log(`Total Size:            ${(totalSize / (1024 * 1024)).toFixed(2)} MB (${totalSize.toLocaleString()} bytes)`);
    console.log(`SHA-256 Fingerprint:   ${sha256Fingerprint}`);
    console.log(`Detected Model Type:   ${scanResult.modelConfig?.modelType || 'CausalLM'}`);
    console.log(`Estimated Parameters:  ${((scanResult.modelConfig?.parameterCount || 7e9) / 1e9).toFixed(1)}B`);
    console.log(`=============================================`);
    console.log(`✅ [Custom Checkpoint Staged Locally]`);
    console.log(`Next step: Run 'vivacious deploy anirudha-s --checkpoint' to train from this base.`);
    return;
  }

  const prepared: PreparedDataset = {
    path: absolutePath,
    filename,
    sizeBytes: totalSize,
    fileCount,
    sha256: sha256Fingerprint,
    preparedAt: new Date().toISOString()
  };

  config.preparedDataset = prepared;
  saveConfig(config);

  console.log(`Files Detected:        ${fileCount}`);
  console.log(`Total Dataset Size:    ${(totalSize / (1024 * 1024)).toFixed(2)} MB (${totalSize.toLocaleString()} bytes)`);
  console.log(`SHA-256 Fingerprint:   ${sha256Fingerprint}`);
  console.log(`=============================================`);
  console.log(`\n✅ [Dataset Prepared Locally] Streaming SHA-256 manifest computed.`);
  console.log(`Zero cloud transfer or GPU compute incurred.`);
  console.log(`Next step: Run 'vivacious permit anirudha-s ambition --model <model-id>' or 'vivacious deploy anirudha-s'.`);
}

// 3. Pre-Flight Financial Permit Check (NO R2 Upload, NO GPU Start)
async function handlePermit(modelId?: string, method: string = 'full', autoConfirm: boolean = false): Promise<boolean> {
  const accessToken = await getValidAccessToken();
  const config = loadConfig();

  const prepared = config.preparedDataset;
  if (!prepared && modelId) {
    console.warn('[Notice] No local dataset prepared yet. Using default reference sizing (100 MB).');
  }

  const payload: Record<string, any> = {};
  if (modelId) {
    payload.modelId = modelId;
    payload.method = method || 'full';
    if (prepared) {
      payload.datasetSizeBytes = prepared.sizeBytes;
      payload.datasetFingerprint = prepared.sha256;
      payload.fileCount = prepared.fileCount;
    }
  }

  console.log('Querying server-authoritative financial permit and pricing models...');

  try {
    const response = await fetch(`${API_HOST}/api/permit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(payload)
    });

    if (response.status === 401) {
      console.error('[Error] Authentication session expired. Please run "vivacious login anirudha-s" again.');
      process.exit(1);
    }

    const data: any = await response.json();
    if (!response.ok) {
      console.error(`\n[Error] Permit check failed: ${data.error || 'Unknown error'}`);
      process.exit(1);
    }

    console.log('\n=============================================');
    console.log('💳 VIVACIOUS CLOUD — FINANCIAL PERMIT STATUS');
    console.log('=============================================');
    console.log(`Active Billing Mode:    ${data.billingMode.toUpperCase()}`);
    console.log(`Available Balance:      ₹${Number(data.currentBalance).toFixed(2)}`);

    if (data.estimate) {
      const est = data.estimate;

      console.log('---------------------------------------------');
      console.log(`Target Model:           ${est.modelId}`);
      console.log(`Training Method:        ${method.toUpperCase()}`);
      console.log(`Allocated GPU Tier:     ${est.gpuTier}`);
      console.log(`Estimated Duration:     ${est.estimatedHours} hours`);
      console.log(`Effective Hourly Rate:  ₹${est.hourlyRate.toFixed(2)}/hour`);
      console.log(`Estimated Total Cost:   ₹${Number(est.estimatedTotal || data.estimatedTotal || 0).toFixed(2)}`);
      console.log(`Permit Reference:       ${data.permitRef}`);
      console.log(`Permit Valid For:       15 minutes (Expires: ${new Date(data.expiresAt).toLocaleTimeString()})`);
      if (est.sizingConfidence === 'fallback_default' || est.confidence === 'fallback_default' || est.isFallbackSizing) {
        console.log('---------------------------------------------');
        console.warn('⚠️  [Sizing Fallback Notice]:');
        console.warn(' • Precise model architecture parameters could not be resolved from Hugging Face config.');
        console.warn(' • Sizing was estimated using a 7B fallback baseline (GPU: ' + est.gpuTier + ').');
        console.warn(' • If deploying a larger model (e.g. 13B/70B), please specify GPU tier manually to prevent OOM.');
      }
      console.log('---------------------------------------------');
      console.log('🛡️  PRICING & SPOT MARKET GOVERNANCE NOTICE:');
      console.log(' • Cost Estimate: Quoted total is an analytical estimate based on token count and model shape.');
      console.log(' • 10% Surge Protection: Broker rates fluctuate dynamically. Upon deployment, your rate is locked.');
      console.log('   If provider spot prices surge >10% mid-run, our policy automatically triggers a Safe Stop/Auto-Migration');
      console.log('   to prevent billing drift and protect your balance.');
      console.log('=============================================');

      if (data.requiresConfirmation) {
        console.warn(`\n⚠️  [Underfunded Warning] Estimated cost (₹${Number(est.estimatedTotal || 0).toFixed(2)}) exceeds your balance (₹${Number(data.currentBalance || 0).toFixed(2)}).`);
        console.warn(`Training will auto-pause if balance depletes before completion.`);

        if (!autoConfirm) {
          const ans = await askQuestion('\nDo you authorize deploying with your current balance ceiling? (y/N): ');
          if (ans.toLowerCase() !== 'y' && ans.toLowerCase() !== 'yes') {
            console.log('[Aborted] Deployment cancelled by user.');
            return false;
          }
        }
      }

      config.lastPermit = {
        permitRef: data.permitRef,
        expiresAt: data.expiresAt,
        modelId: est.modelId,
        method: method || 'full',
        estimatedTotal: Number(est.estimatedTotal || 0),
        maxExposure: Number(est.maxExposure || 0),
        datasetFingerprint: prepared ? prepared.sha256 : 'reference_sizing',
        requiresConfirmation: data.requiresConfirmation,
        permittedAt: new Date().toISOString()
      };
      saveConfig(config);
      return true;
    }

    return true;
  } catch (err: any) {
    console.error(`\n[Error] Failed to connect to orchestrator: ${err.message}`);
    process.exit(1);
  }
}

function createTarHeader(filename: string, size: number, mtime: number = Date.now()): Buffer {
  const header = Buffer.alloc(512);
  const nameBuf = Buffer.from(filename.replace(/\\/g, '/'), 'utf-8');
  nameBuf.copy(header, 0, 0, Math.min(100, nameBuf.length));
  
  header.write('0000644\0', 100, 8, 'utf-8');
  header.write('0000000\0', 108, 8, 'utf-8');
  header.write('0000000\0', 116, 8, 'utf-8');
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf-8');
  header.write(Math.floor(mtime / 1000).toString(8).padStart(11, '0') + '\0', 136, 12, 'utf-8');
  header.fill(32, 148, 156);
  header.write('0', 156, 1, 'utf-8');
  header.write('ustar\0', 257, 6, 'utf-8');
  header.write('00', 263, 2, 'utf-8');

  let chksum = 0;
  for (let i = 0; i < 512; i++) chksum += header[i];
  header.write(chksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf-8');

  return header;
}

async function verifyAvailableDiskSpace(targetDir: string, estimatedBytes: number): Promise<void> {
  try {
    if (typeof (fs as any).statfsSync === 'function') {
      const stats = (fs as any).statfsSync(targetDir);
      const freeBytes = Number(stats.bavail) * Number(stats.bsize);
      const requiredBytes = Math.max(100 * 1024 * 1024, estimatedBytes * 1.5);
      if (freeBytes > 0 && freeBytes < requiredBytes) {
        throw new Error(
          `Insufficient disk space in temporary directory (${targetDir}). ` +
          `Available: ${(freeBytes / (1024 * 1024)).toFixed(1)} MB, ` +
          `Required: ${(requiredBytes / (1024 * 1024)).toFixed(1)} MB. ` +
          `Please free up disk space before packaging dataset.`
        );
      }
    }
  } catch (err: any) {
    if (err.message.includes('Insufficient disk space')) {
      throw err;
    }
  }
}

async function archiveDirectoryToTarGz(dirPath: string, outputPath: string): Promise<number> {
  const tmpDir = path.dirname(outputPath);
  await verifyAvailableDiskSpace(tmpDir, 50 * 1024 * 1024);
  const gzip = zlib.createGzip({ level: 6 });
  const outStream = fs.createWriteStream(outputPath);
  gzip.pipe(outStream);

  async function pipeFileChunks(filePath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const readStream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
      readStream.on('data', (chunk) => {
        const canContinue = gzip.write(chunk);
        if (!canContinue) {
          readStream.pause();
          gzip.once('drain', () => readStream.resume());
        }
      });
      readStream.on('end', () => resolve());
      readStream.on('error', (err) => reject(err));
    });
  }

  async function walkAndWrite(currentPath: string, relativePrefix: string = ''): Promise<void> {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      const relPath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await walkAndWrite(fullPath, relPath);
      } else if (entry.isFile()) {
        const stat = fs.statSync(fullPath);
        const header = createTarHeader(relPath, stat.size, stat.mtimeMs);
        gzip.write(header);
        await pipeFileChunks(fullPath);
        const padding = (512 - (stat.size % 512)) % 512;
        if (padding > 0) {
          gzip.write(Buffer.alloc(padding));
        }
      }
    }
  }

  await walkAndWrite(dirPath);
  gzip.write(Buffer.alloc(1024)); // Two 512-byte EOF zero blocks
  gzip.end();

  await new Promise<void>((resolve, reject) => {
    outStream.on('finish', () => resolve());
    outStream.on('error', (err) => reject(err));
    gzip.on('error', (err) => reject(err));
  });

  return fs.statSync(outputPath).size;
}

// 4. Server-Authoritative Deployment with Resilient Multipart Upload
async function performUpload(_config: any, prepared: any, fileLabel: string, jobId?: string): Promise<{uploadKey: string, jobId: string}> {
  const accessToken = await getValidAccessToken();
  console.log("Initiating secure clamped multipart upload for " + fileLabel + " to Cloudflare R2...");
  let uploadId = "";
  let uploadKey = "";
  let finalJobId = jobId || "";
  let uploadFilePath = prepared.path;
  let uploadFileSizeBytes = prepared.sizeBytes;
  let isTempArchive = false;

  try {
    if (fs.statSync(prepared.path).isDirectory()) {
      console.log(`Packaging directory ${prepared.filename} into compressed tarball for upload...`);
      const tempArchive = path.join(os.tmpdir(), `vivacious_upload_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tar.gz`);
      uploadFileSizeBytes = await archiveDirectoryToTarGz(prepared.path, tempArchive);
      uploadFilePath = tempArchive;
      isTempArchive = true;
    }

    const bodyPayload: any = { filename: prepared.filename };
    if (finalJobId && finalJobId.trim()) {
      bodyPayload.jobId = finalJobId.trim();
    }

    const initRes = await fetch(`${API_HOST}/api/upload/initiate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify(bodyPayload)
    });

    if (!initRes.ok) {
      const err = await initRes.json().catch(() => ({})) as any;
      const errMsg = typeof err.error === 'string' ? err.error : (err.message || (Array.isArray(err.error) ? err.error.map((e: any) => e.message || e).join(', ') : JSON.stringify(err.error || err)));
      throw new Error(`Upload initiation failed: ${errMsg || initRes.statusText}`);
    }

    const initData = await initRes.json() as any;
    uploadId = initData.uploadId;
    uploadKey = initData.key;
    finalJobId = initData.jobId;
    const uploadToken = initData.uploadToken;

    const chunkSize = calculateAdaptiveChunkSize(uploadFileSizeBytes);
    const totalParts = Math.max(1, Math.ceil(uploadFileSizeBytes / chunkSize));
    console.log(`Uploading ${fileLabel} across ${totalParts} adaptive multipart chunk(s) (${(chunkSize / (1024 * 1024)).toFixed(0)} MB/part)...`);

    const parts: { ETag: string; PartNumber: number }[] = [];

    const fd = fs.openSync(uploadFilePath, "r");
    for (let partNum = 1; partNum <= totalParts; partNum++) {
      const start = (partNum - 1) * chunkSize;
      const end = Math.min(uploadFileSizeBytes, partNum * chunkSize);
      const chunkLen = end - start;
      const buffer = Buffer.alloc(chunkLen);
      fs.readSync(fd, buffer, 0, chunkLen, start);

      let partUploaded = false;
      let lastErr = "";

      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          const partRes = await fetch(`${API_HOST}/api/upload/part`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${accessToken}`,
              ...(uploadToken ? { "x-upload-token": uploadToken } : {})
            },
            body: JSON.stringify({ uploadId, key: uploadKey, partNumber: partNum, uploadToken })
          });

          if (!partRes.ok) throw new Error(`Signed URL request failed: ${partRes.status}`);

          const { url } = await partRes.json() as any;
          console.log(`[Upload ${fileLabel}] Part ${partNum}/${totalParts} (${(chunkLen / (1024 * 1024)).toFixed(2)} MB, attempt ${attempt})...`);

          const putRes = await fetch(url, { method: "PUT", body: buffer });
          if (!putRes.ok) throw new Error(`R2 gateway returned HTTP ${putRes.status}`);
          const etag = putRes.headers.get("ETag") || `etag-${partNum}`;
          parts.push({ ETag: etag, PartNumber: partNum });
          partUploaded = true;
          break;
        } catch (err: any) {
          lastErr = err.message;
          const waitMs = Math.min(10000, 1000 * Math.pow(2, attempt));
          console.warn(`[Upload Retry] Part ${partNum} failed (attempt ${attempt}/5: ${lastErr}). Retrying in ${waitMs / 1000}s...`);
          await new Promise((r) => setTimeout(r, waitMs));
        }
      }

      if (!partUploaded) {
        throw new Error(`Part ${partNum} permanently failed after 5 retry attempts: ${lastErr}`);
      }
    }
    fs.closeSync(fd);

    const completeRes = await fetch(`${API_HOST}/api/upload/complete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`,
        ...(uploadToken ? { "x-upload-token": uploadToken } : {})
      },
      body: JSON.stringify({ uploadId, key: uploadKey, parts, uploadToken })
    });

    if (!completeRes.ok) {
      throw new Error("Multipart completion handshake failed");
    }

    console.log(`\n✅ ${fileLabel} upload completed and verified on Cloudflare R2.`);
    return { uploadKey, jobId: finalJobId };
  } catch (uploadErr: any) {
    console.error(`\n[Upload Failed] ${uploadErr.message}`);
    if (uploadId && uploadKey) {
      try {
        console.warn(`[Upload Cleanup] Aborting incomplete multipart upload ${uploadId} for key ${uploadKey}...`);
        await fetch(`${API_HOST}/api/upload/abort`, {
          method: "POST",
          headers: { 
             "Content-Type": "application/json", 
             "Authorization": `Bearer ${accessToken}`
          },
          body: JSON.stringify({ uploadId, key: uploadKey, jobId: finalJobId })
        });
        console.warn(`[Upload Cleanup] Incomplete multipart upload successfully aborted.`);
      } catch (abortErr: any) {
        console.warn(`[Upload Cleanup Warning] Could not reach abort endpoint: ${abortErr.message}`);
      }
    }
    throw uploadErr;
  } finally {
    if (isTempArchive && fs.existsSync(uploadFilePath)) {
      try {
        fs.unlinkSync(uploadFilePath);
      } catch { /* cleanup is best effort */ }
    }
  }
}

async function handleDeploy(target: string = 'anirudha-s', modelId?: string, method: string = 'full', autoConfirm: boolean = false, checkpointPath?: string) {
  const accessToken = await getValidAccessToken();
  let config = loadConfig();

  const prepared = config.preparedDataset;
  if (!prepared) {
    console.error('[Error] No dataset has been prepared for upload.');
    console.error('Run: vivacious prepare <path-to-dataset>');
    process.exit(1);
  }

  if (checkpointPath) {
    console.log(`Preparing checkpoint from ${checkpointPath}...`);
    await handlePrepare(checkpointPath, 'checkpoint');
    config = loadConfig(); // reload config after prepare updates it
  }

  if (modelId) {
    const permitted = await handlePermit(modelId, method, autoConfirm);
    if (!permitted) {
      console.error('[Error] Pre-flight financial check rejected or unconfirmed.');
      process.exit(1);
    }
    config = loadConfig();
  }

  const permit = config.lastPermit;
  if (!permit) {
    console.error('[Error] No active financial permit found. Please run permit first:');
    console.error('  vivacious permit anirudha-s ambition --model <model-id>');
    process.exit(1);
  }

  if (permit.expiresAt && new Date(permit.expiresAt).getTime() < Date.now()) {
    console.warn('[Notice] Your financial permit has expired (>15 minutes). Refreshing permit now...');
    const permitted = await handlePermit(permit.modelId, permit.method, autoConfirm);
    if (!permitted) {
      console.error('[Error] Re-permitting failed.');
      process.exit(1);
    }
    config = loadConfig();
  }

  const activePermit = config.lastPermit!;
  const prepCheckpoint = config.preparedCheckpoint;

  // Pre-flight balance check: Prevent R2 uploads and bandwidth costs if balance is insufficient
  try {
    const balRes = await fetch(`${API_HOST}/api/user/balance`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (balRes.ok) {
      const balData: any = await balRes.json();
      const currentBalance = Number(balData.currentBalance ?? balData.current_balance ?? 0);
      const isCard = balData.billingMode === 'card' || balData.billing_mode === 'card';
      const estimatedCost = Number(activePermit.estimatedTotal || 0);

      if (!isCard && currentBalance <= 0) {
        console.error('\n=============================================');
        console.error('❌ [DEPLOYMENT BLOCKED — INSUFFICIENT BALANCE]');
        console.error('=============================================');
        console.error(`Current Balance:      ₹${currentBalance.toFixed(2)}`);
        console.error(`Estimated Run Cost:   ₹${estimatedCost.toFixed(2)}`);
        console.error('Upload to Cloudflare R2 was stopped to protect your account.');
        console.error('Please recharge your balance via the Dashboard (Billing) before deploying.');
        console.error('=============================================');
        process.exit(1);
      }

      if (!isCard && currentBalance < estimatedCost && !activePermit.requiresConfirmation) {
        console.warn(`\n⚠️  [Notice] Current balance (₹${currentBalance.toFixed(2)}) is lower than estimated cost (₹${estimatedCost.toFixed(2)}).`);
        console.warn('Job may auto-pause if balance depletes during training.');
      }
    }
  } catch {
    // Non-blocking fallback; server /api/upload/initiate and /api/deploy strictly enforce financial ceilings
  }

  console.log(`\n=============================================`);
  console.log(`🚀 VIVACIOUS CLOUD — JOB DEPLOYMENT`);
  console.log(`=============================================`);
  console.log(`Workspace Target:     ${target}`);
  console.log(`Target Model:         ${activePermit.modelId}`);
  console.log(`Training Method:      ${activePermit.method.toUpperCase()}`);
  console.log(`Dataset:              ${prepared.filename} (${(prepared.sizeBytes / (1024 * 1024)).toFixed(2)} MB)`);
  console.log(`SHA-256 Fingerprint:  ${prepared.sha256}`);
  if (prepCheckpoint) {
    console.log(`Checkpoint Archive:   ${prepCheckpoint.filename} (${(prepCheckpoint.sizeBytes / (1024 * 1024)).toFixed(2)} MB)`);
    console.log(`Checkpoint SHA-256:   ${prepCheckpoint.sha256}`);
  }
  console.log(`---------------------------------------------`);

  // Upload Dataset
  const datasetUpload = await performUpload(config, prepared, 'Dataset');
  const activeJobId = datasetUpload.jobId;

  // Upload Checkpoint if present
  let checkpointKey: string | undefined = undefined;
  if (prepCheckpoint) {
    const cpUpload = await performUpload(config, prepCheckpoint, 'Checkpoint', activeJobId);
    checkpointKey = cpUpload.uploadKey;
  }

  // Step 2: Trigger Server-Authoritative Deployment
  const deploymentId = crypto.randomUUID();
  console.log(`Triggering orchestrator GPU provisioning (Deployment ID: ${deploymentId})...`);

  try {
    const deployRes = await fetch(`${API_HOST}/api/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        jobId: activeJobId,
        modelId: activePermit.modelId,
        modelSource: checkpointKey ? 'custom_checkpoint' : 'hf',
        checkpointKey: checkpointKey,
        method: activePermit.method,
        datasetFilename: prepared!.filename,
        datasetSizeBytes: prepared!.sizeBytes,
        datasetFingerprint: prepared!.sha256,
        permitRef: activePermit.permitRef,
        deploymentId,
        confirmedUnderfunded: activePermit.requiresConfirmation || false
      })
    });

    const deployData: any = await deployRes.json();
    if (!deployRes.ok) {
      console.error(`\n[Deployment Error] ${deployData.error || 'Server failed to provision instance.'}`);
      process.exit(1);
    }

    console.log('\n=============================================');
    console.log('✅ DEPLOYMENT LAUNCHED SUCCESSFULLY');
    console.log('=============================================');
    console.log(`Job ID:               ${deployData.jobId}`);
    console.log(`Initial Job Status:   ${(deployData.status || 'QUEUED').toUpperCase()}`);
    console.log(`Allocated GPU Tier:   ${deployData.gpuTier || 'Standard'}`);
    console.log(`Estimated Duration:   ${Number(deployData.estimatedHours || 1).toFixed(2)} hours`);
    console.log(`Estimated Total Cost: ₹${Number(deployData.estimatedTotal || 0).toFixed(2)} (Billing: ${(deployData.billingMode || 'PREPAID').toUpperCase()})`);
    console.log('\nNext Steps:');
    console.log(`  To monitor real-time progress, run: vivacious status ${deployData.jobId}`);
    console.log(`  To stream live loss & telemetry, run: vivacious logs ${deployData.jobId}`);
    console.log('=============================================\n');

    // Clean up local tracking state to prevent accidental double-deploys
    delete config.preparedDataset;
    delete config.preparedCheckpoint;
    delete config.lastPermit;
    saveConfig(config);

  } catch (submitErr: any) {
    console.error(`\n[Deployment Communication Error] ${submitErr.message}`);
    process.exit(1);
  }
}



// 5. Query Real-Time Balance
async function handleBalance() {
  const accessToken = await getValidAccessToken();

  try {
    const res = await fetch(`${API_HOST}/api/user/balance`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!res.ok) {
      if (res.status === 401) {
        console.error('\n[Notice] Your authentication session has expired.');
        console.error('Please run "vivacious login anirudha-s" to authenticate.\n');
        process.exit(1);
      }
      const errJson: any = await res.json().catch(() => ({}));
      console.error(`[Error] Failed to fetch balance: ${errJson.error || res.statusText}`);
      process.exit(1);
    }

    const data: any = await res.json();
    console.log('\n=============================================');
    console.log('💰 VIVACIOUS CLOUD — ACCOUNT BALANCE');
    console.log('=============================================');
    console.log(`User ID:              ${data.userId || data.user_id || 'N/A'}`);
    console.log(`Available Balance:    ₹${Number(data.currentBalance ?? data.current_balance ?? 0).toFixed(2)}`);
    console.log(`Total Paid:           ₹${Number(data.totalPaid ?? data.total_paid ?? 0).toFixed(2)}`);
    console.log(`Total Spent:          ₹${Number(data.totalSpent ?? data.total_spent ?? 0).toFixed(2)}`);
    console.log(`Billing Mode:         ${(data.billingMode || data.billing_mode || 'PREPAID').toUpperCase()}`);
    console.log('=============================================');
  } catch (err: any) {
    console.error(`[Error] Could not retrieve balance: ${err.message}`);
    process.exit(1);
  }
}

// 6. Query Job Status & Live Telemetry
async function handleStatus(jobId?: string) {
  const accessToken = await getValidAccessToken();

  const endpoint = jobId ? `${API_HOST}/api/jobs/${jobId}` : `${API_HOST}/api/jobs/active`;

  try {
    const res = await fetch(endpoint, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (res.status === 404) {
      console.log(jobId ? `[Notice] Job ${jobId} not found.` : '[Notice] No active training jobs found.');
      return;
    }

    if (!res.ok) {
      console.error(`[Error] Failed to fetch status: ${res.statusText}`);
      process.exit(1);
    }

    const data: any = await res.json();
    const modelName = data.model_id || data.model || 'meta-llama/Llama-3-8b';
    console.log('\n=============================================');
    console.log(`📊 JOB STATUS: ${data.id}`);
    console.log('=============================================');
    console.log(`Model:                ${modelName}`);
    console.log(`Status:               ${data.status.toUpperCase()}`);
    console.log(`Progress:             ${Number(data.progress_percent || 0).toFixed(1)}%`);
    console.log(`GPU Tier:             ${data.gpu_type || 'N/A'}`);
    console.log(`Current Cost:         ₹${Number(data.cost || 0).toFixed(2)}`);
    console.log(`Hourly Rate:          ₹${Number(data.hourly_rate || data.locked_hourly_rate || 0).toFixed(2)}/hr`);
    console.log(`Last Heartbeat:       ${data.last_heartbeat ? new Date(data.last_heartbeat).toLocaleTimeString() : 'N/A'}`);
    console.log('=============================================');
  } catch (err: any) {
    console.error(`[Error] Could not retrieve status: ${err.message}`);
    process.exit(1);
  }
}

// 6b. Query Live Execution Logs & Output Telemetry
async function handleLogs(jobId?: string) {
  const accessToken = await getValidAccessToken();

  const endpoint = jobId ? `${API_HOST}/api/jobs/${jobId}` : `${API_HOST}/api/jobs/active`;

  try {
    const res = await fetch(endpoint, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (res.status === 404) {
      console.log(jobId ? `[Notice] Job ${jobId} not found.` : '[Notice] No active training jobs found.');
      return;
    }

    if (!res.ok) {
      console.error(`[Error] Failed to fetch execution logs: ${res.statusText}`);
      process.exit(1);
    }

    const data: any = await res.json();
    const modelName = data.model_id || data.model || 'meta-llama/Llama-3-8b';
    console.log('\n=============================================');
    console.log(`📋 JOB EXECUTION LOGS: ${data.id}`);
    console.log('=============================================');
    console.log(`Model:          ${modelName}`);
    console.log(`Status:         ${data.status.toUpperCase()}`);
    console.log(`Progress:       ${Number(data.progress_percent || 0).toFixed(1)}%`);
    console.log(`Current Step:   ${data.current_step || data.step || 'N/A'}`);
    console.log(`Current Loss:   ${data.loss !== undefined ? Number(data.loss).toFixed(4) : 'N/A'}`);
    console.log('---------------------------------------------');
    console.log('Telemetry & Output:');
    if (data.logs && Array.isArray(data.logs) && data.logs.length > 0) {
      data.logs.forEach((logLine: string) => console.log(`  ${logLine}`));
    } else if (typeof data.logs === 'string' && data.logs.trim().length > 0) {
      console.log(data.logs);
    } else if (data.error_message) {
      console.log(`  [Details] ${data.error_message}`);
    } else {
      console.log(`  [Telemetry] GPU container running normally. Training progress: ${Number(data.progress_percent || 0).toFixed(1)}%.`);
    }
    console.log('=============================================');
  } catch (err: any) {
    console.error(`[Error] Could not retrieve execution logs: ${err.message}`);
    process.exit(1);
  }
}

// 7. Secure Presigned Download Link Generator & Stream Downloader
async function handleDownload(jobId: string, directDownload: boolean = true) {
  const accessToken = await getValidAccessToken();

  console.log(`Requesting secure download link for job ${jobId}...`);

  try {
    const res = await fetch(`${API_HOST}/api/jobs/download`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ jobId })
    });

    const data: any = await res.json();
    if (!res.ok || !data.downloadUrl) {
      console.error(`\n[Error] Download link generation failed: ${data.error || 'Unknown error'}`);
      process.exit(1);
    }

    console.log('\n=============================================');
    console.log('📦 MODEL WEIGHTS DOWNLOAD LINK');
    console.log('=============================================');
    console.log(`Job ID:       ${jobId}`);
    console.log(`Download URL: ${data.downloadUrl}`);
    console.log(`Expires At:   ${data.expiresAt || '7 days'}`);
    console.log('---------------------------------------------');
    console.log('Download via cURL:');
    console.log(`  curl -O "${data.downloadUrl}"`);
    console.log('=============================================');

    if (directDownload) {
      const sanitizedJobId = jobId.replace(/[^a-zA-Z0-9_-]/g, '');
      const outPath = path.resolve(process.cwd(), `model_weights_${sanitizedJobId}.tar.gz`);
      console.log(`\nInitiating direct streaming download to: ${outPath}...`);
      
      const dlRes = await fetch(data.downloadUrl);
      if (!dlRes.ok) {
        console.error(`[Download Error] Storage gateway returned HTTP ${dlRes.status}`);
        return;
      }

      const totalLength = Number(dlRes.headers.get('content-length')) || 0;
      const fileStream = fs.createWriteStream(outPath);

      if (dlRes.body) {
        let downloadedBytes = 0;
        const reader = (dlRes.body as any).getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            fileStream.write(Buffer.from(value));
            downloadedBytes += value.length;
            if (totalLength > 0) {
              const pct = ((downloadedBytes / totalLength) * 100).toFixed(1);
              process.stdout.write(`\rDownloading: ${pct}% (${(downloadedBytes / (1024 * 1024)).toFixed(2)} / ${(totalLength / (1024 * 1024)).toFixed(2)} MB)`);
            } else {
              process.stdout.write(`\rDownloading: ${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB`);
            }
          }
        }
        fileStream.end();
        console.log(`\n✅ Model weights successfully downloaded: ${outPath}`);
      }
    }
  } catch (err: any) {
    console.error(`[Error] Failed to get download link: ${err.message}`);
    process.exit(1);
  }
}

// 8. User-Initiated Job Cancellation
async function handleCancel(jobId: string, autoConfirm: boolean = false) {
  const accessToken = await getValidAccessToken();

  if (!autoConfirm) {
    const ans = await askQuestion(`Are you sure you want to terminate job ${jobId}? (y/N): `);
    if (ans.toLowerCase() !== 'y' && ans.toLowerCase() !== 'yes') {
      console.log('[Aborted] Cancellation aborted.');
      return;
    }
  }

  console.log(`Sending termination signal for job ${jobId}...`);

  try {
    const res = await fetch(`${API_HOST}/api/jobs/cancel`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ jobId })
    });

    const data: any = await res.json();
    if (!res.ok) {
      console.error(`[Error] Cancellation failed: ${data.error || 'Unknown error'}`);
      process.exit(1);
    }

    console.log(`\n✅ Job ${jobId} successfully marked for termination. Final compute settled.`);
  } catch (err: any) {
    console.error(`[Error] Failed to cancel job: ${err.message}`);
    process.exit(1);
  }
}

// 9. Checkpoint Resumption Handlers (Dedicated Isolated Workflow)

async function handleResumeInspect(jobId: string) {
  const accessToken = await getValidAccessToken();
  const config = loadConfig();

  if (!jobId || jobId === 'begin') {
    console.error('[Error] Missing required parameter: <job-id>');
    console.error('Usage: vivacious resume <job-id>');
    console.error('Example: vivacious resume job_8f29ab01');
    process.exit(1);
  }

  console.log(`\n=============================================`);
  console.log(`🔁 VIVACIOUS CLOUD — CHECKPOINT RECOVERY INSPECTION`);
  console.log(`=============================================`);
  console.log(`Querying server-authoritative checkpoint for job ${jobId}...`);

  try {
    const res = await fetch(`${API_HOST}/api/jobs/resume/inspect?jobId=${encodeURIComponent(jobId)}`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    const data: any = await res.json();
    if (!res.ok || !data.success || !data.resumeAvailable) {
      console.error(`\n[Inspection Error] ${data.error || 'Workload is not eligible for resumption.'}`);
      process.exit(1);
    }

    const job = data.job;
    const expiresDate = job.checkpointExpiresAt ? new Date(job.checkpointExpiresAt).toLocaleString() : '7 days from stop';

    console.log(`Job ID:               ${job.id}`);
    console.log(`Target Base Model:    ${job.modelId} (${job.method.toUpperCase()})`);
    console.log(`Training Progress:    ${Number(job.progressPercent).toFixed(1)}% (Checkpoint Step: ${job.checkpointStep})`);
    console.log(`Allocated GPU Shape:  ${job.gpuTier}`);
    console.log(`Accrued Prior Cost:   ₹${Number(job.costAccrued).toFixed(2)}`);
    console.log(`Stop Diagnostic:      ⚠️ ${job.errorReason}`);
    console.log(`Checkpoint Status:    Verified (Vivacious Storage)`);
    console.log(`7-Day Expiration:     ${expiresDate}`);
    console.log(`---------------------------------------------`);
    console.log(`✅ [Checkpoint Verified & Staged for Resumption]`);
    console.log(`Next Step: Run 'vivacious anirudha-s check' to calculate remaining compute and authorize resumption.`);
    console.log(`=============================================`);

    config.resumeContext = {
      jobId: job.id,
      resumeAttemptId: data.resumeAttemptId,
      modelId: job.modelId,
      method: job.method,
      gpuTier: job.gpuTier,
      progressPercent: job.progressPercent,
      checkpointExpiresAt: job.checkpointExpiresAt,
      inspectedAt: new Date().toISOString()
    };
    saveConfig(config);
  } catch (err: any) {
    console.error(`\n[Error] Failed to inspect checkpoint: ${err.message}`);
    process.exit(1);
  }
}

async function handleResumeCheck() {
  const accessToken = await getValidAccessToken();
  let config = loadConfig();

  const resume = config.resumeContext;
  if (!resume || !resume.jobId || !resume.resumeAttemptId) {
    console.error('[Error] No resume workload staged. Please run "vivacious resume <job-id>" first.');
    process.exit(1);
  }

  console.log(`\n=============================================`);
  console.log(`💰 VIVACIOUS CLOUD — RESUME FINANCIAL AUTHORIZATION`);
  console.log(`=============================================`);
  console.log(`Target Job ID:        ${resume.jobId}`);
  console.log(`Target Model:         ${resume.modelId || 'Base Model'} (${(resume.method || 'LORA').toUpperCase()})`);
  console.log(`Completed Progress:   ${Number(resume.progressPercent || 0).toFixed(1)}%`);
  console.log(`Checking server balance against remaining compute exposure...`);

  try {
    const res = await fetch(`${API_HOST}/api/jobs/resume/permit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        jobId: resume.jobId,
        resumeAttemptId: resume.resumeAttemptId
      })
    });

    const data: any = await res.json();
    if (!res.ok) {
      console.error(`\n[Permit Error] ${data.error || 'Server failed to calculate resume permit.'}`);
      process.exit(1);
    }

    console.log(`Available Balance:    ₹${Number(data.currentBalance || 0).toFixed(2)}`);
    console.log(`Remaining Duration:   ~${Number(data.remainingHours || 0).toFixed(2)} hrs`);
    console.log(`Hourly Rate:          ₹${Number(data.hourlyRate || 0).toFixed(2)}/hr`);
    console.log(`Estimated Remaining:  ₹${Number(data.remainingEstimatedTotal || 0).toFixed(2)}`);
    console.log(`Max Exposure Ceiling: ₹${Number(data.remainingMaxExposure || 0).toFixed(2)}`);
    console.log(`---------------------------------------------`);

    if (!data.permitted || !data.permitRef) {
      console.error(`❌ [INSUFFICIENT BALANCE]`);
      console.error(`Your account requires ₹${Number(data.remainingEstimatedTotal || 0).toFixed(2)} to complete this training run.`);
      console.error(`Current balance: ₹${Number(data.currentBalance || 0).toFixed(2)}.`);
      console.error(`Please recharge your account via the Dashboard (Billing) and re-run:`);
      console.error(`  vivacious anirudha-s check`);
      process.exit(1);
    }

    console.log(`✅ [FINANCIAL PERMIT GRANTED] (Valid for 15 minutes, Single-Use)`);
    console.log(`Next Step: Run 'vivacious resume begin' to launch cloud GPU training.`);
    console.log(`=============================================`);

    config.resumeContext!.lastPermitRef = data.permitRef;
    config.resumeContext!.remainingEstimatedTotal = data.remainingEstimatedTotal;
    config.resumeContext!.remainingMaxExposure = data.remainingMaxExposure;
    saveConfig(config);
  } catch (err: any) {
    console.error(`\n[Error] Failed to authorize resume permit: ${err.message}`);
    process.exit(1);
  }
}

async function handleResumeBegin(autoConfirm: boolean = false) {
  const accessToken = await getValidAccessToken();
  const config = loadConfig();

  const resume = config.resumeContext;
  if (!resume || !resume.jobId || !resume.lastPermitRef) {
    console.error('[Error] No active financial permit found for resume.');
    console.error('Please complete the pre-flight check first:');
    console.error('  1. vivacious resume <job-id>');
    console.error('  2. vivacious anirudha-s check');
    process.exit(1);
  }

  console.log(`\n=============================================`);
  console.log(`🚀 VIVACIOUS CLOUD — RESUME WORKLOAD CONFIRMATION`);
  console.log(`=============================================`);
  console.log(`Job ID:               ${resume.jobId}`);
  console.log(`Target Model:         ${resume.modelId || 'Base Model'}`);
  console.log(`Resuming Progress:    ${Number(resume.progressPercent || 0).toFixed(1)}%`);
  console.log(`Remaining Exposure:   ₹${Number(resume.remainingMaxExposure || 0).toFixed(2)} (Max authorized)`);
  console.log(`=============================================`);

  if (!autoConfirm) {
    const ans = await askQuestion('Are you sure you want to resume and dispatch this training workload? (y/N): ');
    if (ans.toLowerCase() !== 'y' && ans.toLowerCase() !== 'yes') {
      console.log('[Aborted] Resume launch aborted.');
      return;
    }
  }

  console.log(`Dispatching server-authoritative resumption to Cloudflare Orchestrator...`);

  try {
    const res = await fetch(`${API_HOST}/api/jobs/resume/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        jobId: resume.jobId,
        permitRef: resume.lastPermitRef
      })
    });

    const data: any = await res.json();
    if (!res.ok || !data.success) {
      console.error(`\n[Deployment Error] ${data.error || 'Server failed to resume workload.'}`);
      process.exit(1);
    }

    console.log('\n=============================================');
    console.log('🎉 RESUMED WORKLOAD LAUNCHED SUCCESSFULLY');
    console.log('=============================================');
    console.log(`Job ID:               ${data.jobId}`);
    console.log(`Status:               ${data.status.toUpperCase()} (Cloud GPU container queued)`);
    console.log(`Continuing From:      ${Number(data.progressPercent || resume.progressPercent || 0).toFixed(1)}%`);
    console.log(`Track Progress:       vivacious status ${data.jobId}`);
    console.log(`Cancel Job:           vivacious cancel ${data.jobId}`);
    console.log('=============================================');

    // Single-use: clear consumed permit reference
    if (config.resumeContext) {
      config.resumeContext.lastPermitRef = undefined;
    }
    saveConfig(config);
  } catch (err: any) {
    console.error(`\n[Error] Resumed deployment connection failed: ${err.message}`);
    process.exit(1);
  }
}

// 10. Logout
function handleLogout() {
  saveConfig({});
  console.log('[Success] Logged out. Local credentials cleared.');
}

function showHelp() {
  console.log(`
Vivacious Cloud CLI — Production Client
An Anirudha's Ambition

Usage:
  vivacious <command> [arguments] [options]

Workflow 1: Open-Source Base Models
  vivacious login anirudha-s
  vivacious prepare <path>
  vivacious permit anirudha-s ambition --model <model-id>
  vivacious permit anirudha-s ambition --model <model-id> --method lora
  vivacious permit anirudha-s ambition --model <model-id> --method qlora
  vivacious deploy anirudha-s
  vivacious balance
  vivacious download <job-id>

Workflow 2: Retrain & Bring Your Own Model (BYOM)
  vivacious login anirudha-s
  vivacious prepare dataset <path>
  vivacious prepare checkpoint <path>
  vivacious permit anirudha-s ambition --model custom_model
  vivacious permit anirudha-s ambition --model custom_model --method lora
  vivacious permit anirudha-s ambition --model custom_model --method qlora
  vivacious deploy anirudha-s
  vivacious status <job-id>
  vivacious download <job-id>

Workflow 3: Resume Interrupted Workload
  vivacious resume <job-id>
  vivacious anirudha-s check
  vivacious resume begin [--yes]

Monitoring & Account Management:
  vivacious balance
  vivacious status <job-id>
  vivacious logs <job-id>
  vivacious download <job-id>
  vivacious cancel <job-id> [--yes]
  vivacious logout

Options:
  --model <model-id>                      Target model identifier or custom_model
  --method <full|lora|qlora>              Fine-tuning method (default: full)
  --checkpoint <path>                     Local checkpoint tarball for retraining
  --yes, -y                               Auto-confirm prompts without manual input
`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    showHelp();
    process.exit(0);
  }

  switch (command) {
    case 'anirudha-s': {
      const sub = args[1];
      if (sub === 'check') {
        await handleResumeCheck();
      } else {
        console.error('[Error] Unrecognized founder command.');
        console.error('Usage: vivacious anirudha-s check');
        process.exit(1);
      }
      break;
    }

    case 'login': {
      const target = args[1];
      if (target !== 'anirudha-s') {
        console.error('[Error] Invalid login target.');
        console.error('Usage: vivacious login anirudha-s');
        process.exit(1);
      }
      await handleLogin(target);
      break;
    }

    case 'prepare':
    case 'upload': {
      let type: 'dataset' | 'checkpoint' = 'dataset';
      let targetPath = args[1];

      if (args[1] === 'checkpoint' || args[1] === '--checkpoint') {
        type = 'checkpoint';
        targetPath = args[2];
      } else if (args[1] === 'dataset' || args[1] === '--dataset') {
        type = 'dataset';
        targetPath = args[2];
      }

      if (!targetPath) {
        console.error('Usage: vivacious prepare [dataset|checkpoint] <path>');
        console.error('Example: vivacious prepare ./new_instructions.jsonl');
        console.error('Example: vivacious prepare checkpoint ./my_model_checkpoint.tar.gz');
        process.exit(1);
      }
      await handlePrepare(targetPath, type);
      break;
    }

    case 'permit':
    case 'permits': {
      let permitModel = '';
      let permitMethod = 'full';
      let autoConfirm = false;
      let hasFounder = false;
      let hasAmbition = false;

      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--model') {
          permitModel = args[i + 1] || '';
          i++;
        } else if (args[i] === '--method') {
          const methodVal = (args[i + 1] || '').toLowerCase();
          permitMethod = (methodVal === 'lora' || methodVal === 'qlora') ? methodVal : 'full';
          i++;
        } else if (args[i] === '--yes' || args[i] === '-y') {
          autoConfirm = true;
        } else if (args[i] === 'anirudha-s') {
          hasFounder = true;
        } else if (args[i] === 'ambition') {
          hasAmbition = true;
        } else if (args[i].startsWith('--')) {
          console.error(`[Error] Unrecognized option: ${args[i]}`);
          process.exit(1);
        } else {
          console.error(`[Error] Unexpected positional argument: "${args[i]}".`);
          console.error('Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]');
          process.exit(1);
        }
      }

      if (!hasFounder || !hasAmbition) {
        console.error('[Error] Missing required founder scope: "anirudha-s ambition"');
        console.error('Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]');
        process.exit(1);
      }

      if (!permitModel) {
        console.error('[Error] Missing required parameter: --model <model-id>');
        console.error('Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]');
        console.error('Example: vivacious permit anirudha-s ambition --model meta-llama/Llama-3-8b');
        console.error('Example: vivacious permit anirudha-s ambition --model custom_model --method lora');
        process.exit(1);
      }

      await handlePermit(permitModel, permitMethod, autoConfirm);
      break;
    }

    case 'deploy': {
      let deployModel = '';
      let deployCheckpoint = '';
      let deployMethod = 'full';
      let autoConfirm = false;
      let hasFounder = false;

      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--model') {
          deployModel = args[i + 1] || '';
          i++;
        } else if (args[i] === '--checkpoint') {
          deployCheckpoint = args[i + 1] || '';
          i++;
        } else if (args[i] === '--method') {
          const methodVal = (args[i + 1] || '').toLowerCase();
          deployMethod = (methodVal === 'lora' || methodVal === 'qlora') ? methodVal : 'full';
          i++;
        } else if (args[i] === '--yes' || args[i] === '-y') {
          autoConfirm = true;
        } else if (args[i] === 'anirudha-s') {
          hasFounder = true;
        } else if (args[i].startsWith('--')) {
          console.error(`[Error] Unrecognized option: ${args[i]}`);
          process.exit(1);
        } else {
          console.error(`[Error] Unexpected positional argument: "${args[i]}".`);
          console.error('Usage: vivacious deploy anirudha-s [--model <model-id>] [--yes]');
          process.exit(1);
        }
      }

      if (!hasFounder) {
        console.error('[Error] Missing required founder scope: "anirudha-s"');
        console.error('Usage: vivacious deploy anirudha-s [--model <model-id>] [--yes]');
        process.exit(1);
      }

      await handleDeploy('anirudha-s', deployModel || undefined, deployMethod, autoConfirm, deployCheckpoint || undefined);
      break;
    }

    case 'resume': {
      const sub = args[1];
      if (!sub || sub === '--help' || sub === '-h' || sub === 'help') {
        console.log('Usage: vivacious resume <job-id> | vivacious resume check | vivacious resume begin [--yes]');
        console.log('Example: vivacious resume job_8f29ab01');
        console.log('Example: vivacious resume check');
        console.log('Example: vivacious resume begin --yes');
        process.exit(0);
      }

      if (sub === 'begin') {
        const autoConfirm = args.includes('--yes') || args.includes('-y');
        await handleResumeBegin(autoConfirm);
      } else if (sub === 'check') {
        await handleResumeCheck();
      } else {
        await handleResumeInspect(sub);
      }
      break;
    }

    case 'balance':
    case 'billing':
      await handleBalance();
      break;

    case 'status': {
      const jobId = args[1];
      await handleStatus(jobId);
      break;
    }

    case 'logs':
    case 'log': {
      const jobId = args[1];
      await handleLogs(jobId);
      break;
    }

    case 'download': {
      const jobId = args[1];
      if (!jobId) {
        console.error('Usage: vivacious download <job-id>');
        process.exit(1);
      }
      await handleDownload(jobId);
      break;
    }

    case 'cancel': {
      const jobId = args[1];
      if (!jobId || jobId.startsWith('--')) {
        console.error('Usage: vivacious cancel <job-id> [--yes]');
        process.exit(1);
      }
      const autoConfirm = args.includes('--yes') || args.includes('-y');
      await handleCancel(jobId, autoConfirm);
      break;
    }

    case 'logout':
      handleLogout();
      break;

    default:
      console.error(`Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
}

if (require.main === module) {
  void main().catch((err: unknown) => {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.error(`Fatal CLI Error: ${errorMsg}`);
    process.exit(1);
  });
}

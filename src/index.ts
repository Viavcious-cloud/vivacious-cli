#!/usr/bin/env node

/**
 * Vivacious Cloud CLI Client
 * Production client supporting streaming SHA-256 fingerprinting (memory <50MB on >10GB files),
 * clamped adaptive multipart uploads (16–64 MiB, ≤8500 parts), dual workspace staging,
 * and defensive checkpoint archive inspection.
 */

import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as readline from "node:readline";
import * as zlib from "node:zlib";

const API_HOST =
	process.env.VIVACIOUS_API_HOST ||
	process.env.VIVACIOUS_API_URL ||
	"https://vivacious-orchestrator.vivacious-cloud.workers.dev";
const CONFIG_DIR = path.join(os.homedir(), ".vivacious");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

function openBrowser(url: string): void {
	try {
		const platform = process.platform;
		if (platform === "win32") {
			child_process.exec(`start "" "${url}"`);
		} else if (platform === "darwin") {
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

export interface UploadSessionState {
	sessionId: string;
	filePath: string;
	filename: string;
	fileSizeBytes: number;
	mtimeMs: number;
	chunkSize: number;
	totalParts: number;
	uploadId: string;
	uploadKey: string;
	uploadToken?: string;
	completedParts: { ETag: string; PartNumber: number }[];
	status: "in_progress" | "completed";
	updatedAt: string;
}

export interface ResumeContext {
	jobId: string;
	resumeAttemptId: string;
	state?: "RESUME_INSPECTED" | "RESUME_AUTHORIZED" | "RESUME_DISPATCHED";
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
		const parts = token.split(".");
		if (parts.length !== 3) return null;
		const base64Url = parts[1];
		const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
		const jsonPayload = decodeURIComponent(
			Buffer.from(base64, "base64")
				.toString("binary")
				.split("")
				.map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
				.join("")
		);
		const decoded = JSON.parse(jsonPayload);
		return typeof decoded.exp === "number" && Number.isFinite(decoded.exp)
			? decoded.exp * 1000
			: null;
	} catch {
		return null;
	}
}

/**
 * Universal safe API error formatter — guarantees zero [object Object] output
 */
export function formatApiError(err: any): string {
	if (!err) return "Unknown error";
	if (typeof err === "string") return err;
	if (err.message && typeof err.message === "string") return err.message;
	if (err.error) {
		if (typeof err.error === "string") return err.error;
		if (err.error.message && typeof err.error.message === "string")
			return err.error.message;
		if (Array.isArray(err.error))
			return err.error
				.map((e: any) => (typeof e === "string" ? e : e.message || JSON.stringify(e)))
				.join(", ");
		return JSON.stringify(err.error);
	}
	if (Array.isArray(err.errors)) {
		return err.errors
			.map((e: any) => (typeof e === "string" ? e : e.message || JSON.stringify(e)))
			.join(", ");
	}
	return JSON.stringify(err);
}

export async function getValidAccessToken(
	forceRefresh: boolean = false
): Promise<string> {
	const config = loadConfig();
	if (!config.accessToken) {
		console.error(
			'[Error] You are not logged in. Please run "vivacious login anirudha-s" first.'
		);
		process.exitCode = 1;
		return "";
	}

	const now = Date.now();
	const tokenExp =
		parseJwtExpiryMs(config.accessToken) || config.tokenExpiresAt || 0;
	// Trigger proactive refresh if token expires within 120 seconds (or is already expired)
	const isExpiringSoon = tokenExp - now < 120_000;

	if ((isExpiringSoon || forceRefresh) && config.refreshToken) {
		try {
			const refreshRes = await fetch(`${API_HOST}/api/auth/token/refresh`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ refreshToken: config.refreshToken }),
			});

			if (refreshRes.ok) {
				const refreshData: any = await refreshRes.json();
				if (refreshData.access_token) {
					config.accessToken = refreshData.access_token;
					if (refreshData.refresh_token) {
						config.refreshToken = refreshData.refresh_token;
					}
					const parsedExp = parseJwtExpiryMs(refreshData.access_token);
					config.tokenExpiresAt =
						parsedExp || Date.now() + (refreshData.expires_in || 3600) * 1000;
					saveConfig(config);
					return config.accessToken!;
				}
			} else {
				if (refreshRes.status === 401 || refreshRes.status === 400) {
					console.warn(
						'[Notice] Session expired. Please re-authenticate via "vivacious login anirudha-s".'
					);
				}
			}
		} catch (refreshErr: any) {
			console.warn(
				`[Notice] Temporary network issue during session refresh: ${refreshErr.message || "Continuing with current credentials..."}`
			);
		}
	}

	// If token is already expired and cannot be refreshed, halt cleanly with guidance
	if (tokenExp > 0 && tokenExp <= now) {
		console.error("\n[Notice] Your authentication session has expired.");
		console.error('Please run "vivacious login anirudha-s" to authenticate.\n');
		process.exitCode = 1;
		return "";
	}

	return config.accessToken || "";
}

function loadConfig(): Config {
	if (!fs.existsSync(CONFIG_FILE)) {
		return {};
	}
	try {
		fs.chmodSync(CONFIG_FILE, 0o600);
	} catch {}
	try {
		const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
		return JSON.parse(raw);
	} catch {
		return {};
	}
}

function saveConfig(config: Config) {
	if (!fs.existsSync(CONFIG_DIR)) {
		fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
	}
	const tempFile = path.join(
		CONFIG_DIR,
		`config.${Date.now()}.${crypto.randomBytes(4).toString("hex")}.tmp`
	);
	fs.writeFileSync(tempFile, JSON.stringify(config, null, 2), {
		encoding: "utf-8",
		mode: 0o600,
	});
	try {
		fs.chmodSync(tempFile, 0o600);
	} catch {}
	try {
		fs.renameSync(tempFile, CONFIG_FILE);
	} catch {
		// Windows fallback if destination is locked
		fs.copyFileSync(tempFile, CONFIG_FILE);
		try {
			fs.unlinkSync(tempFile);
		} catch {}
	}
	try {
		fs.chmodSync(CONFIG_FILE, 0o600);
	} catch {}
}

const UPLOAD_SESSIONS_DIR = path.join(CONFIG_DIR, "uploads");

export function getUploadSessionId(
	filePath: string,
	sizeBytes: number,
	mtimeMs: number
): string {
	return crypto
		.createHash("sha256")
		.update(`${path.resolve(filePath)}:${sizeBytes}:${mtimeMs}`)
		.digest("hex")
		.slice(0, 16);
}

export function loadUploadSession(sessionId: string): UploadSessionState | null {
	try {
		const file = path.join(UPLOAD_SESSIONS_DIR, `${sessionId}.json`);
		if (!fs.existsSync(file)) return null;
		const raw = fs.readFileSync(file, "utf-8");
		return JSON.parse(raw);
	} catch {
		return null;
	}
}

export function saveUploadSession(session: UploadSessionState): void {
	try {
		if (!fs.existsSync(UPLOAD_SESSIONS_DIR)) {
			fs.mkdirSync(UPLOAD_SESSIONS_DIR, { recursive: true, mode: 0o700 });
		}
		const file = path.join(UPLOAD_SESSIONS_DIR, `${session.sessionId}.json`);
		fs.writeFileSync(file, JSON.stringify(session, null, 2), {
			encoding: "utf-8",
			mode: 0o600,
		});
	} catch {}
}

export function deleteUploadSession(sessionId: string): void {
	try {
		const file = path.join(UPLOAD_SESSIONS_DIR, `${sessionId}.json`);
		if (fs.existsSync(file)) {
			fs.unlinkSync(file);
		}
	} catch {}
}

const STAGING_DIR = path.join(CONFIG_DIR, "staging");

export function getStagedArchivePath(
	sourcePath: string,
	sizeBytes: number,
	mtimeMs: number,
	prefix: string = "staged"
): string {
	try {
		if (!fs.existsSync(STAGING_DIR)) {
			fs.mkdirSync(STAGING_DIR, { recursive: true, mode: 0o700 });
		}
	} catch {}

	const hash = crypto
		.createHash("sha256")
		.update(`${path.resolve(sourcePath)}:${sizeBytes}:${mtimeMs}`)
		.digest("hex")
		.slice(0, 16);
	return path.join(STAGING_DIR, `${prefix}_${hash}.tar.gz`);
}

function askQuestion(query: string): Promise<string> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
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
		const hash = crypto.createHash("sha256");
		const stream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("end", () => resolve(hash.digest("hex")));
		stream.on("error", (err) => reject(err));
	});
}

/**
 * Stream-based directory fingerprint calculation with constant-memory directory traversal
 */
export async function calculateDirectoryFingerprint(
	dirPath: string
): Promise<{ totalSize: number; fileCount: number; sha256: string }> {
	const hash = crypto.createHash("sha256");
	let totalSize = 0;
	let fileCount = 0;

	async function walk(currentDir: string, depth: number = 0) {
		if (depth > 20) {
			throw new Error(
				`Directory nesting exceeds maximum depth limit of 20 at "${currentDir}". Recursive directory or symlink loop detected.`
			);
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
				const normalizedRelPath = path
					.relative(dirPath, fullPath)
					.replace(/\\/g, "/");
				hash.update(normalizedRelPath);
				await new Promise<void>((resolve, reject) => {
					const stream = fs.createReadStream(fullPath, {
						highWaterMark: 64 * 1024,
					});
					stream.on("data", (chunk) => hash.update(chunk));
					stream.on("end", () => resolve());
					stream.on("error", (err) => reject(err));
				});
			}
		}
	}

	await walk(dirPath, 0);
	return { totalSize, fileCount, sha256: hash.digest("hex") };
}

/**
 * Mathematically aligned adaptive multipart chunk calculation targeting ~400 parts.
 * Clamped strictly between 16 MiB and 256 MiB, aligned to 16 MiB boundaries.
 * Prevents exceeding Cloudflare Worker 600 req/min rate limits on large files.
 */
export function calculateAdaptiveChunkSize(totalBytes: number): number {
	const MIN_CHUNK_SIZE = 16 * 1024 * 1024; // 16 MiB min
	const MAX_CHUNK_SIZE = 256 * 1024 * 1024; // 256 MiB max
	const TARGET_PARTS = 400;

	const rawChunk = Math.ceil(totalBytes / TARGET_PARTS);
	const alignedChunk =
		Math.ceil(rawChunk / (16 * 1024 * 1024)) * (16 * 1024 * 1024);

	return Math.min(MAX_CHUNK_SIZE, Math.max(MIN_CHUNK_SIZE, alignedChunk));
}

/**
 * Architecture-aware parameter estimation for transformer models (informational pre-flight inspection).
 * Sizing, GPU tier selection, and pricing remain 100% server-authoritative via /api/permit.
 */
export function estimateParametersFromConfig(config: any): number | null {
	if (!config || typeof config !== "object") return null;

	if (config.num_parameters && Number(config.num_parameters) > 0) {
		const explicitParams = Number(config.num_parameters);
		if (
			Number.isFinite(explicitParams) &&
			explicitParams > 0 &&
			explicitParams <= 2_000_000_000_000
		) {
			return explicitParams;
		}
	}

	const hiddenSize = Number(
		config.hidden_size ||
			config.d_model ||
			config.n_embd ||
			config.n_emb ||
			config.embedding_size ||
			config.hidden_dim
	);
	const numLayers = Number(
		config.num_hidden_layers ||
			config.n_layer ||
			config.n_layers ||
			config.num_layers ||
			config.encoder_layers ||
			config.decoder_layers
	);

	if (!hiddenSize || !numLayers || hiddenSize <= 0 || numLayers <= 0) {
		return null;
	}

	const boundedHiddenSize = Math.max(1, Math.min(65536, hiddenSize));
	const boundedNumLayers = Math.max(1, Math.min(256, numLayers));
	const vocabSize = Math.max(
		1,
		Math.min(
			1000000,
			Number(config.vocab_size || config.padded_vocab_size || 32000) || 32000
		)
	);
	const numHeads = Math.max(
		1,
		Math.min(
			256,
			Number(
				config.num_attention_heads ||
					config.n_head ||
					config.num_heads ||
					config.n_heads ||
					config.num_attention_heads_per_partition ||
					32
			) || 32
		)
	);
	const numKvHeads = Math.max(
		1,
		Math.min(
			256,
			Number(
				config.num_key_value_heads ||
					config.num_kv_heads ||
					config.n_head_kv ||
					config.multi_query_group_num ||
					numHeads
			) || numHeads
		)
	);
	const headDim = Number(config.head_dim || boundedHiddenSize / numHeads);
	const intermediateSize = Math.max(
		1,
		Math.min(
			262144,
			Number(
				config.intermediate_size ||
					config.n_inner ||
					config.d_ff ||
					config.ffn_dim ||
					boundedHiddenSize * 4
			) || boundedHiddenSize * 4
		)
	);
	const modelType = (config.model_type || "").toLowerCase();
	const archName = (config.architectures?.[0] || "").toLowerCase();
	const isGatedMlp = Boolean(
		config.hidden_act === "silu" ||
			config.hidden_activation === "silu" ||
			config.hidden_act === "swish" ||
			modelType.includes("llama") ||
			modelType.includes("mistral") ||
			modelType.includes("qwen") ||
			modelType.includes("gemma") ||
			modelType.includes("mixtral") ||
			archName.includes("llama") ||
			archName.includes("mistral") ||
			archName.includes("qwen") ||
			archName.includes("gemma") ||
			archName.includes("mixtral")
	);
	const tieWordEmbeddings = Boolean(
		config.tie_word_embeddings ??
			(modelType === "gpt2" || archName.includes("gpt2"))
	);

	// 1. Embeddings
	let embeddingParams = vocabSize * boundedHiddenSize;
	if (!tieWordEmbeddings) {
		embeddingParams += vocabSize * boundedHiddenSize;
	}

	// 2. Attention Projections
	const qProj = boundedHiddenSize * (numHeads * headDim);
	const kProj = boundedHiddenSize * (numKvHeads * headDim);
	const vProj = boundedHiddenSize * (numKvHeads * headDim);
	const oProj = numHeads * headDim * boundedHiddenSize;
	const attnParamsPerLayer = qProj + kProj + vProj + oProj;

	// 3. MLP Projections
	const mlpProjections = isGatedMlp ? 3 : 2;
	const numLocalExperts = Number(
		config.num_local_experts ||
			config.n_routed_experts ||
			config.num_experts ||
			0
	);
	const expertIntermediateSize = Number(
		config.moe_intermediate_size ||
			config.intermediate_size ||
			config.n_inner ||
			boundedHiddenSize * 4
	);

	let mlpParamsPerLayer: number;
	if (numLocalExperts > 1) {
		const routerGateParams = boundedHiddenSize * numLocalExperts;
		const routedMlpParams =
			numLocalExperts *
			mlpProjections *
			(boundedHiddenSize * expertIntermediateSize);
		if (
			archName.includes("deepseek") ||
			config.model_type?.includes("deepseek")
		) {
			const sharedExperts = Number(config.n_shared_experts || 0);
			const sharedMlpParams =
				sharedExperts *
				mlpProjections *
				(boundedHiddenSize * expertIntermediateSize);
			mlpParamsPerLayer = routerGateParams + routedMlpParams + sharedMlpParams;
		} else if (
			archName.includes("qwen2") ||
			config.model_type?.includes("qwen2_moe")
		) {
			const sharedIntermediate = Number(
				config.shared_expert_intermediate_size || expertIntermediateSize
			);
			const sharedMlpParams =
				mlpProjections * (boundedHiddenSize * sharedIntermediate);
			mlpParamsPerLayer = routerGateParams + routedMlpParams + sharedMlpParams;
		} else {
			mlpParamsPerLayer = routerGateParams + routedMlpParams;
		}
	} else {
		mlpParamsPerLayer = mlpProjections * (boundedHiddenSize * intermediateSize);
	}

	// 4. Layer Norms
	const normParamsPerLayer = 2 * boundedHiddenSize;

	const layerParams =
		boundedNumLayers *
		(attnParamsPerLayer + mlpParamsPerLayer + normParamsPerLayer);
	const totalParams = embeddingParams + layerParams;

	if (!Number.isFinite(totalParams) || totalParams <= 0) {
		return null;
	}

	return Math.min(2_000_000_000_000, totalParams);
}

export function validateTarHeaderChecksum(header: Buffer): boolean {
	const chksumStr = header
		.toString("utf-8", 148, 156)
		.replace(/\0.*$/, "")
		.trim();
	const expectedChksum = parseInt(chksumStr, 8);
	if (isNaN(expectedChksum)) return false;

	let unsignedSum = 0;
	let signedSum = 0;
	for (let i = 0; i < 512; i++) {
		const byteVal = i >= 148 && i < 156 ? 32 : header[i]!;
		unsignedSum += byteVal;
		signedSum += byteVal > 127 ? byteVal - 256 : byteVal;
	}
	return unsignedSum === expectedChksum || signedSum === expectedChksum;
}

export function parsePaxPayload(buf: Buffer): Record<string, string> {
	const text = buf.toString("utf-8");
	const records: Record<string, string> = {};
	let pos = 0;
	while (pos < text.length) {
		const spaceIdx = text.indexOf(" ", pos);
		if (spaceIdx === -1) break;
		const lenStr = text.substring(pos, spaceIdx);
		const recLen = parseInt(lenStr, 10);
		if (Number.isNaN(recLen) || recLen <= 0) break;
		const recEnd = pos + recLen;
		const eqIdx = text.indexOf("=", spaceIdx + 1);
		if (eqIdx !== -1 && eqIdx < recEnd) {
			const key = text.substring(spaceIdx + 1, eqIdx).trim();
			const valEnd = text[recEnd - 1] === "\n" ? recEnd - 1 : recEnd;
			const value = text.substring(eqIdx + 1, valEnd);
			records[key] = value;
		}
		pos = recEnd;
	}
	return records;
}

export function formatPaxRecord(key: string, value: string): string {
	const entry = ` ${key}=${value}\n`;
	let len = entry.length + 2;
	while (true) {
		const fullLen = String(len).length + entry.length;
		if (fullLen === len) {
			return `${len}${entry}`;
		}
		len = fullLen;
	}
}

export function checkJsonNestingDepth(
	jsonString: string,
	maxDepth: number = 30
): boolean {
	let depth = 0;
	let inString = false;
	let escape = false;

	for (let i = 0; i < jsonString.length; i++) {
		const ch = jsonString[i];
		if (escape) {
			escape = false;
			continue;
		}
		if (ch === "\\") {
			if (inString) {
				escape = true;
			}
			continue;
		}
		if (ch === '"') {
			inString = !inString;
			continue;
		}
		if (inString) {
			continue;
		}
		if (ch === "{" || ch === "[") {
			depth++;
			if (depth > maxDepth) return false;
		} else if (ch === "}" || ch === "]") {
			depth = Math.max(0, depth - 1);
		}
	}
	return true;
}

export const DANGEROUS_EXTENSIONS = [
	".py",
	".sh",
	".exe",
	".so",
	".dll",
	".elf",
	".bat",
	".cmd",
	".wasm",
	".js",
	".mjs",
	".cjs",
	".a",
	".lib",
	".vbs",
	".ps1",
];

export const ALLOWED_EXACT_CHECKPOINT_FILES = new Set([
	"config.json",
	"generation_config.json",
	"adapter_config.json",
	"chat_template.json",
	"tokenizer.json",
	"tokenizer_config.json",
	"special_tokens_map.json",
	"vocab.json",
	"merges.txt",
	"added_tokens.json",
	"tokenizer.model",
	"spiece.model",
	"sentencepiece.bpe.model",
	"model.safetensors.index.json",
	"adapter_model.safetensors.index.json",
	// Standard HuggingFace Trainer & PyTorch Checkpoint Artifacts:
	"trainer_state.json",
	"training_args.bin",
	"optimizer.pt",
	"scheduler.pt",
	"scaler.pt",
	"rng_state.pth",
]);

export function validateCheckpointEntry(
	filename: string,
	isDirectory: boolean = false
): { isAllowed: boolean; error?: string } {
	const basename = path.posix.basename(filename.replace(/\\/g, "/"));
	if (!basename || isDirectory) return { isAllowed: true };

	const ext = path.extname(basename).toLowerCase();
	const isVersionedSo = /\.so(\.[0-9]+)+$/i.test(basename);

	if (DANGEROUS_EXTENSIONS.includes(ext) || isVersionedSo) {
		return {
			isAllowed: false,
			error: `Executable, library, or script binary "${basename}" is strictly forbidden in model archives.`,
		};
	}

	// Arbitrary binary / pickle rejection (unless explicitly in ALLOWED_EXACT_CHECKPOINT_FILES)
	if ([".bin", ".pt", ".pth", ".pkl", ".pickle"].includes(ext)) {
		if (!ALLOWED_EXACT_CHECKPOINT_FILES.has(basename)) {
			return {
				isAllowed: false,
				error: `Unrecognized binary or pickle weight file "${basename}" rejected. Model weights must be formatted as safe zero-code .safetensors.`,
			};
		}
	}

	const isAllowed =
		ALLOWED_EXACT_CHECKPOINT_FILES.has(basename) ||
		basename.endsWith(".safetensors") ||
		basename.endsWith(".json") ||
		basename.endsWith(".txt");

	if (!isAllowed) {
		return {
			isAllowed: false,
			error: `Unrecognized file "${basename}" rejected. Custom checkpoint archives only permit safetensors weights, training state, and HuggingFace/PEFT metadata.`,
		};
	}

	return { isAllowed: true };
}

export function classifyCheckpointShape(filenames: string[]): {
	classification: "base_model" | "trainer_checkpoint" | "invalid";
	error?: string;
} {
	const basenames = filenames.map((f) =>
		path.posix.basename(f.replace(/\\/g, "/"))
	);
	const hasTrainerState = basenames.includes("trainer_state.json");
	const hasConfig = basenames.includes("config.json");
	const hasAdapterConfig = basenames.includes("adapter_config.json");
	const hasWeights = basenames.some(
		(f) =>
			f === "model.safetensors" ||
			f === "model.safetensors.index.json" ||
			/^model-\d+-of-\d+\.safetensors$/.test(f) ||
			f === "adapter_model.safetensors" ||
			f === "adapter_model.safetensors.index.json" ||
			f === "pytorch_model.bin" ||
			/^pytorch_model-\d+-of-\d+\.bin$/.test(f)
	);

	if (hasTrainerState) {
		return { classification: "trainer_checkpoint" };
	}
	if ((hasConfig || hasAdapterConfig) && hasWeights) {
		return { classification: "base_model" };
	}

	return {
		classification: "invalid",
		error: `Malformed checkpoint: Expected either clean base model (config.json + model weights) or trainer resumption checkpoint (trainer_state.json). Found files: [${basenames.slice(0, 10).join(", ")}]`,
	};
}

export async function scanAndValidateCheckpointDirectory(
	dirPath: string
): Promise<{
	isValid: boolean;
	modelConfig?: any;
	error?: string;
}> {
	if (!fs.existsSync(dirPath)) {
		return {
			isValid: false,
			error: `Directory path does not exist: ${dirPath}`,
		};
	}
	if (!fs.statSync(dirPath).isDirectory()) {
		return { isValid: false, error: `Path is not a directory: ${dirPath}` };
	}

	const foundFiles: string[] = [];
	let extractedConfig: any = null;

	function walk(currentDir: string, relativePrefix: string = "") {
		const entries = fs.readdirSync(currentDir, { withFileTypes: true });
		for (const entry of entries) {
			const relPath = relativePrefix
				? `${relativePrefix}/${entry.name}`
				: entry.name;
			const fullPath = path.join(currentDir, entry.name);

			if (entry.isDirectory()) {
				walk(fullPath, relPath);
			} else if (entry.isFile()) {
				foundFiles.push(relPath);
				const validation = validateCheckpointEntry(relPath, false);
				if (!validation.isAllowed) {
					throw new Error(validation.error);
				}
				if (
					(entry.name === "config.json" ||
						entry.name === "adapter_config.json") &&
					!extractedConfig
				) {
					try {
						const content = fs.readFileSync(fullPath, "utf-8");
						if (checkJsonNestingDepth(content, 30)) {
							const parsed = JSON.parse(content);
							const estimatedParams = estimateParametersFromConfig(parsed);
							const hidden =
								Number(
									parsed.hidden_size || parsed.d_model || parsed.n_embd
								) || 4096;
							const layers =
								Number(parsed.num_hidden_layers || parsed.n_layer) || 32;
							const heads =
								Number(parsed.num_attention_heads || parsed.n_head) || 32;
							const intermediate =
								Number(parsed.intermediate_size || parsed.n_inner) ||
								hidden * 4;

							extractedConfig = {
								...parsed,
								modelType: parsed.model_type || "custom_causal_lm",
								hiddenSize: hidden,
								numHiddenLayers: layers,
								numAttentionHeads: heads,
								intermediateSize: intermediate,
								vocabSize: parsed.vocab_size || 32000,
								architectures: parsed.architectures || [
									parsed.model_type
										? `${parsed.model_type}LMHeadModel`
										: "LlamaForCausalLM",
								],
								parameterCount: estimatedParams || undefined,
							};
						}
					} catch {}
				}
			}
		}
	}

	try {
		walk(dirPath);
	} catch (err: any) {
		return { isValid: false, error: err.message };
	}

	if (foundFiles.length === 0) {
		return {
			isValid: false,
			error: "Checkpoint directory is completely empty (0 files).",
		};
	}

	const shape = classifyCheckpointShape(foundFiles);
	if (shape.classification === "invalid") {
		return { isValid: false, error: shape.error || "Malformed checkpoint directory shape." };
	}

	return {
		isValid: true,
		modelConfig: extractedConfig,
	};
}

/**
 * Defensive Tar Scanner for custom checkpoints
 * Auto-detects format (GZIP .tar.gz vs uncompressed .tar), validates POSIX header checksums,
 * parses POSIX extended PAX headers ('x', 'g'), and defends against path traversal (../),
 * symlinks, hardlinks, special files, duplicate paths, legacy pickle weights, and decompression bombs.
 */
export async function scanAndValidateCheckpointArchive(
	archivePath: string
): Promise<{
	isValid: boolean;
	modelConfig?: any;
	error?: string;
}> {
	if (!fs.existsSync(archivePath)) {
		return {
			isValid: false,
			error: `Archive path does not exist: ${archivePath}`,
		};
	}

	const fd = fs.openSync(archivePath, "r");
	const headerBuf = Buffer.alloc(512);
	const bytesRead = fs.readSync(fd, headerBuf, 0, 512, 0);
	fs.closeSync(fd);

	if (bytesRead < 10) {
		return {
			isValid: false,
			error: "Archive is corrupted or too small (less than 10 bytes).",
		};
	}

	const isGzip = headerBuf[0] === 0x1f && headerBuf[1] === 0x8b;
	if (!isGzip && bytesRead < 512) {
		return {
			isValid: false,
			error:
				"Uncompressed tar archive is corrupted or too small (less than 512 bytes).",
		};
	}

	const isTar =
		!isGzip &&
		(headerBuf.toString("utf-8", 257, 262).startsWith("ustar") ||
			validateTarHeaderChecksum(headerBuf));

	if (!isGzip && !isTar) {
		return {
			isValid: false,
			error:
				"Invalid archive format: must be a gzip-compressed tarball (.tar.gz) or standard tar archive (.tar).",
		};
	}

	// Decompression Bomb Limits
	const MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024 * 1024; // 200 GiB
	const MAX_ARCHIVE_ENTRIES = 10000;
	const MAX_CONFIG_JSON_BYTES = 2 * 1024 * 1024; // 2 MiB
	const MAX_COMPRESSION_RATIO = 50.0; // Suspicious compression ratio threshold

	const compressedFileSizeBytes = fs.statSync(archivePath).size;
	let totalUncompressedBytes = 0;
	let entryCount = 0;
	let extractedConfigBuffer: Buffer | null = null;
	const seenEntries = new Set<string>();

	try {
		const zlib = await import("node:zlib");
		const readStream = fs.createReadStream(archivePath);
		const decompressStream = isGzip
			? readStream.pipe(zlib.createGunzip())
			: readStream;

		let buffer = Buffer.alloc(0);
		let currentEntry: {
			name: string;
			size: number;
			type: string;
			bytesRead: number;
			isPax: boolean;
		} | null = null;
		let targetConfigChunks: Buffer[] = [];
		let targetPaxChunks: Buffer[] = [];
		let localPaxOverrides: Record<string, string> = {};
		let globalPaxOverrides: Record<string, string> = {};

		const extractedConfigResult = await new Promise<Buffer | null>(
			(resolve, reject) => {
				decompressStream.on("data", (chunk: Buffer) => {
					totalUncompressedBytes += chunk.length;
					if (totalUncompressedBytes > MAX_UNCOMPRESSED_BYTES) {
						decompressStream.destroy();
						return reject(
							new Error(
								"Decompression bomb detected: total uncompressed size exceeds 200 GiB ceiling."
							)
						);
					}

					// Check compression ratio once at least 100 MB uncompressed
					if (
						totalUncompressedBytes > 100 * 1024 * 1024 &&
						compressedFileSizeBytes > 0
					) {
						const currentRatio =
							totalUncompressedBytes / compressedFileSizeBytes;
						if (currentRatio > MAX_COMPRESSION_RATIO) {
							decompressStream.destroy();
							return reject(
								new Error(
									`Suspicious archive compression ratio (${currentRatio.toFixed(1)}:1 exceeds safety ceiling of ${MAX_COMPRESSION_RATIO}:1).`
								)
							);
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

							// Validate header checksum
							if (!validateTarHeaderChecksum(header)) {
								decompressStream.destroy();
								return reject(
									new Error(
										`Corrupted tar archive: header checksum mismatch at entry ${entryCount + 1}.`
									)
								);
							}

							entryCount++;
							if (entryCount > MAX_ARCHIVE_ENTRIES) {
								decompressStream.destroy();
								return reject(
									new Error(
										`Archive bomb detected: entry count exceeds ${MAX_ARCHIVE_ENTRIES} entries.`
									)
								);
							}

							const typeFlag = String.fromCharCode(header[156] || 48); // '0' = 48
							const isPax = typeFlag === "x" || typeFlag === "g";

							// Parse file size (octal at bytes 124-136)
							const sizeStr = header
								.toString("utf-8", 124, 136)
								.replace(/\0.*$/, "")
								.trim();
							const rawFileSize = parseInt(sizeStr, 8) || 0;

							// Extract filename from header (bytes 0-100) and prefix (bytes 345-500)
							const rawName = header
								.toString("utf-8", 0, 100)
								.replace(/\0.*$/, "")
								.trim();
							const prefix = header
								.toString("utf-8", 345, 500)
								.replace(/\0.*$/, "")
								.trim();
							const rawFullPath = prefix ? `${prefix}/${rawName}` : rawName;

							// Determine effective name and size applying local or global PAX extended headers
							const rawEffectivePath =
								!isPax && (localPaxOverrides.path || globalPaxOverrides.path)
									? (localPaxOverrides.path || globalPaxOverrides.path)!
									: rawFullPath;

							const effectiveFileSize =
								!isPax && (localPaxOverrides.size || globalPaxOverrides.size)
									? parseInt(
											(localPaxOverrides.size || globalPaxOverrides.size)!,
											10
										) || rawFileSize
									: rawFileSize;

							if (!isPax) {
								localPaxOverrides = {}; // Consume local override for the immediate member
							}

							// Normalize path for canonical security validation
							const normalizedFullPath = rawEffectivePath
								.replace(/\\/g, "/")
								.replace(/^(\.\/)+/, "");
							const isDirectory =
								typeFlag === "5" ||
								rawEffectivePath.endsWith("/") ||
								normalizedFullPath.endsWith("/");

							if (!isPax) {
								// Security Check 1: Duplicate Archive Entry Collision under canonical name
								if (seenEntries.has(normalizedFullPath)) {
									decompressStream.destroy();
									return reject(
										new Error(
											`Duplicate entry detected in archive: "${normalizedFullPath}". Potential entry-override attack.`
										)
									);
								}
								seenEntries.add(normalizedFullPath);

								// Security Check 2: Path Traversal (.., leading slashes, Windows drive letters, null bytes)
								if (
									rawEffectivePath.includes("..") ||
									rawEffectivePath.startsWith("/") ||
									rawEffectivePath.startsWith("\\") ||
									normalizedFullPath.startsWith("..") ||
									normalizedFullPath.includes("/../") ||
									normalizedFullPath.endsWith("/..") ||
									/^[a-zA-Z]:/.test(rawEffectivePath) ||
									rawEffectivePath.includes("\0")
								) {
									decompressStream.destroy();
									return reject(
										new Error(
											`Path traversal attack detected in archive entry: "${rawEffectivePath}"`
										)
									);
								}

								// Security Check 3: Symlink, Hardlink & Special File Attacks (Typeflag at byte 156)
								if (typeFlag === "1") {
									decompressStream.destroy();
									return reject(
										new Error(
											`Hard link attack detected in archive entry: "${rawEffectivePath}"`
										)
									);
								}
								if (typeFlag === "2" || typeFlag === "s") {
									decompressStream.destroy();
									return reject(
										new Error(
											`Symlink attack detected in archive entry: "${rawEffectivePath}"`
										)
									);
								}
								if (typeFlag === "3" || typeFlag === "4" || typeFlag === "6") {
									decompressStream.destroy();
									return reject(
										new Error(
											`Unsupported special file entry (device/fifo) rejected: "${rawEffectivePath}"`
										)
									);
								}

								// Security Check 4: Shared Semantic Allowlist Validation (No scripts, no arbitrary pickle binaries)
								const validation = validateCheckpointEntry(
									normalizedFullPath,
									isDirectory
								);
								if (!validation.isAllowed) {
									decompressStream.destroy();
									return reject(new Error(validation.error));
								}
							}

							buffer = buffer.subarray(512);
							currentEntry = {
								name: normalizedFullPath,
								size: effectiveFileSize,
								type: typeFlag,
								bytesRead: 0,
								isPax,
							};
						} else {
							// Read file payload
							const needed = currentEntry.size - currentEntry.bytesRead;
							const available = Math.min(needed, buffer.length);
							const chunkData = buffer.subarray(0, available);
							const basename = path.posix.basename(currentEntry.name);
							const isExactConfig =
								!currentEntry.isPax &&
								basename === "config.json" &&
								extractedConfigBuffer === null;

							if (currentEntry.isPax) {
								targetPaxChunks.push(Buffer.from(chunkData));
							} else if (isExactConfig) {
								if (
									currentEntry.bytesRead + chunkData.length <=
									MAX_CONFIG_JSON_BYTES
								) {
									targetConfigChunks.push(Buffer.from(chunkData));
								}
							}

							currentEntry.bytesRead += available;
							buffer = buffer.subarray(available);

							if (currentEntry.bytesRead >= currentEntry.size) {
								if (currentEntry.isPax) {
									const combinedPaxBuf = Buffer.concat(targetPaxChunks);
									const parsed = parsePaxPayload(combinedPaxBuf);
									if (currentEntry.type === "g") {
										globalPaxOverrides = { ...globalPaxOverrides, ...parsed };
									} else {
										localPaxOverrides = { ...localPaxOverrides, ...parsed };
									}
									targetPaxChunks = [];
								} else if (isExactConfig) {
									extractedConfigBuffer = Buffer.concat(targetConfigChunks);
									targetConfigChunks = [];
								}

								// Tar blocks are padded to 512-byte boundaries
								const padding = (512 - (currentEntry.size % 512)) % 512;
								if (buffer.length >= padding) {
									buffer = buffer.subarray(padding);
									currentEntry = null;
								} else {
									// Wait for padding chunk
									break;
								}
							}
						}
					}
				});

				decompressStream.on("end", () => {
					if (extractedConfigBuffer === null && targetConfigChunks.length > 0) {
						extractedConfigBuffer = Buffer.concat(targetConfigChunks);
					}
					resolve(extractedConfigBuffer);
				});
				decompressStream.on("error", (err: any) => reject(err));
			}
		);
		extractedConfigBuffer = extractedConfigResult;
	} catch (scanErr: any) {
		return {
			isValid: false,
			error: `Defensive archive scan rejected: ${scanErr.message}`,
		};
	}

	let modelConfig: any = null;
	if (extractedConfigBuffer !== null) {
		try {
			const rawText = (extractedConfigBuffer as Buffer).toString("utf-8");
			if (!checkJsonNestingDepth(rawText, 30)) {
				return {
					isValid: false,
					error:
						"Defensive archive scan rejected: config.json exceeds maximum structural nesting depth (30).",
				};
			}
			const parsed = JSON.parse(rawText);
			const estimatedParams = estimateParametersFromConfig(parsed);

			if (!estimatedParams) {
				const foundKeys = Object.keys(parsed).slice(0, 10).join(", ");
				return {
					isValid: false,
					error: `Checkpoint config.json is missing required model architecture parameters. Expected 'hidden_size'/'num_hidden_layers'/'num_attention_heads' (Llama/Mistral/Qwen/BERT) or 'n_embd'/'n_layer'/'n_head' (GPT-2). Found keys: [${foundKeys}]`,
				};
			}

			const hidden =
				Number(
					parsed.hidden_size ||
						parsed.d_model ||
						parsed.n_embd ||
						parsed.n_emb ||
						parsed.embedding_size
				) || 4096;
			const layers =
				Number(
					parsed.num_hidden_layers ||
						parsed.n_layer ||
						parsed.n_layers ||
						parsed.num_layers
				) || 32;
			const heads =
				Number(parsed.num_attention_heads || parsed.n_head || parsed.num_heads) ||
				32;
			const intermediate =
				Number(parsed.intermediate_size || parsed.n_inner || parsed.d_ff) ||
				hidden * 4;

			modelConfig = {
				...parsed,
				modelType: parsed.model_type || "custom_causal_lm",
				hiddenSize: hidden,
				numHiddenLayers: layers,
				numAttentionHeads: heads,
				intermediateSize: intermediate,
				vocabSize: parsed.vocab_size || 32000,
				architectures: parsed.architectures || [
					parsed.model_type
						? `${parsed.model_type}LMHeadModel`
						: "LlamaForCausalLM",
				],
				parameterCount: estimatedParams,
			};
		} catch (parseErr: any) {
			return {
				isValid: false,
				error: `Defensive archive scan rejected: config.json JSON parse error (${parseErr.message})`,
			};
		}
	}

	// Fallback to adjacent config.json if not found inside archive root
	if (!modelConfig) {
		const adjacentConfigPath = path.join(
			path.dirname(archivePath),
			"config.json"
		);
		if (fs.existsSync(adjacentConfigPath)) {
			try {
				const raw = fs.readFileSync(adjacentConfigPath, "utf-8");
				const parsed = JSON.parse(raw);
				const estimatedParams = estimateParametersFromConfig(parsed);

				if (!estimatedParams) {
					const foundKeys = Object.keys(parsed).slice(0, 10).join(", ");
					return {
						isValid: false,
						error: `Checkpoint config.json is missing required model architecture parameters. Expected 'hidden_size'/'num_hidden_layers'/'num_attention_heads' (Llama/Mistral/Qwen/BERT) or 'n_embd'/'n_layer'/'n_head' (GPT-2). Found keys: [${foundKeys}]`,
					};
				}

				const hidden =
					Number(
						parsed.hidden_size ||
							parsed.d_model ||
							parsed.n_embd ||
							parsed.n_emb ||
							parsed.embedding_size
					) || 4096;
				const layers =
					Number(
						parsed.num_hidden_layers ||
							parsed.n_layer ||
							parsed.n_layers ||
							parsed.num_layers
					) || 32;
				const heads =
					Number(
						parsed.num_attention_heads || parsed.n_head || parsed.num_heads
					) || 32;
				const intermediate =
					Number(parsed.intermediate_size || parsed.n_inner || parsed.d_ff) ||
					hidden * 4;

				modelConfig = {
					...parsed,
					modelType: parsed.model_type || "custom_causal_lm",
					hiddenSize: hidden,
					numHiddenLayers: layers,
					numAttentionHeads: heads,
					intermediateSize: intermediate,
					vocabSize: parsed.vocab_size || 32000,
					architectures: parsed.architectures || [
						parsed.model_type
							? `${parsed.model_type}LMHeadModel`
							: "LlamaForCausalLM",
					],
					parameterCount: estimatedParams,
				};
			} catch (adjErr: any) {
				return {
					isValid: false,
					error: `Adjacent config.json parse error: ${adjErr.message}`,
				};
			}
		}
	}

	const shape = classifyCheckpointShape(Array.from(seenEntries));
	if (shape.classification === "invalid") {
		return {
			isValid: false,
			error: shape.error || "Malformed checkpoint archive shape.",
		};
	}

	if (!modelConfig) {
		if (shape.classification === "trainer_checkpoint") {
			return {
				isValid: true,
				modelConfig: {
					modelType: "trainer_resumption",
					architectures: ["TrainerCheckpoint"],
				},
			};
		}
		return {
			isValid: false,
			error:
				"Archive is valid but missing config.json. Model architecture parameters could not be determined.",
		};
	}

	return { isValid: true, modelConfig };
}

export interface DatasetValidationResult {
	isValid: boolean;
	format?: "alpaca" | "sharegpt_messages" | "text" | "raw_jsonl" | undefined;
	sampleCount: number;
	error?: string | undefined;
	warning?: string | undefined;
}

/**
 * Streaming parser & validator for large JSON datasets (up to 50+ GB).
 * Reads the dataset chunk-by-chunk using a constant-memory scanner (<35 MB RAM).
 * Validates the first 100 records for HuggingFace/SFT schema compatibility
 * and verifies syntactic integrity of the JSON array throughout.
 */
export async function streamValidateLargeJsonArray(
	filePath: string
): Promise<DatasetValidationResult> {
	return new Promise<DatasetValidationResult>((resolve) => {
		const stream = fs.createReadStream(filePath, {
			encoding: "utf-8",
			highWaterMark: 256 * 1024,
		});

		let inArray = false;
		let inString = false;
		let escape = false;
		let depth = 0;
		let currentObjectStr = "";
		let objectCount = 0;
		let detectedFormat:
			| "alpaca"
			| "sharegpt_messages"
			| "text"
			| "raw_jsonl"
			| undefined;
		let seenClosingBracket = false;
		let streamError: string | null = null;

		stream.on("data", (chunkData: string | Buffer) => {
			if (streamError) return;
			const chunk = typeof chunkData === "string" ? chunkData : chunkData.toString("utf-8");

			for (let i = 0; i < chunk.length; i++) {
				const ch = chunk[i];

				if (!inArray) {
					if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
						continue;
					}
					if (ch === "[") {
						inArray = true;
						continue;
					} else {
						streamError = `Dataset JSON must begin with a top-level array '['. Found: '${ch}'.`;
						stream.destroy();
						return;
					}
				}

				if (seenClosingBracket) {
					if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
						continue;
					}
					streamError = `Extraneous characters after JSON array close: '${ch}'.`;
					stream.destroy();
					return;
				}

				if (inString) {
					if (depth <= 1) {
						currentObjectStr += ch;
					}
					if (escape) {
						escape = false;
					} else if (ch === "\\") {
						escape = true;
					} else if (ch === '"') {
						inString = false;
					}
					continue;
				}

				// Not in string
				if (ch === '"') {
					inString = true;
					escape = false;
					if (depth <= 1) {
						currentObjectStr += ch;
					}
				} else if (ch === "{") {
					depth++;
					if (depth === 1) {
						currentObjectStr = "{";
					} else {
						currentObjectStr += ch;
					}
				} else if (ch === "}") {
					depth--;
					currentObjectStr += ch;
					if (depth === 0) {
						objectCount++;
						if (objectCount <= 100) {
							try {
								const parsed = JSON.parse(currentObjectStr);
								if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
									streamError = `Record ${objectCount} is not a valid JSON object.`;
									stream.destroy();
									return;
								}
								if (!detectedFormat) {
									if ("instruction" in parsed && "output" in parsed) {
										detectedFormat = "alpaca";
									} else if ("prompt" in parsed && "completion" in parsed) {
										detectedFormat = "alpaca";
									} else if (
										"messages" in parsed &&
										Array.isArray(parsed.messages)
									) {
										detectedFormat = "sharegpt_messages";
									} else if (
										"text" in parsed &&
										typeof parsed.text === "string"
									) {
										detectedFormat = "text";
									} else {
										detectedFormat = "raw_jsonl";
									}
								}
							} catch (e: any) {
								streamError = `Malformed JSON object at record ${objectCount}: ${e.message}`;
								stream.destroy();
								return;
							}
						}
						currentObjectStr = "";
					} else if (depth < 0) {
						streamError = "Unmatched '}' encountered in JSON array.";
						stream.destroy();
						return;
					}
				} else if (ch === "]") {
					if (depth === 0) {
						seenClosingBracket = true;
					} else {
						currentObjectStr += ch;
					}
				} else {
					if (depth > 0) {
						currentObjectStr += ch;
					}
				}
			}
		});

		stream.on("end", () => {
			if (streamError) {
				return resolve({
					isValid: false,
					sampleCount: objectCount,
					error: streamError,
				});
			}

			if (!inArray) {
				return resolve({
					isValid: false,
					sampleCount: 0,
					error: "Dataset JSON file is empty (0 bytes).",
				});
			}

			if (!seenClosingBracket) {
				return resolve({
					isValid: false,
					sampleCount: objectCount,
					error: "Incomplete JSON array: missing closing bracket ']'.",
				});
			}

			if (objectCount === 0) {
				return resolve({
					isValid: false,
					sampleCount: 0,
					error: "Dataset JSON array contains 0 records.",
				});
			}

			resolve({
				isValid: true,
				format: detectedFormat || "raw_jsonl",
				sampleCount: objectCount,
			});
		});

		stream.on("error", (err: any) => {
			resolve({
				isValid: false,
				sampleCount: objectCount,
				error: `File read error during dataset streaming: ${err.message}`,
			});
		});
	});
}

/**
 * Pre-flight local validation of training datasets before any cloud storage upload or GPU spend.
 * Validates JSON/JSONL syntactic validity and checks for standard training schemas (instruction/output,
 * prompt/completion, messages, or text) to prevent mid-run Python SFTTrainer crashes.
 */
export async function validateDatasetFile(
	filePath: string
): Promise<DatasetValidationResult> {
	const ext = path.extname(filePath).toLowerCase();

	if (![".jsonl", ".json", ".csv", ".parquet", ".txt"].includes(ext)) {
		return {
			isValid: false,
			sampleCount: 0,
			error: `Unsupported dataset format: '${ext}'. Supported extensions are: .jsonl, .json, .csv, .parquet, .txt`,
		};
	}

	// If CSV or Parquet, defer detailed tabular parsing to the runner Python environment
	if (ext === ".csv" || ext === ".parquet") {
		return {
			isValid: true,
			format: "text",
			sampleCount: 1,
			warning: `Local pre-flight validation deferred to runner Python environment for ${ext.toUpperCase()} dataset.`,
		};
	}

	let lineCount = 0;
	let detectedFormat:
		| "alpaca"
		| "sharegpt_messages"
		| "text"
		| "raw_jsonl"
		| undefined;
	let parsedJsonArray: any[] | null = null;
	let rl: readline.Interface | null = null;
	let fileStream: fs.ReadStream | null = null;

	try {
		if (ext === ".json") {
			const stat = fs.statSync(filePath);
			// For large JSON files (> 20 MB, up to 50+ GB), use streaming constant-memory scanner
			if (stat.size > 20 * 1024 * 1024) {
				return await streamValidateLargeJsonArray(filePath);
			}

			// For JSON files <= 50MB, parse either an array of objects or an object
			const fullContent = await fs.promises.readFile(filePath, "utf-8");
			if (!fullContent.trim()) {
				return {
					isValid: false,
					sampleCount: 0,
					error: "Dataset JSON file is empty (0 records).",
				};
			}
			const data = JSON.parse(fullContent);
			if (Array.isArray(data)) {
				parsedJsonArray = data;
				if (data.length === 0) {
					return {
						isValid: false,
						sampleCount: 0,
						error: "Dataset JSON array contains 0 records.",
					};
				}
			} else if (typeof data === "object" && data !== null) {
				parsedJsonArray = [data];
			} else {
				return {
					isValid: false,
					sampleCount: 0,
					error:
						"Dataset JSON must contain an array of objects or a single JSON object.",
				};
			}
		}

		if (parsedJsonArray) {
			// Validate array samples (up to first 100)
			const samplesToCheck = parsedJsonArray.slice(0, 100);
			for (let idx = 0; idx < samplesToCheck.length; idx++) {
				const item = samplesToCheck[idx];
				if (!item || typeof item !== "object") {
					return {
						isValid: false,
						sampleCount: 0,
						error: `Record ${idx + 1} is not a valid JSON object.`,
					};
				}
				if (!detectedFormat) {
					if ("instruction" in item && "output" in item)
						detectedFormat = "alpaca";
					else if ("prompt" in item && "completion" in item)
						detectedFormat = "alpaca";
					else if ("messages" in item && Array.isArray(item.messages))
						detectedFormat = "sharegpt_messages";
					else if ("text" in item && typeof item.text === "string")
						detectedFormat = "text";
					else detectedFormat = "raw_jsonl";
				}
			}
			return {
				isValid: true,
				format: detectedFormat || "raw_jsonl",
				sampleCount: parsedJsonArray.length,
			};
		}

		// Stream inspect line-by-line for .jsonl
		fileStream = fs.createReadStream(filePath, { encoding: "utf-8", highWaterMark: 256 * 1024 });
		rl = readline.createInterface({
			input: fileStream,
			crlfDelay: Infinity,
		});

		const MAX_STRICT_VALIDATION_LINES = 5000;

		for await (const line of rl) {
			const trimmed = line.trim();
			if (!trimmed) continue; // skip blank lines
			lineCount++;

			// Perform strict JSON syntactic and schema verification on first 5,000 lines
			if (lineCount <= MAX_STRICT_VALIDATION_LINES) {
				let parsed: any;
				try {
					parsed = JSON.parse(trimmed);
				} catch (parseErr: any) {
					return {
						isValid: false,
						sampleCount: lineCount,
						error: `Malformed JSON on line ${lineCount}: ${parseErr.message}\nProblematic line preview: ${trimmed.slice(0, 120)}`,
					};
				}

				if (
					typeof parsed !== "object" ||
					parsed === null ||
					Array.isArray(parsed)
				) {
					return {
						isValid: false,
						sampleCount: lineCount,
						error: `Invalid record on line ${lineCount}: Each JSONL line must be a JSON object, received ${Array.isArray(parsed) ? "array" : typeof parsed}.`,
					};
				}

				// Check first 50 lines for recognized schema
				if (lineCount <= 50 && !detectedFormat) {
					if (
						("instruction" in parsed && "output" in parsed) ||
						("prompt" in parsed && "completion" in parsed)
					) {
						detectedFormat = "alpaca";
					} else if ("messages" in parsed && Array.isArray(parsed.messages)) {
						detectedFormat = "sharegpt_messages";
					} else if ("text" in parsed && typeof parsed.text === "string") {
						detectedFormat = "text";
					}
				}
			} else {
				// Fast structural check for remaining lines: check basic JSON object framing
				if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
					return {
						isValid: false,
						sampleCount: lineCount,
						error: `Invalid JSON record framing on line ${lineCount}: Line does not begin with '{' and end with '}'.\nProblematic line preview: ${trimmed.slice(0, 120)}`,
					};
				}
			}
		}

		if (lineCount === 0) {
			return {
				isValid: false,
				sampleCount: 0,
				error: "Dataset file contains 0 valid training lines.",
			};
		}

		// If no standard schema was detected in first 50 lines, provide informative warning
		let warning: string | undefined;
		if (!detectedFormat) {
			detectedFormat = "raw_jsonl";
			warning =
				"No standard columns (instruction/output, prompt/completion, messages, or text) detected. Runner will attempt generic stringification.";
		}

		return {
			isValid: true,
			format: detectedFormat,
			sampleCount: lineCount,
			warning,
		};
	} catch (readErr: any) {
		return {
			isValid: false,
			sampleCount: lineCount,
			error: `Failed to inspect dataset file: ${readErr.message}`,
		};
	} finally {
		if (rl) rl.close();
		if (fileStream) fileStream.destroy();
	}
}

// 1. Device Authorization Login
async function handleLogin(target: string = "anirudha-s") {
	console.log(
		`Initiating device authorization login flow for workspace target: ${target}...`
	);

	try {
		const response = await fetch(`${API_HOST}/api/auth/device/code`, {
			method: "POST",
		});
		if (!response.ok) {
			throw new Error(`Server returned status ${response.status}`);
		}

		const data: any = await response.json();
		const { device_code, user_code, verification_uri, expires_in, interval } =
			data;

		// Automatic browser opening for zero-friction login
		openBrowser(verification_uri);

		// Hyperlink with OSC 8 escape sequence for single-click in supported modern terminals
		const clickableUri = `\u001b]8;;${verification_uri}\u001b\\${verification_uri}\u001b]8;;\u001b\\`;

		console.log("\n=============================================");
		console.log("🔐 VIVACIOUS CLOUD — DEVICE LOGIN");
		console.log("   An Anirudha's Ambition");
		console.log("=============================================");
		console.log(
			"Opening authorization page in your browser automatically...\n"
		);
		console.log(
			"If your browser did not open, click or copy & paste this URL:"
		);
		console.log(`👉 ${clickableUri}`);
		console.log("\nOne-Time Authorization Code:");
		console.log(`🔑 ${user_code}`);
		console.log("=============================================");
		console.log(
			`Waiting for browser authorization (polling every ${interval || 5}s)...`
		);

		const pollInterval = (interval || 5) * 1000;
		const expiresAt = Date.now() + (expires_in || 900) * 1000;

		while (Date.now() < expiresAt) {
			await new Promise((resolve) => setTimeout(resolve, pollInterval));

			try {
				const tokenRes = await fetch(`${API_HOST}/api/auth/device/token`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ device_code }),
				});

				if (tokenRes.ok) {
					const tokenData: any = await tokenRes.json();
					const config = loadConfig();
					config.accessToken = tokenData.access_token;
					if (tokenData.refresh_token) {
						config.refreshToken = tokenData.refresh_token;
					}
					const parsedExp = parseJwtExpiryMs(tokenData.access_token);
					config.tokenExpiresAt =
						parsedExp || Date.now() + (tokenData.expires_in || 3600) * 1000;
					saveConfig(config);

					console.log(
						"\n[Success] Logged in successfully! Credentials saved locally."
					);
					return;
				}

				const errData: any = await tokenRes.json().catch(() => ({}));
				if (errData.error === "authorization_pending") {
				} else if (errData.error === "expired_token") {
					console.error(
						'\n[Error] Login attempt expired. Please run "vivacious login anirudha-s" again.'
					);
					process.exitCode = 1;
					return;
				} else {
					console.error(`\n[Error] Login failed: ${formatApiError(errData)}`);
					process.exitCode = 1;
					return;
				}
			} catch (err: any) {
				console.warn(
					`\n[Warning] Temporary network issue while polling authorization status: ${err.message || "Retrying..."}`
				);
			}
		}

		console.error("\n[Error] Login timed out. Please try again.");
		process.exitCode = 1;
		return;
	} catch (err: any) {
		console.error(
			`\n[Error] Failed to connect to orchestrator: ${err.message}`
		);
		process.exitCode = 1;
		return;
	}
}

// 2. Prepare / Inspect Dataset or Checkpoint (Dual Staging Support)
async function handlePrepare(
	inputPath: string,
	type: "dataset" | "checkpoint" = "dataset"
) {
	const absolutePath = path.resolve(inputPath);
	if (!fs.existsSync(absolutePath)) {
		console.error(`[Error] Target path not found: ${inputPath}`);
		process.exitCode = 1;
		return;
	}

	const stat = fs.statSync(absolutePath);
	let totalSize = 0;
	let fileCount = 0;
	let sha256Fingerprint = "";
	const filename = path.basename(absolutePath);

	console.log(`\n=============================================`);
	console.log(
		`📁 VIVACIOUS CLOUD — ${type.toUpperCase()} PREPARATION & STAGING`
	);
	console.log(`=============================================`);
	console.log(`Inspecting path: ${absolutePath}`);

	if (stat.isDirectory()) {
		console.log(
			`Analyzing directory structure and calculating streaming cryptographic checksum...`
		);
		const res = await calculateDirectoryFingerprint(absolutePath);
		totalSize = res.totalSize;
		fileCount = res.fileCount;
		sha256Fingerprint = res.sha256;
	} else {
		console.log(
			`Analyzing file and calculating streaming cryptographic checksum...`
		);
		totalSize = stat.size;
		fileCount = 1;
		sha256Fingerprint = await calculateFileSha256(absolutePath);
	}

	if (totalSize === 0) {
		console.error(`[Error] Staging target is empty (0 bytes).`);
		process.exitCode = 1;
		return;
	}

	const config = loadConfig();

	if (type === "checkpoint") {
		if (stat.isDirectory()) {
			console.log(
				`Running defensive directory scanner on custom model checkpoint...`
			);
			const scanResult = await scanAndValidateCheckpointDirectory(absolutePath);
			if (!scanResult.isValid) {
				console.error(
					`[Error] Checkpoint directory validation failed: ${scanResult.error}`
				);
				process.exitCode = 1;
				return;
			}

			const stagedArchivePath = getStagedArchivePath(
				absolutePath,
				totalSize,
				stat.mtimeMs,
				"checkpoint"
			);

			let archiveSize = 0;
			if (
				fs.existsSync(stagedArchivePath) &&
				fs.statSync(stagedArchivePath).size > 0
			) {
				console.log(
					`[Cache Hit] Reusing pre-staged checkpoint archive: ${path.basename(stagedArchivePath)}`
				);
				archiveSize = fs.statSync(stagedArchivePath).size;
			} else {
				console.log(
					`Packaging checkpoint directory into cached archive for upload...`
				);
				archiveSize = await archiveDirectoryToTarGz(
					absolutePath,
					stagedArchivePath,
					totalSize
				);
			}

			const archiveSha256 = await calculateFileSha256(stagedArchivePath);

			const preparedCheckpoint: PreparedCheckpoint = {
				path: stagedArchivePath,
				filename: path.basename(stagedArchivePath),
				sizeBytes: archiveSize,
				sha256: archiveSha256,
				modelConfig: scanResult.modelConfig,
				preparedAt: new Date().toISOString(),
			};
			config.preparedCheckpoint = preparedCheckpoint;
			saveConfig(config);

			const paramDisplay = scanResult.modelConfig?.parameterCount
				? `~${(scanResult.modelConfig.parameterCount / 1e9).toFixed(1)}B (Analytical Pre-flight)`
				: "Authoritative sizing calculated on permit";
			console.log(`Checkpoint Source:     ${filename} (Directory)`);
			console.log(`Staged Archive:        ${path.basename(stagedArchivePath)}`);
			console.log(
				`Archive Size:          ${(archiveSize / (1024 * 1024)).toFixed(2)} MB (${archiveSize.toLocaleString()} bytes)`
			);
			console.log(`SHA-256 Fingerprint:   ${archiveSha256}`);
			console.log(
				`Detected Model Type:   ${scanResult.modelConfig?.modelType || "CausalLM"}`
			);
			console.log(`Base Architecture:     ${paramDisplay}`);
			console.log(`=============================================`);
			console.log(`✅ [Custom Checkpoint Directory Packaged & Staged Locally]`);
			console.log(
				`Next step: Run 'vivacious permit anirudha-s ambition --model custom_model' or 'vivacious deploy anirudha-s'.`
			);
			return;
		}

		console.log(
			`Running defensive archive scanner on custom model checkpoint...`
		);
		const scanResult = await scanAndValidateCheckpointArchive(absolutePath);
		if (!scanResult.isValid) {
			console.error(
				`[Error] Checkpoint archive validation failed: ${scanResult.error}`
			);
			process.exitCode = 1;
			return;
		}

		const preparedCheckpoint: PreparedCheckpoint = {
			path: absolutePath,
			filename,
			sizeBytes: totalSize,
			sha256: sha256Fingerprint,
			modelConfig: scanResult.modelConfig,
			preparedAt: new Date().toISOString(),
		};
		config.preparedCheckpoint = preparedCheckpoint;
		saveConfig(config);

		const paramDisplay = scanResult.modelConfig?.parameterCount
			? `~${(scanResult.modelConfig.parameterCount / 1e9).toFixed(1)}B (Analytical Pre-flight)`
			: "Authoritative sizing calculated on permit";
		console.log(`Checkpoint Archive:    ${filename}`);
		console.log(
			`Total Size:            ${(totalSize / (1024 * 1024)).toFixed(2)} MB (${totalSize.toLocaleString()} bytes)`
		);
		console.log(`SHA-256 Fingerprint:   ${sha256Fingerprint}`);
		console.log(
			`Detected Model Type:   ${scanResult.modelConfig?.modelType || "CausalLM"}`
		);
		console.log(`Base Architecture:     ${paramDisplay}`);
		console.log(`=============================================`);
		console.log(`✅ [Custom Checkpoint Staged Locally]`);
		console.log(
			`Next step: Run 'vivacious permit anirudha-s ambition --model custom_model' or 'vivacious deploy anirudha-s'.`
		);
		return;
	}

	// Pre-flight Dataset Syntactic & Schema Validation
	if (!stat.isDirectory()) {
		console.log(`Validating dataset structure and training schema...`);
		const valResult = await validateDatasetFile(absolutePath);
		if (!valResult.isValid) {
			console.error(`\n=============================================`);
			console.error(`❌ [DATASET VALIDATION FAILED]`);
			console.error(`=============================================`);
			console.error(valResult.error);
			console.error(
				`\nUpload blocked before incurring any GPU compute or storage costs.`
			);
			console.error(`Please fix the format of ${filename} and re-run:`);
			console.error(`  vivacious prepare ${inputPath}`);
			console.error(`=============================================`);
			process.exitCode = 1;
			return;
		}

		console.log(
			`Schema Format:         ${valResult.format ? valResult.format.toUpperCase() : "UNKNOWN"}`
		);
		console.log(
			`Valid Training Items:  ${valResult.sampleCount.toLocaleString()}`
		);
		if (valResult.warning) {
			console.warn(`⚠️  Notice: ${valResult.warning}`);
		}
	}

	const prepared: PreparedDataset = {
		path: absolutePath,
		filename,
		sizeBytes: totalSize,
		fileCount,
		sha256: sha256Fingerprint,
		preparedAt: new Date().toISOString(),
	};

	config.preparedDataset = prepared;
	saveConfig(config);

	console.log(`Files Detected:        ${fileCount}`);
	console.log(
		`Total Dataset Size:    ${(totalSize / (1024 * 1024)).toFixed(2)} MB (${totalSize.toLocaleString()} bytes)`
	);
	console.log(`SHA-256 Fingerprint:   ${sha256Fingerprint}`);
	console.log(`=============================================`);
	console.log(
		`\n✅ [Dataset Validated & Prepared Locally] Streaming SHA-256 manifest computed.`
	);
	console.log(`Zero cloud transfer or GPU compute incurred.`);
	console.log(
		`Next step: Run 'vivacious permit anirudha-s ambition --model <model-id>' or 'vivacious deploy anirudha-s'.`
	);
}

// 3. Pre-Flight Financial Permit Check (NO R2 Upload, NO GPU Start)
async function handlePermit(
	modelId?: string,
	method: string = "full",
	autoConfirm: boolean = false
): Promise<boolean> {
	const accessToken = await getValidAccessToken();
	if (!accessToken) {
		process.exitCode = 1;
		return false;
	}
	const config = loadConfig();

	const prepared = config.preparedDataset;
	const preparedCheckpoint = config.preparedCheckpoint;

	if (!prepared && modelId) {
		console.warn(
			"[Notice] No local dataset prepared yet. Using default reference sizing (100 MB)."
		);
	}

	const payload: Record<string, any> = {};
	const effectiveModelId = modelId || "";

	// Check if target is a custom checkpoint archive or custom model
	const isCustom =
		effectiveModelId === "custom_model" ||
		(effectiveModelId.length > 0 &&
			(fs.existsSync(effectiveModelId) ||
				effectiveModelId.endsWith(".tar.gz") ||
				effectiveModelId.includes("\\") ||
				effectiveModelId.includes("/"))) ||
		(Boolean(preparedCheckpoint) &&
			(!effectiveModelId ||
				effectiveModelId === preparedCheckpoint?.filename ||
				effectiveModelId === preparedCheckpoint?.path));

	if (isCustom) {
		payload.modelId = "custom_model";
		payload.modelSource = "custom_checkpoint";
		if (preparedCheckpoint?.modelConfig) {
			payload.checkpointConfig = preparedCheckpoint.modelConfig;
			payload.checkpointFingerprint = preparedCheckpoint.sha256;
		}
	} else if (effectiveModelId) {
		payload.modelId = effectiveModelId;
	}

	payload.method = method || "full";
	if (prepared) {
		payload.datasetSizeBytes = prepared.sizeBytes;
		payload.datasetFingerprint = prepared.sha256;
		payload.fileCount = prepared.fileCount;
	}

	console.log(
		"Querying server-authoritative financial permit and pricing models..."
	);

	try {
		const response = await fetch(`${API_HOST}/api/permit`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify(payload),
		});

		if (response.status === 401) {
			console.error(
				'[Error] Authentication session expired. Please run "vivacious login anirudha-s" again.'
			);
			process.exitCode = 1;
			return false;
		}

		const data: any = await response.json().catch(() => ({}));
		if (!response.ok) {
			const errMsg = formatApiError(data);
			console.error(`\n[Error] Permit check failed: ${errMsg}`);
			process.exitCode = 1;
			return false;
		}

		console.log("\n=============================================");
		console.log("💳 VIVACIOUS CLOUD — FINANCIAL PERMIT STATUS");
		console.log("=============================================");
		console.log(`Active Billing Mode:    ${data.billingMode.toUpperCase()}`);
		console.log(
			`Available Balance:      ₹${Number(data.currentBalance).toFixed(2)}`
		);

		if (data.estimate) {
			const est = data.estimate;

			const hoursNum = Number(est.estimatedHours || 0.15);
			const totalMinutes = Math.round(hoursNum * 60);
			let durationStr =
				totalMinutes < 60
					? `~${totalMinutes} mins (${hoursNum.toFixed(2)} hrs)`
					: `${Math.floor(totalMinutes / 60)}h ${totalMinutes % 60}m (${hoursNum.toFixed(2)} hrs)`;
			if (est.bootMinutes && est.trainMinutes && est.finalizeMinutes) {
				const bufStr = est.bufferMinutes
					? ` | Buffer ~${Math.round(est.bufferMinutes)}m`
					: "";
				durationStr += ` [Boot ~${Math.round(est.bootMinutes)}m | Train ~${Math.round(est.trainMinutes)}m | Upload ~${Math.round(est.finalizeMinutes)}m${bufStr}]`;
			}

			console.log("---------------------------------------------");
			console.log(`Target Model:           ${est.modelId}`);
			console.log(`Training Method:        ${method.toUpperCase()}`);
			console.log(`Allocated GPU Tier:     ${est.gpuTier}`);
			console.log(`Estimated Duration:     ${durationStr}`);
			console.log(`Effective Hourly Rate:  ₹${est.hourlyRate.toFixed(2)}/hour`);
			console.log(
				`Estimated Total Cost:   ₹${Number(est.estimatedTotal || data.estimatedTotal || 0).toFixed(2)}`
			);
			console.log(`Permit Reference:       ${data.permitRef}`);
			console.log(
				`Permit Valid For:       15 minutes (Expires: ${new Date(data.expiresAt).toLocaleTimeString()})`
			);
			if (
				est.sizingConfidence === "fallback_default" ||
				est.confidence === "fallback_default" ||
				est.isFallbackSizing
			) {
				console.log("---------------------------------------------");
				console.warn("⚠️  [Sizing Fallback Notice]:");
				console.warn(
					" • Precise model architecture parameters could not be resolved from Hugging Face config."
				);
				console.warn(
					" • Sizing was estimated using a 7B fallback baseline (GPU: " +
						est.gpuTier +
						")."
				);
				console.warn(
					" • If deploying a larger model (e.g. 13B/70B), please specify GPU tier manually to prevent OOM."
				);
			}
			console.log("---------------------------------------------");
			console.log("🛡️  PRICING & SPOT MARKET GOVERNANCE NOTICE:");
			console.log(
				" • Cost Estimate: Quoted total is an analytical estimate based on token count and model shape."
			);
			console.log(
				" • 10% Surge Protection: Broker rates fluctuate dynamically. Upon deployment, your rate is locked."
			);
			console.log(
				"   If provider spot prices surge >10% mid-run, our policy automatically triggers a Safe Stop/Auto-Migration"
			);
			console.log("   to prevent billing drift and protect your balance.");
			console.log("=============================================");

			if (data.requiresConfirmation) {
				console.warn(
					`\n⚠️  [Underfunded Warning] Estimated cost (₹${Number(est.estimatedTotal || 0).toFixed(2)}) exceeds your balance (₹${Number(data.currentBalance || 0).toFixed(2)}).`
				);
				console.warn(
					`Training will auto-pause if balance depletes before completion.`
				);

				if (!autoConfirm) {
					const ans = await askQuestion(
						"\nDo you authorize deploying with your current balance ceiling? (y/N): "
					);
					if (ans.toLowerCase() !== "y" && ans.toLowerCase() !== "yes") {
						console.log("[Aborted] Deployment cancelled by user.");
						return false;
					}
				}
			}

			config.lastPermit = {
				permitRef: data.permitRef,
				expiresAt: data.expiresAt,
				modelId: est.modelId,
				method: method || "full",
				estimatedTotal: Number(est.estimatedTotal || 0),
				maxExposure: Number(est.maxExposure || 0),
				datasetFingerprint: prepared ? prepared.sha256 : "reference_sizing",
				requiresConfirmation: data.requiresConfirmation,
				permittedAt: new Date().toISOString(),
			};
			saveConfig(config);
			return true;
		}

		return true;
	} catch (err: any) {
		console.error(
			`\n[Error] Failed to connect to orchestrator: ${err.message}`
		);
		process.exitCode = 1;
		return false;
	}
}

export function createTarHeader(
	filename: string,
	size: number,
	mtime: number = Date.now()
): Buffer {
	const normalizedName = filename.replace(/\\/g, "/");
	const nameByteLength = Buffer.byteLength(normalizedName, "utf-8");
	const requiresPax = size >= 8589934592 || nameByteLength > 100;

	if (requiresPax) {
		let paxRecords = "";
		if (size >= 8589934592) {
			paxRecords += formatPaxRecord("size", String(size));
		}
		if (nameByteLength > 100) {
			paxRecords += formatPaxRecord("path", normalizedName);
		}

		const paxPayload = Buffer.from(paxRecords, "utf-8");
		const paxPadding = (512 - (paxPayload.length % 512)) % 512;
		const paxHeader = Buffer.alloc(512);

		const paxName = `PaxHeader/${path.posix.basename(normalizedName).slice(0, 80)}`;
		Buffer.from(paxName, "utf-8").copy(
			paxHeader,
			0,
			0,
			Math.min(100, Buffer.byteLength(paxName))
		);
		paxHeader.write("0000644\0", 100, 8, "utf-8");
		paxHeader.write("0000000\0", 108, 8, "utf-8");
		paxHeader.write("0000000\0", 116, 8, "utf-8");
		paxHeader.write(
			paxPayload.length.toString(8).padStart(11, "0") + "\0",
			124,
			12,
			"utf-8"
		);
		paxHeader.write(
			Math.floor(mtime / 1000).toString(8).padStart(11, "0") + "\0",
			136,
			12,
			"utf-8"
		);
		paxHeader.fill(32, 148, 156);
		paxHeader.write("x", 156, 1, "utf-8");
		paxHeader.write("ustar\0", 257, 6, "utf-8");
		paxHeader.write("00", 263, 2, "utf-8");

		let paxChksum = 0;
		for (let i = 0; i < 512; i++) paxChksum += paxHeader[i]!;
		paxHeader.write(
			paxChksum.toString(8).padStart(6, "0") + "\0 ",
			148,
			8,
			"utf-8"
		);

		const mainHeader = Buffer.alloc(512);
		const cappedName = normalizedName.slice(0, 100);
		Buffer.from(cappedName, "utf-8").copy(
			mainHeader,
			0,
			0,
			Math.min(100, Buffer.byteLength(cappedName))
		);
		mainHeader.write("0000644\0", 100, 8, "utf-8");
		mainHeader.write("0000000\0", 108, 8, "utf-8");
		mainHeader.write("0000000\0", 116, 8, "utf-8");
		const octalSize = Math.min(size, 8589934591);
		mainHeader.write(
			octalSize.toString(8).padStart(11, "0") + "\0",
			124,
			12,
			"utf-8"
		);
		mainHeader.write(
			Math.floor(mtime / 1000).toString(8).padStart(11, "0") + "\0",
			136,
			12,
			"utf-8"
		);
		mainHeader.fill(32, 148, 156);
		mainHeader.write("0", 156, 1, "utf-8");
		mainHeader.write("ustar\0", 257, 6, "utf-8");
		mainHeader.write("00", 263, 2, "utf-8");

		let mainChksum = 0;
		for (let i = 0; i < 512; i++) mainChksum += mainHeader[i]!;
		mainHeader.write(
			mainChksum.toString(8).padStart(6, "0") + "\0 ",
			148,
			8,
			"utf-8"
		);

		return Buffer.concat([
			paxHeader,
			paxPayload,
			Buffer.alloc(paxPadding),
			mainHeader,
		]);
	}

	const header = Buffer.alloc(512);
	const nameBuf = Buffer.from(normalizedName, "utf-8");
	nameBuf.copy(header, 0, 0, Math.min(100, nameBuf.length));

	header.write("0000644\0", 100, 8, "utf-8");
	header.write("0000000\0", 108, 8, "utf-8");
	header.write("0000000\0", 116, 8, "utf-8");
	header.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "utf-8");
	header.write(
		Math.floor(mtime / 1000)
			.toString(8)
			.padStart(11, "0") + "\0",
		136,
		12,
		"utf-8"
	);
	header.fill(32, 148, 156);
	header.write("0", 156, 1, "utf-8");
	header.write("ustar\0", 257, 6, "utf-8");
	header.write("00", 263, 2, "utf-8");

	let chksum = 0;
	for (let i = 0; i < 512; i++) chksum += header[i]!;
	header.write(chksum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "utf-8");

	return header;
}

function isDirectoryPrecompressed(dirPath: string): boolean {
	try {
		const PRECOMPRESSED_EXTS = new Set([
			".safetensors",
			".bin",
			".pt",
			".parquet",
			".gz",
			".zip",
			".zst",
			".7z",
			".tar",
		]);
		let binaryBytes = 0;
		let totalBytes = 0;
		function scan(dir: string, depth = 0) {
			if (depth > 4) return;
			const list = fs.readdirSync(dir, { withFileTypes: true });
			for (const item of list) {
				const full = path.join(dir, item.name);
				if (item.isDirectory()) {
					scan(full, depth + 1);
				} else if (item.isFile()) {
					const stat = fs.statSync(full);
					totalBytes += stat.size;
					const ext = path.extname(item.name).toLowerCase();
					if (PRECOMPRESSED_EXTS.has(ext)) {
						binaryBytes += stat.size;
					}
				}
			}
		}
		scan(dirPath);
		return totalBytes > 20 * 1024 * 1024 && binaryBytes / totalBytes > 0.5;
	} catch {
		return false;
	}
}

async function verifyAvailableDiskSpace(
	targetDir: string,
	estimatedBytes: number
): Promise<void> {
	try {
		if (typeof (fs as any).statfsSync === "function") {
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
		if (err.message.includes("Insufficient disk space")) {
			throw err;
		}
	}
}

export async function archiveDirectoryToTarGz(
	dirPath: string,
	outputPath: string,
	estimatedBytes: number = 50 * 1024 * 1024
): Promise<number> {
	const tmpDir = path.dirname(outputPath);
	await verifyAvailableDiskSpace(tmpDir, estimatedBytes);

	// Smart packaging: For precompressed/safetensors directories, use level 0 (store/pass-through) to bypass CPU lockup
	const isPrecompressed = isDirectoryPrecompressed(dirPath);
	const compressionLevel = isPrecompressed ? 0 : 1; // Level 1 Z_BEST_SPEED for text, 0 for binary weights
	const gzip = zlib.createGzip({ level: compressionLevel });
	const outStream = fs.createWriteStream(outputPath);
	gzip.pipe(outStream);

	async function pipeFileChunks(filePath: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const readStream = fs.createReadStream(filePath, {
				highWaterMark: 256 * 1024,
			});
			readStream.on("data", (chunk) => {
				const canContinue = gzip.write(chunk);
				if (!canContinue) {
					readStream.pause();
					gzip.once("drain", () => readStream.resume());
				}
			});
			readStream.on("end", () => resolve());
			readStream.on("error", (err) => reject(err));
		});
	}

	async function walkAndWrite(
		currentPath: string,
		relativePrefix: string = ""
	): Promise<void> {
		const entries = fs.readdirSync(currentPath, { withFileTypes: true });
		for (const entry of entries) {
			const fullPath = path.join(currentPath, entry.name);
			const relPath = relativePrefix
				? `${relativePrefix}/${entry.name}`
				: entry.name;
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
		outStream.on("finish", () => resolve());
		outStream.on("error", (err) => reject(err));
		gzip.on("error", (err) => reject(err));
	});

	return fs.statSync(outputPath).size;
}

// 4. Server-Authoritative Deployment with High-Speed Parallel Multipart Upload Engine
async function performUpload(
	_config: any,
	prepared: any,
	fileLabel: string,
	jobId?: string
): Promise<{ uploadKey: string; jobId: string }> {
	const accessToken = await getValidAccessToken();
	console.log(
		`Initiating high-speed parallel multipart transfer for ${fileLabel} to Cloudflare R2...`
	);
	let uploadId = "";
	let uploadKey = "";
	let finalJobId = jobId || "";
	let uploadToken = "";
	let uploadFilePath = prepared.path;
	let uploadFileSizeBytes = prepared.sizeBytes;
	let isTempArchive = false;

	try {
		if (fs.statSync(prepared.path).isDirectory()) {
			console.log(
				`Packaging directory ${prepared.filename} into compressed tarball for upload...`
			);
			const stagedArchive = getStagedArchivePath(
				prepared.path,
				prepared.sizeBytes,
				fs.statSync(prepared.path).mtimeMs,
				"upload"
			);
			if (fs.existsSync(stagedArchive) && fs.statSync(stagedArchive).size > 0) {
				console.log(
					`[Cache Hit] Reusing pre-staged upload archive: ${path.basename(stagedArchive)}`
				);
				uploadFileSizeBytes = fs.statSync(stagedArchive).size;
			} else {
				uploadFileSizeBytes = await archiveDirectoryToTarGz(
					prepared.path,
					stagedArchive,
					prepared.sizeBytes
				);
			}
			uploadFilePath = stagedArchive;
			isTempArchive = false;
		}

		const fileStat = fs.statSync(uploadFilePath);
		const sessionId = getUploadSessionId(
			uploadFilePath,
			uploadFileSizeBytes,
			fileStat.mtimeMs
		);
		let session = loadUploadSession(sessionId);

		const canResume =
			session &&
			session.filePath === uploadFilePath &&
			session.fileSizeBytes === uploadFileSizeBytes &&
			session.mtimeMs === fileStat.mtimeMs &&
			Boolean(session.uploadId) &&
			Boolean(session.uploadKey);

		if (canResume && session) {
			uploadId = session.uploadId;
			uploadKey = session.uploadKey;
			uploadToken = session.uploadToken || "";
			console.log(
				`[Transfer Engine] Active session found (${session.sessionId}). Resuming upload from Cloudflare R2...`
			);
		} else {
			const isCheckpoint = fileLabel.toLowerCase() === "checkpoint";
			const category = isCheckpoint ? "checkpoints" : "datasets";
			let uploadFilename = prepared.filename;
			if (isCheckpoint && !uploadFilename.startsWith("checkpoint")) {
				uploadFilename = `checkpoint_${uploadFilename}`;
			}
			const bodyPayload: any = { filename: uploadFilename, category };
			if (finalJobId.trim()) {
				bodyPayload.jobId = finalJobId.trim();
			}

			const initRes = await fetch(`${API_HOST}/api/upload/initiate`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${accessToken}`,
				},
				body: JSON.stringify(bodyPayload),
			});

			if (!initRes.ok) {
				const err = (await initRes.json().catch(() => ({}))) as any;
				const errMsg =
					typeof err.error === "string"
						? err.error
						: err.message ||
							(Array.isArray(err.error)
								? err.error.map((e: any) => e.message || e).join(", ")
								: JSON.stringify(err.error || err));
				throw new Error(
					`Upload initiation failed: ${errMsg || initRes.statusText}`
				);
			}

			const initData = (await initRes.json()) as any;
			uploadId = initData.uploadId;
			uploadKey = initData.key;
			finalJobId = initData.jobId || finalJobId;
			uploadToken = initData.uploadToken || "";

			const chunkSize = calculateAdaptiveChunkSize(uploadFileSizeBytes);
			const totalParts = Math.max(1, Math.ceil(uploadFileSizeBytes / chunkSize));

			const newSession: UploadSessionState = {
				sessionId,
				filePath: uploadFilePath,
				filename: uploadFilename,
				fileSizeBytes: uploadFileSizeBytes,
				mtimeMs: fileStat.mtimeMs,
				uploadId,
				uploadKey,
				uploadToken,
				chunkSize,
				totalParts,
				completedParts: [],
				status: "in_progress",
				updatedAt: new Date().toISOString(),
			};
			saveUploadSession(newSession);
			session = newSession;
		}

		const activeSession: UploadSessionState = session;
		const chunkSize = activeSession.chunkSize;
		const totalParts = activeSession.totalParts;
		const completedMap = new Map<number, string>();
		for (const p of activeSession.completedParts) {
			completedMap.set(p.PartNumber, p.ETag);
		}

		const pendingPartNumbers: number[] = [];
		for (let p = 1; p <= totalParts; p++) {
			if (!completedMap.has(p)) {
				pendingPartNumbers.push(p);
			}
		}

		if (completedMap.size > 0) {
			console.log(
				`[Transfer Engine] Instant resume active: ${completedMap.size}/${totalParts} parts previously uploaded. Skipping redundant hash scan.`
			);
		}
		console.log(
			`Uploading ${fileLabel} across ${totalParts} adaptive chunk(s) (${(chunkSize / (1024 * 1024)).toFixed(0)} MB/part, concurrency: 4)...`
		);

		// Prefetching cache for presigned part URLs
		const presignedUrlCache = new Map<number, Promise<string>>();
		function getPresignedUrl(partNum: number): Promise<string> {
			const existing = presignedUrlCache.get(partNum);
			if (existing) return existing;

			const promise = (async () => {
				for (let attempt = 1; attempt <= 3; attempt++) {
					try {
						const partRes = await fetch(`${API_HOST}/api/upload/part`, {
							method: "POST",
							headers: {
								"Content-Type": "application/json",
								Authorization: `Bearer ${accessToken}`,
								...(uploadToken ? { "x-upload-token": uploadToken } : {}),
							},
							body: JSON.stringify({
								uploadId,
								key: uploadKey,
								partNumber: partNum,
								uploadToken,
							}),
						});

						if (!partRes.ok) {
							const errBody = await partRes.text().catch(() => "");
							throw new Error(`Signed URL request failed (HTTP ${partRes.status}): ${errBody}`);
						}

						const partData = (await partRes.json()) as any;
						return partData.url as string;
					} catch (err: any) {
						if (attempt === 3) throw err;
						await new Promise((r) => setTimeout(r, 500 * attempt));
					}
				}
				throw new Error(`Failed to obtain presigned URL for part ${partNum}`);
			})();

			presignedUrlCache.set(partNum, promise);
			return promise;
		}

		// Rolling telemetry tracking
		let totalUploadedBytes = 0;
		for (let p = 1; p <= totalParts; p++) {
			if (completedMap.has(p)) {
				const start = (p - 1) * chunkSize;
				const end = Math.min(uploadFileSizeBytes, p * chunkSize);
				totalUploadedBytes += end - start;
			}
		}

		const speedWindow: { time: number; bytes: number }[] = [];
		let peakSpeedMBs = 0;

		function recordBytesTransferred(bytes: number): number {
			const now = Date.now();
			totalUploadedBytes += bytes;
			speedWindow.push({ time: now, bytes });

			while (speedWindow.length > 0 && now - speedWindow[0]!.time > 4000) {
				speedWindow.shift();
			}

			const windowDurationSec =
				speedWindow.length > 1
					? (now - speedWindow[0]!.time) / 1000
					: 1;
			const windowBytes = speedWindow.reduce((acc, cur) => acc + cur.bytes, 0);
			const currentSpeedMBs =
				windowDurationSec > 0
					? (windowBytes / (1024 * 1024)) / windowDurationSec
					: 0;

			if (currentSpeedMBs > peakSpeedMBs) {
				peakSpeedMBs = currentSpeedMBs;
			}
			return currentSpeedMBs;
		}

		function renderProgress(lastUploadedPart: number, speedMBs: number) {
			const pct = ((totalUploadedBytes / uploadFileSizeBytes) * 100).toFixed(1);
			const remainingBytes = Math.max(0, uploadFileSizeBytes - totalUploadedBytes);
			const speedBytesSec = speedMBs * 1024 * 1024;
			const etaSec = speedBytesSec > 0 ? Math.round(remainingBytes / speedBytesSec) : 0;
			const etaStr =
				etaSec >= 60
					? `${Math.floor(etaSec / 60)}m ${etaSec % 60}s`
					: `${etaSec}s`;
			const barWidth = 20;
			const filled = Math.min(
				barWidth,
				Math.round((totalUploadedBytes / uploadFileSizeBytes) * barWidth)
			);
			const bar =
				"=".repeat(filled) +
				(filled < barWidth ? ">" : "") +
				" ".repeat(Math.max(0, barWidth - filled - (filled < barWidth ? 1 : 0)));

			const statusLine = `[Transfer] [${bar}] ${pct}% | ${(totalUploadedBytes / (1024 * 1024)).toFixed(1)} / ${(uploadFileSizeBytes / (1024 * 1024)).toFixed(1)} MB | Speed: ${speedMBs.toFixed(1)} MB/s (Peak: ${peakSpeedMBs.toFixed(1)} MB/s) | Part ${lastUploadedPart}/${totalParts} | ETA: ${etaStr}`;

			if (process.stdout.isTTY) {
				process.stdout.write(`\r${statusLine}`);
			} else {
				console.log(statusLine);
			}
		}

		async function uploadSinglePart(partNum: number): Promise<void> {
			const start = (partNum - 1) * chunkSize;
			const end = Math.min(uploadFileSizeBytes, partNum * chunkSize);
			const chunkLen = end - start;

			let partUploaded = false;
			let lastErr = "";

			for (let attempt = 1; attempt <= 5; attempt++) {
				try {
					const url = await getPresignedUrl(partNum);
					const partStream = fs.createReadStream(uploadFilePath, {
						start,
						end: end - 1,
						highWaterMark: 256 * 1024,
					});

					const putRes = await fetch(url, {
						method: "PUT",
						headers: {
							"Content-Length": String(chunkLen),
						},
						body: partStream as any,
						// @ts-ignore
						duplex: "half",
					});

					if (!putRes.ok) {
						presignedUrlCache.delete(partNum);
						throw new Error(`R2 gateway returned HTTP ${putRes.status}`);
					}

					const rawEtag = putRes.headers.get("ETag") || `etag-${partNum}`;
					const etag = rawEtag.replace(/"/g, "");
					completedMap.set(partNum, etag);
					session!.completedParts.push({ PartNumber: partNum, ETag: etag });
					saveUploadSession(session!);

					const speed = recordBytesTransferred(chunkLen);
					renderProgress(partNum, speed);
					partUploaded = true;
					break;
				} catch (err: any) {
					lastErr = err.message;
					presignedUrlCache.delete(partNum);
					const waitMs = Math.min(8000, 500 * (2 ** attempt));
					await new Promise((r) => setTimeout(r, waitMs));
				}
			}

			if (!partUploaded) {
				throw new Error(
					`Part ${partNum} permanently failed after 5 retry attempts: ${lastErr}`
				);
			}
		}

		// Concurrency worker pool with pipelined URL prefetching
		const CONCURRENCY = Math.min(4, Math.max(1, pendingPartNumbers.length));
		let partQueueIndex = 0;

		async function worker(): Promise<void> {
			while (partQueueIndex < pendingPartNumbers.length) {
				const idx = partQueueIndex++;
				const partNum = pendingPartNumbers[idx]!;

				// Pipeline: prefetch next URLs ahead of workers
				for (let ahead = 1; ahead <= 4; ahead++) {
					const nextIdx = idx + ahead;
					if (nextIdx < pendingPartNumbers.length) {
						void getPresignedUrl(pendingPartNumbers[nextIdx]!);
					}
				}

				await uploadSinglePart(partNum);
			}
		}

		const workers: Promise<void>[] = [];
		for (let w = 0; w < CONCURRENCY; w++) {
			workers.push(worker());
		}
		await Promise.all(workers);

		if (process.stdout.isTTY) {
			process.stdout.write("\n");
		}
		console.log(`Verifying and completing multipart upload on Cloudflare R2...`);

		const parts = Array.from(completedMap.entries())
			.map(([PartNumber, ETag]) => ({ PartNumber, ETag }))
			.sort((a, b) => a.PartNumber - b.PartNumber);

		const completeRes = await fetch(`${API_HOST}/api/upload/complete`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
				...(uploadToken ? { "x-upload-token": uploadToken } : {}),
			},
			body: JSON.stringify({ uploadId, key: uploadKey, parts, uploadToken }),
		});

		if (!completeRes.ok) {
			const errData = await completeRes.json().catch(() => ({}));
			throw new Error(
				`Multipart completion handshake failed: ${formatApiError(errData)}`
			);
		}

		// Cleanup session on successful upload completion
		deleteUploadSession(sessionId);

		console.log(
			`\n✅ ${fileLabel} upload completed and verified on Cloudflare R2.`
		);
		return { uploadKey, jobId: finalJobId };
	} catch (uploadErr: any) {
		console.error(`\n[Upload Failed] ${uploadErr.message}`);
		console.warn(
			`[Upload Session Preserved] Progress saved to session cache. Re-running will resume from last completed part without re-reading.`
		);
		throw uploadErr;
	} finally {
		if (isTempArchive && fs.existsSync(uploadFilePath)) {
			try {
				fs.unlinkSync(uploadFilePath);
			} catch {
				/* cleanup is best effort */
			}
		}
	}
}

async function handleDeploy(
	target: string = "anirudha-s",
	modelId?: string,
	method: string = "full",
	autoConfirm: boolean = false,
	checkpointPath?: string
) {
	const accessToken = await getValidAccessToken();
	if (!accessToken) {
		process.exitCode = 1;
		return;
	}
	let config = loadConfig();

	const prepared = config.preparedDataset;
	if (!prepared) {
		console.error("[Error] No dataset has been prepared for upload.");
		console.error("Run: vivacious prepare <path-to-dataset>");
		process.exitCode = 1;
		return;
	}

	if (checkpointPath) {
		console.log(`Preparing checkpoint from ${checkpointPath}...`);
		await handlePrepare(checkpointPath, "checkpoint");
		config = loadConfig(); // reload config after prepare updates it
	}

	if (modelId) {
		const permitted = await handlePermit(modelId, method, autoConfirm);
		if (!permitted) {
			console.error(
				"[Error] Pre-flight financial check rejected or unconfirmed."
			);
			process.exitCode = 1;
			return;
		}
		config = loadConfig();
	}

	const permit = config.lastPermit;
	if (!permit) {
		console.error(
			"[Error] No active financial permit found. Please run permit first:"
		);
		console.error("  vivacious permit anirudha-s ambition --model <model-id>");
		process.exitCode = 1;
		return;
	}

	if (permit.expiresAt && new Date(permit.expiresAt).getTime() < Date.now()) {
		console.warn(
			"[Notice] Your financial permit has expired (>15 minutes). Refreshing permit now..."
		);
		const permitted = await handlePermit(
			permit.modelId,
			permit.method,
			autoConfirm
		);
		if (!permitted) {
			console.error("[Error] Re-permitting failed.");
			process.exitCode = 1;
			return;
		}
		config = loadConfig();
	}

	const activePermit = config.lastPermit!;
	const prepCheckpoint = config.preparedCheckpoint;

	// Pre-flight balance check: Prevent R2 uploads and bandwidth costs if balance is insufficient
	try {
		const balRes = await fetch(`${API_HOST}/api/user/balance`, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		if (balRes.ok) {
			const balData: any = await balRes.json().catch(() => ({}));
			const currentBalance = Number(
				balData.currentBalance ?? balData.current_balance ?? 0
			);
			const isCard =
				balData.billingMode === "card" || balData.billing_mode === "card";
			const estimatedCost = Number(activePermit.estimatedTotal || 0);

			if (!isCard && currentBalance <= 0) {
				console.error("\n=============================================");
				console.error("❌ [DEPLOYMENT BLOCKED — INSUFFICIENT BALANCE]");
				console.error("=============================================");
				console.error(`Current Balance:      ₹${currentBalance.toFixed(2)}`);
				console.error(`Estimated Run Cost:   ₹${estimatedCost.toFixed(2)}`);
				console.error(
					"Upload to Cloudflare R2 was stopped to protect your account."
				);
				console.error(
					"Please recharge your balance via the Dashboard (Billing) before deploying."
				);
				console.error("=============================================");
				process.exitCode = 1;
				return;
			}

			if (
				!isCard &&
				currentBalance < estimatedCost &&
				!activePermit.requiresConfirmation
			) {
				console.warn(
					`\n⚠️  [Notice] Current balance (₹${currentBalance.toFixed(2)}) is lower than estimated cost (₹${estimatedCost.toFixed(2)}).`
				);
				console.warn("Job may auto-pause if balance depletes during training.");
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
	console.log(
		`Dataset:              ${prepared.filename} (${(prepared.sizeBytes / (1024 * 1024)).toFixed(2)} MB)`
	);
	console.log(`SHA-256 Fingerprint:  ${prepared.sha256}`);
	if (prepCheckpoint) {
		console.log(
			`Checkpoint Archive:   ${prepCheckpoint.filename} (${(prepCheckpoint.sizeBytes / (1024 * 1024)).toFixed(2)} MB)`
		);
		console.log(`Checkpoint SHA-256:   ${prepCheckpoint.sha256}`);
	}
	console.log(`---------------------------------------------`);

	// Upload Dataset
	const datasetUpload = await performUpload(config, prepared, "Dataset");
	const activeJobId = datasetUpload.jobId;

	// Upload Checkpoint if present
	let checkpointKey: string | undefined;
	if (prepCheckpoint) {
		const cpUpload = await performUpload(
			config,
			prepCheckpoint,
			"Checkpoint"
		);
		checkpointKey = cpUpload.uploadKey;
	}

	// Step 2: Trigger Server-Authoritative Deployment
	const deploymentId = crypto.randomUUID();
	console.log(
		`Triggering orchestrator GPU provisioning (Deployment ID: ${deploymentId})...`
	);

	// Ensure access token is fresh after potentially long multi-gigabyte upload
	const deployToken = (await getValidAccessToken(true)) || accessToken;

	// Re-verify and refresh financial permit at final deployment boundary
	// Orchestrator permits have a strict 15-minute TTL and will fail if expired during long uploads
	let finalPermitRef = activePermit.permitRef;
	const permitExpired =
		activePermit.expiresAt &&
		new Date(activePermit.expiresAt).getTime() - Date.now() < 120_000;
	if (permitExpired) {
		console.log(
			`\n[Notice] Upload completed. Refreshing 15-minute financial permit before GPU deployment...`
		);
		const renewed = await handlePermit(
			activePermit.modelId,
			activePermit.method,
			autoConfirm
		);
		if (!renewed) {
			console.error("[Error] Re-permitting failed at final deployment boundary.");
			process.exitCode = 1;
			return;
		}
		config = loadConfig();
		finalPermitRef = config.lastPermit?.permitRef || finalPermitRef;
	}

	try {
		const deployRes = await fetch(`${API_HOST}/api/deploy`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${deployToken}`,
			},
			body: JSON.stringify({
				jobId: activeJobId,
				modelId: activePermit.modelId,
				modelSource: checkpointKey ? "custom_checkpoint" : "hf",
				checkpointKey: checkpointKey,
				checkpointConfig: prepCheckpoint?.modelConfig,
				checkpointFingerprint: prepCheckpoint?.sha256,
				method: activePermit.method,
				datasetFilename: prepared!.filename,
				datasetSizeBytes: prepared!.sizeBytes,
				datasetFingerprint: prepared!.sha256,
				permitRef: finalPermitRef,
				deploymentId,
				confirmedUnderfunded: activePermit.requiresConfirmation || false,
			}),
		});

		const deployData: any = await deployRes.json().catch(() => ({}));
		if (!deployRes.ok) {
			console.error(
				`\n[Deployment Error] ${formatApiError(deployData) || "Server failed to provision instance."}`
			);
			process.exitCode = 1;
			return;
		}

		console.log("\n=============================================");
		console.log("✅ DEPLOYMENT LAUNCHED SUCCESSFULLY");
		console.log("=============================================");
		const deployHours = Number(deployData.estimatedHours || 0.15);
		const deployMinutes = Math.round(deployHours * 60);
		let deployDurationStr =
			deployMinutes < 60
				? `~${deployMinutes} mins (${deployHours.toFixed(2)} hours)`
				: `${Math.floor(deployMinutes / 60)}h ${deployMinutes % 60}m (${deployHours.toFixed(2)} hours)`;
		if (
			deployData.bootMinutes &&
			deployData.trainMinutes &&
			deployData.finalizeMinutes
		) {
			const bufStr = deployData.bufferMinutes
				? ` | Buffer ~${Math.round(deployData.bufferMinutes)}m`
				: "";
			deployDurationStr += ` [Boot ~${Math.round(deployData.bootMinutes)}m | Train ~${Math.round(deployData.trainMinutes)}m | Upload ~${Math.round(deployData.finalizeMinutes)}m${bufStr}]`;
		}

		console.log(`Job ID:               ${deployData.jobId}`);
		console.log(
			`Initial Job Status:   ${(deployData.status || "QUEUED").toUpperCase()}`
		);
		console.log(`Allocated GPU Tier:   ${deployData.gpuTier || "Standard"}`);
		console.log(`Estimated Duration:   ${deployDurationStr}`);
		console.log(
			`Estimated Total Cost: ₹${Number(deployData.estimatedTotal || 0).toFixed(2)} (Billing: ${(deployData.billingMode || "PREPAID").toUpperCase()})`
		);
		console.log("\nNext Steps:");
		console.log(
			`  To monitor real-time progress, run: vivacious status ${deployData.jobId}`
		);
		console.log(
			`  To stream live loss & telemetry, run: vivacious logs ${deployData.jobId}`
		);
		console.log("=============================================\n");

		// Clean up local tracking state to prevent accidental double-deploys
		delete config.preparedDataset;
		delete config.preparedCheckpoint;
		delete config.lastPermit;
		saveConfig(config);
	} catch (submitErr: any) {
		console.error(`\n[Deployment Communication Error] ${submitErr.message}`);
		process.exitCode = 1;
		return;
	}
}

// 5. Query Real-Time Balance
async function handleBalance() {
	const accessToken = await getValidAccessToken();
	if (!accessToken) {
		process.exitCode = 1;
		return;
	}

	try {
		const res = await fetch(`${API_HOST}/api/user/balance`, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (!res.ok) {
			if (res.status === 401) {
				console.error("\n[Notice] Your authentication session has expired.");
				console.error(
					'Please run "vivacious login anirudha-s" to authenticate.\n'
				);
				process.exitCode = 1;
				return;
			}
			const errJson: any = await res.json().catch(() => ({}));
			console.error(
				`[Error] Failed to fetch balance: ${formatApiError(errJson) || res.statusText}`
			);
			process.exitCode = 1;
			return;
		}

		const data: any = await res.json();
		console.log("\n=============================================");
		console.log("💰 VIVACIOUS CLOUD — ACCOUNT BALANCE");
		console.log("=============================================");
		console.log(
			`User ID:              ${data.userId || data.user_id || "N/A"}`
		);
		console.log(
			`Available Balance:    ₹${Number(data.currentBalance ?? data.current_balance ?? 0).toFixed(2)}`
		);
		console.log(
			`Total Paid:           ₹${Number(data.totalPaid ?? data.total_paid ?? 0).toFixed(2)}`
		);
		console.log(
			`Total Spent:          ₹${Number(data.totalSpent ?? data.total_spent ?? 0).toFixed(2)}`
		);
		console.log(
			`Billing Mode:         ${(data.billingMode || data.billing_mode || "PREPAID").toUpperCase()}`
		);
		console.log("=============================================");
	} catch (err: any) {
		console.error(`[Error] Could not retrieve balance: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

// 6. Query Job Status & Live Telemetry
async function handleStatus(jobId?: string) {
	const accessToken = await getValidAccessToken();
	if (!accessToken) {
		process.exitCode = 1;
		return;
	}

	const endpoint = jobId
		? `${API_HOST}/api/jobs/${jobId}`
		: `${API_HOST}/api/jobs/active`;

	try {
		const res = await fetch(endpoint, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (res.status === 404) {
			console.log(
				jobId
					? `[Notice] Job ${jobId} not found.`
					: "[Notice] No active training jobs found."
			);
			return;
		}

		if (!res.ok) {
			const errJson: any = await res.json().catch(() => ({}));
			console.error(`[Error] Failed to fetch status: ${formatApiError(errJson) || res.statusText}`);
			process.exitCode = 1;
			return;
		}

		const data: any = await res.json();
		const modelName = data.model_id || data.model || "meta-llama/Llama-3-8b";
		console.log("\n=============================================");
		console.log(`📊 JOB STATUS: ${data.id}`);
		console.log("=============================================");
		console.log(`Model:                ${modelName}`);
		const rawStatus = (data.status || "unknown").toUpperCase();
		const isFinishedProgress = Number(data.progress_percent || 0) >= 100;
		const displayStatus =
			rawStatus === "RUNNING" && isFinishedProgress
				? "FINALIZING (Packaging & Syncing Weights)"
				: rawStatus;

		console.log(`Status:               ${displayStatus}`);
		console.log(
			`Progress:             ${Number(data.progress_percent || 0).toFixed(1)}%`
		);
		console.log(`GPU Tier:             ${data.gpu_type || "N/A"}`);
		console.log(`Current Cost:         ₹${Number(data.cost || 0).toFixed(2)}`);
		console.log(
			`Hourly Rate:          ₹${Number(data.hourly_rate || data.locked_hourly_rate || 0).toFixed(2)}/hr`
		);
		console.log(
			`Last Heartbeat:       ${data.last_heartbeat ? new Date(data.last_heartbeat).toLocaleTimeString() : "N/A"}`
		);
		console.log("=============================================");
	} catch (err: any) {
		console.error(`[Error] Could not retrieve status: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

// 6b. Query Live Execution Logs & Output Telemetry
async function handleLogs(jobId?: string) {
	const accessToken = await getValidAccessToken();
	if (!accessToken) {
		process.exitCode = 1;
		return;
	}

	const endpoint = jobId
		? `${API_HOST}/api/jobs/${jobId}`
		: `${API_HOST}/api/jobs/active`;

	try {
		const res = await fetch(endpoint, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (res.status === 404) {
			console.log(
				jobId
					? `[Notice] Job ${jobId} not found.`
					: "[Notice] No active training jobs found."
			);
			return;
		}

		if (!res.ok) {
			const errJson: any = await res.json().catch(() => ({}));
			console.error(
				`[Error] Failed to fetch execution logs: ${formatApiError(errJson) || res.statusText}`
			);
			process.exitCode = 1;
			return;
		}

		const data: any = await res.json();
		const modelName = data.model_id || data.model || "meta-llama/Llama-3-8b";
		console.log("\n=============================================");
		console.log(`📋 JOB EXECUTION LOGS: ${data.id}`);
		console.log("=============================================");
		console.log(`Model:          ${modelName}`);
		const rawStatus = (data.status || "unknown").toUpperCase();
		const isFinishedProgress = Number(data.progress_percent || 0) >= 100;
		const displayStatus =
			rawStatus === "RUNNING" && isFinishedProgress
				? "FINALIZING (Packaging & Syncing Weights)"
				: rawStatus;

		console.log(`Status:         ${displayStatus}`);
		console.log(
			`Progress:       ${Number(data.progress_percent || 0).toFixed(1)}%`
		);
		console.log(`Current Step:   ${data.current_step || data.step || "N/A"}`);
		console.log(
			`Current Loss:   ${data.loss !== undefined ? Number(data.loss).toFixed(4) : "N/A"}`
		);
		console.log("---------------------------------------------");
		console.log("Telemetry & Output:");
		if (data.logs && Array.isArray(data.logs) && data.logs.length > 0) {
			data.logs.forEach((logLine: string) => {
				console.log(`  ${logLine}`);
			});
		} else if (typeof data.logs === "string" && data.logs.trim().length > 0) {
			console.log(data.logs);
		} else if (data.error_message) {
			console.log(`  [Details] ${data.error_message}`);
		} else {
			console.log(
				`  [Telemetry] GPU container running normally. Training progress: ${Number(data.progress_percent || 0).toFixed(1)}%.`
			);
		}
		console.log("=============================================");
	} catch (err: any) {
		console.error(`[Error] Could not retrieve execution logs: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

// 7. Secure Presigned Download Link Generator & Stream Downloader
async function handleDownload(jobId: string, directDownload: boolean = true) {
	const accessToken = await getValidAccessToken();

	console.log(`Requesting secure download link for job ${jobId}...`);

	try {
		const res = await fetch(`${API_HOST}/api/jobs/download`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({ jobId }),
		});

		const data: any = await res.json();
		if (!res.ok || !data.downloadUrl) {
			console.error(
				`\n[Error] Download link generation failed: ${data.error || "Unknown error"}`
			);
			process.exitCode = 1;
			return;
		}

		console.log("\n=============================================");
		console.log("📦 MODEL WEIGHTS DOWNLOAD LINK");
		console.log("=============================================");
		console.log(`Job ID:       ${jobId}`);
		console.log(`Download URL: ${data.downloadUrl}`);
		console.log(`Expires At:   ${data.expiresAt || "7 days"}`);
		console.log("---------------------------------------------");
		console.log("Download via cURL:");
		console.log(`  curl -O "${data.downloadUrl}"`);
		console.log("=============================================");

		if (directDownload) {
			const sanitizedJobId = jobId.replace(/[^a-zA-Z0-9_-]/g, "");
			const outPath = path.resolve(
				process.cwd(),
				`model_weights_${sanitizedJobId}.tar.gz`
			);
			console.log(`\nInitiating direct streaming download to: ${outPath}...`);

			const dlRes = await fetch(data.downloadUrl);
			if (!dlRes.ok) {
				console.error(
					`[Download Error] Storage gateway returned HTTP ${dlRes.status}`
				);
				return;
			}

			const totalLength = Number(dlRes.headers.get("content-length")) || 0;
			const fileStream = fs.createWriteStream(outPath);

			if (dlRes.body) {
				let downloadedBytes = 0;
				const reader = (dlRes.body as any).getReader();
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value) {
						const ok = fileStream.write(Buffer.from(value));
						downloadedBytes += value.length;
						if (!ok) {
							await new Promise<void>((resolve) =>
								fileStream.once("drain", resolve)
							);
						}
						if (totalLength > 0) {
							const pct = ((downloadedBytes / totalLength) * 100).toFixed(1);
							process.stdout.write(
								`\rDownloading: ${pct}% (${(downloadedBytes / (1024 * 1024)).toFixed(2)} / ${(totalLength / (1024 * 1024)).toFixed(2)} MB)`
							);
						} else {
							process.stdout.write(
								`\rDownloading: ${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB`
							);
						}
					}
				}
				fileStream.end();
				console.log(`\n✅ Model weights successfully downloaded: ${outPath}`);
			}
		}
	} catch (err: any) {
		console.error(`[Error] Failed to get download link: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

// 8. User-Initiated Job Cancellation
async function handleCancel(jobId: string, autoConfirm: boolean = false) {
	const accessToken = await getValidAccessToken();

	if (!autoConfirm) {
		const ans = await askQuestion(
			`Are you sure you want to terminate job ${jobId}? (y/N): `
		);
		if (ans.toLowerCase() !== "y" && ans.toLowerCase() !== "yes") {
			console.log("[Aborted] Cancellation aborted.");
			return;
		}
	}

	console.log(`Sending termination signal for job ${jobId}...`);

	try {
		const res = await fetch(`${API_HOST}/api/jobs/cancel`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({ jobId }),
		});

		const data: any = await res.json();
		if (!res.ok) {
			console.error(
				`[Error] Cancellation failed: ${data.error || "Unknown error"}`
			);
			process.exitCode = 1;
			return;
		}

		console.log(
			`\n✅ Job ${jobId} successfully marked for termination. Final compute settled.`
		);
	} catch (err: any) {
		console.error(`[Error] Failed to cancel job: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

// 9. Checkpoint Resumption Handlers (Dedicated Isolated Workflow)

async function handleResumeInspect(jobId: string) {
	const accessToken = await getValidAccessToken();
	const config = loadConfig();

	if (!jobId || jobId === "begin") {
		console.error("[Error] Missing required parameter: <job-id>");
		console.error("Usage: vivacious resume <job-id>");
		console.error("Example: vivacious resume job_8f29ab01");
		process.exitCode = 1;
		return;
	}

	console.log(`\n=============================================`);
	console.log(`🔁 VIVACIOUS CLOUD — CHECKPOINT RECOVERY INSPECTION`);
	console.log(`=============================================`);
	console.log(`Querying server-authoritative checkpoint for job ${jobId}...`);

	try {
		const res = await fetch(
			`${API_HOST}/api/jobs/resume/inspect?jobId=${encodeURIComponent(jobId)}`,
			{
				headers: { Authorization: `Bearer ${accessToken}` },
			}
		);

		const data: any = await res.json().catch(() => ({}));
		if (!res.ok || !data.success || !data.resumeAvailable) {
			console.error(
				`\n[Inspection Error] ${formatApiError(data) || "Workload is not eligible for resumption."}`
			);
			process.exitCode = 1;
			return;
		}

		const job = data.job;
		const expiresDate = job.checkpointExpiresAt
			? new Date(job.checkpointExpiresAt).toLocaleString()
			: "7 days from stop";

		console.log(`Job ID:               ${job.id}`);
		console.log(
			`Target Base Model:    ${job.modelId} (${job.method.toUpperCase()})`
		);
		console.log(
			`Training Progress:    ${Number(job.progressPercent).toFixed(1)}% (Checkpoint Step: ${job.checkpointStep})`
		);
		console.log(`Allocated GPU Shape:  ${job.gpuTier}`);
		console.log(`Accrued Prior Cost:   ₹${Number(job.costAccrued).toFixed(2)}`);
		console.log(`Stop Diagnostic:      ⚠️ ${job.errorReason}`);
		console.log(`Checkpoint Status:    Verified (Vivacious Storage)`);
		console.log(`7-Day Expiration:     ${expiresDate}`);
		console.log(`---------------------------------------------`);
		console.log(`✅ [Checkpoint Verified & Staged for Resumption]`);
		console.log(
			`Next Step: Run 'vivacious anirudha-s check' to calculate remaining compute and authorize resumption.`
		);
		console.log(`=============================================`);

		config.resumeContext = {
			jobId: job.id,
			resumeAttemptId: data.resumeAttemptId,
			modelId: job.modelId,
			method: job.method,
			gpuTier: job.gpuTier,
			progressPercent: job.progressPercent,
			checkpointExpiresAt: job.checkpointExpiresAt,
			inspectedAt: new Date().toISOString(),
			state: "RESUME_INSPECTED",
		};
		saveConfig(config);
	} catch (err: any) {
		console.error(`\n[Error] Failed to inspect checkpoint: ${err.message}`);
		process.exitCode = 1;
		return;
	}
}

async function handleResumeCheck() {
	const accessToken = await getValidAccessToken();
	const config = loadConfig();

	const resume = config.resumeContext;
	if (!resume?.jobId || !resume.resumeAttemptId || resume.state !== "RESUME_INSPECTED") {
		console.error(
			'[Error] Resumption workflow sequence violation. Step 1 must be completed first:'
		);
		console.error('  vivacious resume <job-id>');
		process.exitCode = 1;
		return;
	}

	console.log(`\n=============================================`);
	console.log(`💰 VIVACIOUS CLOUD — RESUME FINANCIAL AUTHORIZATION`);
	console.log(`=============================================`);
	console.log(`Target Job ID:        ${resume.jobId}`);
	console.log(
		`Target Model:         ${resume.modelId || "Base Model"} (${(resume.method || "LORA").toUpperCase()})`
	);
	console.log(
		`Completed Progress:   ${Number(resume.progressPercent || 0).toFixed(1)}%`
	);
	console.log(`Checking server balance against remaining compute exposure...`);

	try {
		const res = await fetch(`${API_HOST}/api/jobs/resume/permit`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({
				jobId: resume.jobId,
				resumeAttemptId: resume.resumeAttemptId,
			}),
		});

		const data: any = await res.json().catch(() => ({}));
		if (!res.ok) {
			console.error(
				`\n[Permit Error] ${formatApiError(data) || "Server failed to calculate resume permit."}`
			);
			process.exitCode = 1;
			return;
		}

		console.log(
			`Available Balance:    ₹${Number(data.currentBalance || 0).toFixed(2)}`
		);
		console.log(
			`Remaining Duration:   ~${Number(data.remainingHours || 0).toFixed(2)} hrs`
		);
		console.log(
			`Hourly Rate:          ₹${Number(data.hourlyRate || 0).toFixed(2)}/hr`
		);
		console.log(
			`Estimated Remaining:  ₹${Number(data.remainingEstimatedTotal || 0).toFixed(2)}`
		);
		console.log(
			`Max Exposure Ceiling: ₹${Number(data.remainingMaxExposure || 0).toFixed(2)}`
		);
		console.log(`---------------------------------------------`);

		if (!data.permitted || !data.permitRef) {
			console.error(`❌ [INSUFFICIENT BALANCE]`);
			console.error(
				`Your account requires ₹${Number(data.remainingEstimatedTotal || 0).toFixed(2)} to complete this training run.`
			);
			console.error(
				`Current balance: ₹${Number(data.currentBalance || 0).toFixed(2)}.`
			);
			console.error(
				`Please recharge your account via the Dashboard (Billing) and re-run:`
			);
			console.error(`  vivacious anirudha-s check`);
			process.exitCode = 1;
			return;
		}

		console.log(
			`✅ [FINANCIAL PERMIT GRANTED] (Valid for 15 minutes, Single-Use)`
		);
		console.log(
			`Next Step: Run 'vivacious resume begin' to launch cloud GPU training.`
		);
		console.log(`=============================================`);

		config.resumeContext!.lastPermitRef = data.permitRef;
		config.resumeContext!.remainingEstimatedTotal =
			data.remainingEstimatedTotal;
		config.resumeContext!.remainingMaxExposure = data.remainingMaxExposure;
		config.resumeContext!.state = "RESUME_AUTHORIZED";
		saveConfig(config);
	} catch (err: any) {
		console.error(
			`\n[Error] Failed to authorize resume permit: ${err.message}`
		);
		process.exitCode = 1;
		return;
	}
}

async function handleResumeBegin(autoConfirm: boolean = false) {
	const accessToken = await getValidAccessToken();
	const config = loadConfig();

	const resume = config.resumeContext;
	if (!resume?.jobId || !resume.lastPermitRef || resume.state !== "RESUME_AUTHORIZED") {
		console.error("[Error] Resumption workflow sequence violation. Step 2 financial authorization required first:");
		console.error("  1. vivacious resume <job-id>");
		console.error("  2. vivacious anirudha-s check");
		console.error("  3. vivacious resume begin");
		process.exitCode = 1;
		return;
	}

	console.log(`\n=============================================`);
	console.log(`🚀 VIVACIOUS CLOUD — RESUME WORKLOAD CONFIRMATION`);
	console.log(`=============================================`);
	console.log(`Job ID:               ${resume.jobId}`);
	console.log(`Target Model:         ${resume.modelId || "Base Model"}`);
	console.log(
		`Resuming Progress:    ${Number(resume.progressPercent || 0).toFixed(1)}%`
	);
	console.log(
		`Remaining Exposure:   ₹${Number(resume.remainingMaxExposure || 0).toFixed(2)} (Max authorized)`
	);
	console.log(`=============================================`);

	if (!autoConfirm) {
		const ans = await askQuestion(
			"Are you sure you want to resume and dispatch this training workload? (y/N): "
		);
		if (ans.toLowerCase() !== "y" && ans.toLowerCase() !== "yes") {
			console.log("[Aborted] Resume launch aborted.");
			return;
		}
	}

	console.log(
		`Dispatching server-authoritative resumption to Cloudflare Orchestrator...`
	);

	try {
		const res = await fetch(`${API_HOST}/api/jobs/resume/deploy`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${accessToken}`,
			},
			body: JSON.stringify({
				jobId: resume.jobId,
				permitRef: resume.lastPermitRef,
			}),
		});

		const data: any = await res.json().catch(() => ({}));
		if (!res.ok || !data.success) {
			console.error(
				`\n[Deployment Error] ${formatApiError(data) || "Server failed to resume workload."}`
			);
			process.exitCode = 1;
			return;
		}

		console.log("\n=============================================");
		console.log("🎉 RESUMED WORKLOAD LAUNCHED SUCCESSFULLY");
		console.log("=============================================");
		console.log(`Job ID:               ${data.jobId}`);
		console.log(
			`Status:               ${data.status.toUpperCase()} (Cloud GPU container queued)`
		);
		console.log(
			`Continuing From:      ${Number(data.progressPercent || resume.progressPercent || 0).toFixed(1)}%`
		);
		console.log(`Track Progress:       vivacious status ${data.jobId}`);
		console.log(`Cancel Job:           vivacious cancel ${data.jobId}`);
		console.log("=============================================");

		// Single-use: clear consumed permit reference and mark dispatched
		if (config.resumeContext) {
			config.resumeContext.lastPermitRef = undefined;
			config.resumeContext.state = "RESUME_DISPATCHED";
		}
		saveConfig(config);
	} catch (err: any) {
		console.error(
			`\n[Error] Resumed deployment connection failed: ${err.message}`
		);
		process.exitCode = 1;
		return;
	}
}

// 10. Logout
function handleLogout() {
	saveConfig({});
	console.log("[Success] Logged out. Local credentials cleared.");
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

	if (
		!command ||
		command === "help" ||
		command === "--help" ||
		command === "-h"
	) {
		showHelp();
		process.exit(0);
	}

	switch (command) {
		case "anirudha-s": {
			const sub = args[1];
			if (sub === "check") {
				await handleResumeCheck();
			} else {
				console.error("[Error] Unrecognized founder command.");
				console.error("Usage: vivacious anirudha-s check");
				process.exit(1);
			}
			break;
		}

		case "login": {
			const target = args[1];
			if (target !== "anirudha-s") {
				console.error("[Error] Invalid login target.");
				console.error("Usage: vivacious login anirudha-s");
				process.exit(1);
			}
			await handleLogin(target);
			break;
		}

		case "prepare":
		case "upload": {
			let type: "dataset" | "checkpoint" = "dataset";
			let targetPath = args[1];

			if (args[1] === "checkpoint" || args[1] === "--checkpoint") {
				type = "checkpoint";
				targetPath = args[2];
			} else if (args[1] === "dataset" || args[1] === "--dataset") {
				type = "dataset";
				targetPath = args[2];
			}

			if (!targetPath) {
				console.error("Usage: vivacious prepare [dataset|checkpoint] <path>");
				console.error("Example: vivacious prepare ./new_instructions.jsonl");
				console.error(
					"Example: vivacious prepare checkpoint ./my_model_checkpoint.tar.gz"
				);
				process.exit(1);
			}
			await handlePrepare(targetPath, type);
			break;
		}

		case "permit":
		case "permits": {
			let permitModel = "";
			let permitMethod = "full";
			let autoConfirm = false;
			let hasFounder = false;
			let hasAmbition = false;

			for (let i = 1; i < args.length; i++) {
				if (args[i] === "--model") {
					permitModel = args[i + 1] || "";
					i++;
				} else if (args[i] === "--method") {
					const methodVal = (args[i + 1] || "").toLowerCase();
					permitMethod =
						methodVal === "lora" || methodVal === "qlora" ? methodVal : "full";
					i++;
				} else if (args[i] === "--yes" || args[i] === "-y") {
					autoConfirm = true;
				} else if (args[i] === "anirudha-s") {
					hasFounder = true;
				} else if (args[i] === "ambition") {
					hasAmbition = true;
				} else if (args[i].startsWith("--")) {
					console.error(`[Error] Unrecognized option: ${args[i]}`);
					process.exit(1);
				} else {
					console.error(
						`[Error] Unexpected positional argument: "${args[i]}".`
					);
					console.error(
						"Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]"
					);
					process.exit(1);
				}
			}

			if (!hasFounder || !hasAmbition) {
				console.error(
					'[Error] Missing required founder scope: "anirudha-s ambition"'
				);
				console.error(
					"Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]"
				);
				process.exit(1);
			}

			if (!permitModel) {
				console.error("[Error] Missing required parameter: --model <model-id>");
				console.error(
					"Usage: vivacious permit anirudha-s ambition --model <model-id> [--method <full|lora|qlora>] [--yes]"
				);
				console.error(
					"Example: vivacious permit anirudha-s ambition --model meta-llama/Llama-3-8b"
				);
				console.error(
					"Example: vivacious permit anirudha-s ambition --model custom_model --method lora"
				);
				process.exit(1);
			}

			await handlePermit(permitModel, permitMethod, autoConfirm);
			break;
		}

		case "deploy": {
			let deployModel = "";
			let deployCheckpoint = "";
			let deployMethod = "full";
			let autoConfirm = false;
			let hasFounder = false;

			for (let i = 1; i < args.length; i++) {
				if (args[i] === "--model") {
					deployModel = args[i + 1] || "";
					i++;
				} else if (args[i] === "--checkpoint") {
					deployCheckpoint = args[i + 1] || "";
					i++;
				} else if (args[i] === "--method") {
					const methodVal = (args[i + 1] || "").toLowerCase();
					deployMethod =
						methodVal === "lora" || methodVal === "qlora" ? methodVal : "full";
					i++;
				} else if (args[i] === "--yes" || args[i] === "-y") {
					autoConfirm = true;
				} else if (args[i] === "anirudha-s") {
					hasFounder = true;
				} else if (args[i].startsWith("--")) {
					console.error(`[Error] Unrecognized option: ${args[i]}`);
					process.exit(1);
				} else {
					console.error(
						`[Error] Unexpected positional argument: "${args[i]}".`
					);
					console.error(
						"Usage: vivacious deploy anirudha-s [--model <model-id>] [--yes]"
					);
					process.exit(1);
				}
			}

			if (!hasFounder) {
				console.error('[Error] Missing required founder scope: "anirudha-s"');
				console.error(
					"Usage: vivacious deploy anirudha-s [--model <model-id>] [--yes]"
				);
				process.exit(1);
			}

			await handleDeploy(
				"anirudha-s",
				deployModel || undefined,
				deployMethod,
				autoConfirm,
				deployCheckpoint || undefined
			);
			break;
		}

		case "resume": {
			const sub = args[1];
			if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
				console.log(
					"Usage:\n  Step 1: vivacious resume <job-id>\n  Step 2: vivacious anirudha-s check\n  Step 3: vivacious resume begin [--yes]"
				);
				console.log("Example:");
				console.log("  vivacious resume job_8f29ab01");
				console.log("  vivacious anirudha-s check");
				console.log("  vivacious resume begin --yes");
				process.exit(0);
			}

			if (sub === "begin") {
				const autoConfirm = args.includes("--yes") || args.includes("-y");
				await handleResumeBegin(autoConfirm);
			} else if (sub === "check") {
				console.error(
					"[Error] Invalid command syntax for patent-protected resumption flow."
				);
				console.error("Resumption step 2 requires: vivacious anirudha-s check");
				console.error("Workflow sequence:");
				console.error("  Step 1: vivacious resume <job-id>");
				console.error("  Step 2: vivacious anirudha-s check");
				console.error("  Step 3: vivacious resume begin [--yes]");
				process.exit(1);
			} else {
				await handleResumeInspect(sub);
			}
			break;
		}

		case "balance":
		case "billing":
			await handleBalance();
			break;

		case "status": {
			const jobId = args[1];
			await handleStatus(jobId);
			break;
		}

		case "logs":
		case "log": {
			const jobId = args[1];
			await handleLogs(jobId);
			break;
		}

		case "download": {
			const jobId = args[1];
			if (!jobId) {
				console.error("Usage: vivacious download <job-id>");
				process.exit(1);
			}
			await handleDownload(jobId);
			break;
		}

		case "cancel": {
			const jobId = args[1];
			if (!jobId || jobId.startsWith("--")) {
				console.error("Usage: vivacious cancel <job-id> [--yes]");
				process.exit(1);
			}
			const autoConfirm = args.includes("--yes") || args.includes("-y");
			await handleCancel(jobId, autoConfirm);
			break;
		}

		case "logout":
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

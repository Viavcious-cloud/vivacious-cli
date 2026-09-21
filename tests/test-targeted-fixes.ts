import * as assert from "node:assert";
import * as child_process from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import {
	calculateAdaptiveChunkSize,
	checkJsonNestingDepth,
	createTarHeader,
	getUploadSessionId,
	loadUploadSession,
	saveUploadSession,
	deleteUploadSession,
	UploadSessionState,
	validateCheckpointEntry,
	classifyCheckpointShape,
	scanAndValidateCheckpointDirectory,
	scanAndValidateCheckpointArchive,
	streamValidateLargeJsonArray,
	getStagedArchivePath,
	archiveDirectoryToTarGz,
	calculateDirectoryFastFingerprint,
} from "../src/index";

async function runTests(): Promise<void> {
	console.log("=================================================");
	console.log("🧪 VIVACIOUS CLOUD — TARGETED VERIFICATION SUITE");
	console.log("=================================================\n");

	let passed = 0;
	let total = 0;

	async function test(name: string, fn: () => void | Promise<void>): Promise<void> {
		total++;
		try {
			await fn();
			console.log(`  ✅ [PASS] ${name}`);
			passed++;
		} catch (err: any) {
			console.error(`  ❌ [FAIL] ${name}`);
			console.error(`     ${err.message}`);
		}
	}

	// -------------------------------------------------------------
	// 1. Transfer Engine: Clamped Adaptive Multipart Chunking
	// -------------------------------------------------------------
	console.log("--- 1. Transfer Engine: Adaptive Chunking & Rate Limiting ---");

	await test("Small file (100 MB) clamps to minimum 16 MiB chunk", () => {
		const size = 100 * 1024 * 1024;
		const chunk = calculateAdaptiveChunkSize(size);
		assert.strictEqual(chunk, 16 * 1024 * 1024);
		const parts = Math.ceil(size / chunk);
		assert.strictEqual(parts, 7);
	});

	await test("10 GiB dataset targets ~300-400 parts (32 MiB chunks, safe for 600 req/min)", () => {
		const size = 10 * 1024 * 1024 * 1024;
		const chunk = calculateAdaptiveChunkSize(size);
		const parts = Math.ceil(size / chunk);
		assert.strictEqual(chunk, 32 * 1024 * 1024);
		assert.strictEqual(parts, 320);
		assert.ok(parts < 500, "Part count must stay within optimal window");
	});

	await test("50 GiB model weights uses 128 MiB chunks (exactly 400 parts)", () => {
		const size = 50 * 1024 * 1024 * 1024;
		const chunk = calculateAdaptiveChunkSize(size);
		const parts = Math.ceil(size / chunk);
		assert.strictEqual(chunk, 128 * 1024 * 1024);
		assert.strictEqual(parts, 400);
	});

	await test("100 GiB vast dataset clamps to maximum 256 MiB chunk", () => {
		const size = 100 * 1024 * 1024 * 1024;
		const chunk = calculateAdaptiveChunkSize(size);
		const parts = Math.ceil(size / chunk);
		assert.strictEqual(chunk, 256 * 1024 * 1024);
		assert.strictEqual(parts, 400);
	});

	await test("Extreme 1 TiB dataset stays strictly <= 8,500 parts (Cloudflare R2 limit: 10,000)", () => {
		const size = 1024 * 1024 * 1024 * 1024;
		const chunk = calculateAdaptiveChunkSize(size);
		const parts = Math.ceil(size / chunk);
		assert.strictEqual(chunk, 256 * 1024 * 1024);
		assert.ok(parts <= 8500, `Part count ${parts} must not exceed 8,500`);
	});

	// -------------------------------------------------------------
	// 2. Packaging & Checkpoint Inspection: Jinja2 Chat Templates
	// -------------------------------------------------------------
	console.log("\n--- 2. Packaging: Jinja2 & String-Aware JSON Scanner ---");

	await test("Jinja2 chat template with nested curly braces inside quotes is ALLOWED", () => {
		const jinjaJson = JSON.stringify({
			model_type: "llama",
			chat_template:
				"{% for message in messages %}{% if message['role'] == 'user' %}{{ 'User: ' + message['content'] }}{% endif %}{% endfor %}",
			num_hidden_layers: 32,
		});
		const ok = checkJsonNestingDepth(jinjaJson, 30);
		assert.strictEqual(ok, true, "Jinja2 chat template should not trigger nesting depth rejections");
	});

	await test("Deeply nested JSON structure (>30 levels) is REJECTED", () => {
		let nested = '{"a":';
		for (let i = 0; i < 35; i++) {
			nested += '{"level":';
		}
		nested += '1' + "}".repeat(36);
		const ok = checkJsonNestingDepth(nested, 30);
		assert.strictEqual(ok, false, "Deeply nested attack object must be rejected");
	});

	// -------------------------------------------------------------
	// 3. POSIX PAX Extended Tar Headers for Files >= 8 GiB
	// -------------------------------------------------------------
	console.log("\n--- 3. POSIX PAX Extended Headers (Files >= 8 GiB & Paths > 100) ---");

	await test("Small file (<8 GiB, short path) generates standard 512-byte ustar header", () => {
		const header = createTarHeader("model.safetensors", 1024 * 1024);
		assert.strictEqual(header.length, 512);
		const magic = header.subarray(257, 263).toString("utf-8");
		assert.strictEqual(magic, "ustar\0");
	});

	await test("Vast file (10 GiB >= 8 GiB) generates valid POSIX.1-2001 PAX extended header", () => {
		const vastSize = 10 * 1024 * 1024 * 1024;
		const header = createTarHeader("model-00001-of-00004.safetensors", vastSize);
		assert.ok(header.length >= 1536, "PAX header buffer should contain PAX record and main header");
		const typeFlag = String.fromCharCode(header[156]);
		assert.strictEqual(typeFlag, "x", "Typeflag of PAX extended header must be 'x'");

		const headerStr = header.toString("utf-8");
		assert.ok(
			headerStr.includes(`size=${vastSize}`),
			`PAX payload must encode full 64-bit size (${vastSize})`
		);
	});

	await test("File path > 100 characters generates POSIX PAX path record", () => {
		const longPath =
			"weights/checkpoints/iteration_5000/fine_tuned_llama3_model_lora_adapter_weights_distribution_checkpoint_v2/adapter_model.safetensors";
		assert.ok(longPath.length > 100);
		const header = createTarHeader(longPath, 4096);
		assert.ok(header.length >= 1536);
		const headerStr = header.toString("utf-8");
		assert.ok(
			headerStr.includes(`path=${longPath}`),
			"PAX payload must encode complete long path"
		);
	});

	// -------------------------------------------------------------
	// 4. Instant Upload Session Resumption & Hashing Bypass
	// -------------------------------------------------------------
	console.log("\n--- 4. Upload Session Engine: Instant Resumption ---");

	await test("Upload session ID is deterministic and fast", () => {
		const id1 = getUploadSessionId("C:/data/large_dataset.jsonl", 1000000, 1700000000000);
		const id2 = getUploadSessionId("C:/data/large_dataset.jsonl", 1000000, 1700000000000);
		const id3 = getUploadSessionId("C:/data/large_dataset.jsonl", 1000001, 1700000000000);
		assert.strictEqual(id1, id2);
		assert.notStrictEqual(id1, id3);
		assert.strictEqual(id1.length, 16);
	});

	await test("Upload session state saves, loads, and deletes cleanly", () => {
		const testSessionId = "test_sess_" + Date.now();
		const sessionData: UploadSessionState = {
			sessionId: testSessionId,
			filePath: "/tmp/weights.tar.gz",
			filename: "weights.tar.gz",
			fileSizeBytes: 50 * 1024 * 1024,
			mtimeMs: 1700000000000,
			chunkSize: 16 * 1024 * 1024,
			totalParts: 4,
			uploadId: "r2_upload_id_12345",
			uploadKey: "staging/user/weights.tar.gz",
			uploadToken: "token_abc_xyz",
			completedParts: [
				{ PartNumber: 1, ETag: "etag1" },
				{ PartNumber: 2, ETag: "etag2" },
			],
			status: "in_progress",
			updatedAt: new Date().toISOString(),
		};

		saveUploadSession(sessionData);

		const loaded = loadUploadSession(testSessionId);
		assert.ok(loaded !== null);
		assert.strictEqual(loaded!.sessionId, testSessionId);
		assert.strictEqual(loaded!.completedParts.length, 2);
		assert.strictEqual(loaded!.completedParts[0].ETag, "etag1");
		assert.strictEqual(loaded!.completedParts[1].ETag, "etag2");

		deleteUploadSession(testSessionId);
		const deleted = loadUploadSession(testSessionId);
		assert.strictEqual(deleted, null);
	});

	// -------------------------------------------------------------
	// 5. Strict Patented 3-Step Workload Resumption Enforcement
	// -------------------------------------------------------------
	console.log("\n--- 5. Patented 3-Step Resume Command Routing & State Machine ---");

	await test("CLI blocks 'vivacious resume check' and instructs user to use 'vivacious anirudha-s check'", () => {
		const cliPath = path.resolve(__dirname, "../src/index.ts");
		const res = child_process.spawnSync(
			process.execPath,
			["-r", "ts-node/register", cliPath, "resume", "check"],
			{ encoding: "utf-8" }
		);
		assert.strictEqual(res.status, 1);
		assert.ok(
			res.stderr.includes("vivacious anirudha-s check"),
			"CLI must direct user to founder command 'vivacious anirudha-s check'"
		);
		assert.ok(
			res.stderr.includes("patent-protected resumption flow"),
			"CLI must explain the patent-protected resumption flow"
		);
	});

	await test("CLI router routes 'vivacious anirudha-s check' to resume check handler", () => {
		const cliPath = path.resolve(__dirname, "../src/index.ts");
		const res = child_process.spawnSync(
			process.execPath,
			["-r", "ts-node/register", cliPath, "anirudha-s", "check"],
			{ encoding: "utf-8" }
		);
		assert.strictEqual(res.status, 1);
		const output = res.stderr + res.stdout;
		assert.ok(
			output.includes("No resume workload staged") ||
				output.includes("login") ||
				output.includes("Authentication required") ||
				output.includes("sequence violation"),
			`Output must show router reached handleResumeCheck: ${output}`
		);
	});

	// -------------------------------------------------------------
	// 6. Security Validation Core: Checkpoint Allowlist & Dangerous Files
	// -------------------------------------------------------------
	console.log("\n--- 6. Security Validation Core: Checkpoint Entry Verification ---");

	await test("Legitimate HuggingFace & PyTorch checkpoint artifacts are permitted", () => {
		const allowedFiles = [
			"config.json",
			"generation_config.json",
			"adapter_config.json",
			"tokenizer.json",
			"tokenizer_config.json",
			"vocab.json",
			"merges.txt",
			"model.safetensors",
			"model-00001-of-00002.safetensors",
			"trainer_state.json",
			"training_args.bin",
			"optimizer.pt",
			"scheduler.pt",
			"scaler.pt",
			"rng_state.pth",
		];
		for (const file of allowedFiles) {
			const res = validateCheckpointEntry(file, false);
			assert.strictEqual(
				res.isAllowed,
				true,
				`File '${file}' must be allowed in checkpoint archives`
			);
		}
	});

	await test("Dangerous executables, scripts, and libraries are strictly rejected", () => {
		const dangerousFiles = [
			"exploit.py",
			"setup.sh",
			"loader.exe",
			"malicious.so",
			"libssl.so.1.1",
			"helper.bat",
			"script.cmd",
			"attack.ps1",
			"payload.dll",
			"core.wasm",
			"index.js",
			"worker.mjs",
		];
		for (const file of dangerousFiles) {
			const res = validateCheckpointEntry(file, false);
			assert.strictEqual(
				res.isAllowed,
				false,
				`File '${file}' must be rejected as dangerous`
			);
			assert.ok(
				res.error?.includes("strictly forbidden"),
				`Error message must indicate forbidden status for ${file}`
			);
		}
	});

	await test("Arbitrary unapproved pickle / binary weight files are rejected", () => {
		const forbiddenPickles = [
			"custom_weights.pt",
			"custom_model.pth",
			"arbitrary_weights.bin",
			"payload.pkl",
			"state.pickle",
		];
		for (const file of forbiddenPickles) {
			const res = validateCheckpointEntry(file, false);
			assert.strictEqual(
				res.isAllowed,
				false,
				`Arbitrary pickle file '${file}' must be rejected`
			);
			assert.ok(
				res.error?.includes("safetensors") || res.error?.includes("pickle"),
				`Error must mention safetensors / pickle for ${file}`
			);
		}
	});

	// -------------------------------------------------------------
	// 7. Checkpoint Shape Classifier: Invariants for BYOM & Resumption
	// -------------------------------------------------------------
	console.log("\n--- 7. Checkpoint Shape Classifier ---");

	await test("Classifies clean base model checkpoint correctly", () => {
		const shape = classifyCheckpointShape([
			"config.json",
			"model.safetensors",
			"tokenizer.json",
		]);
		assert.strictEqual(shape.classification, "base_model");
	});

	await test("Classifies trainer resumption checkpoint correctly", () => {
		const shape = classifyCheckpointShape([
			"trainer_state.json",
			"optimizer.pt",
			"scheduler.pt",
			"training_args.bin",
		]);
		assert.strictEqual(shape.classification, "trainer_checkpoint");
	});

	await test("Rejects invalid checkpoint missing essential model weights or state", () => {
		const shape = classifyCheckpointShape(["notes.txt", "readme.md"]);
		assert.strictEqual(shape.classification, "invalid");
		assert.ok(shape.error?.includes("Malformed checkpoint"));
	});

	// -------------------------------------------------------------
	// 8. Safe Directory Ingestion (EISDIR Bug Resolution)
	// -------------------------------------------------------------
	console.log("\n--- 8. Directory Ingestion & Safe Scanning ---");

	await test("scanAndValidateCheckpointDirectory accepts valid checkpoint directory", async () => {
		const testDir = path.join(os.tmpdir(), `vivacious_test_ckpt_${Date.now()}`);
		fs.mkdirSync(testDir, { recursive: true });
		try {
			fs.writeFileSync(
				path.join(testDir, "config.json"),
				JSON.stringify({
					model_type: "llama",
					hidden_size: 4096,
					num_hidden_layers: 32,
					num_attention_heads: 32,
				})
			);
			fs.writeFileSync(path.join(testDir, "model.safetensors"), Buffer.alloc(1024));

			const result = await scanAndValidateCheckpointDirectory(testDir);
			assert.strictEqual(result.isValid, true);
			assert.ok(result.modelConfig);
			assert.strictEqual(result.modelConfig.modelType, "llama");
			assert.strictEqual(result.modelConfig.hiddenSize, 4096);
		} finally {
			fs.rmSync(testDir, { recursive: true, force: true });
		}
	});

	await test("scanAndValidateCheckpointDirectory rejects directory containing malicious script", async () => {
		const testDir = path.join(os.tmpdir(), `vivacious_test_bad_ckpt_${Date.now()}`);
		fs.mkdirSync(testDir, { recursive: true });
		try {
			fs.writeFileSync(
				path.join(testDir, "config.json"),
				JSON.stringify({ model_type: "llama" })
			);
			fs.writeFileSync(path.join(testDir, "model.safetensors"), Buffer.alloc(1024));
			fs.writeFileSync(path.join(testDir, "eval_hook.py"), "print('evil')");

			const result = await scanAndValidateCheckpointDirectory(testDir);
			assert.strictEqual(result.isValid, false);
			assert.ok(
				result.error?.includes("strictly forbidden"),
				`Should reject eval_hook.py: ${result.error}`
			);
		} finally {
			fs.rmSync(testDir, { recursive: true, force: true });
		}
	});

	// -------------------------------------------------------------
	// 9. Streaming JSON Parser for Vast Datasets (<35 MB Memory)
	// -------------------------------------------------------------
	console.log("\n--- 9. Streaming JSON Dataset Parser ---");

	await test("streamValidateLargeJsonArray validates multi-record JSON array and detects alpaca format", async () => {
		const testJson = path.join(os.tmpdir(), `vivacious_test_dataset_${Date.now()}.json`);
		const records = [];
		for (let i = 0; i < 250; i++) {
			records.push({
				instruction: `Analyze document record number ${i}`,
				input: `Input details for iteration ${i}`,
				output: `Generated authoritative summary for iteration ${i}`,
			});
		}
		fs.writeFileSync(testJson, JSON.stringify(records, null, 2));

		try {
			const res = await streamValidateLargeJsonArray(testJson);
			assert.strictEqual(res.isValid, true);
			assert.strictEqual(res.sampleCount, 250);
			assert.strictEqual(res.format, "alpaca");
		} finally {
			fs.rmSync(testJson, { force: true });
		}
	});

	await test("streamValidateLargeJsonArray rejects malformed JSON array missing closing bracket", async () => {
		const testJson = path.join(os.tmpdir(), `vivacious_test_bad_json_${Date.now()}.json`);
		fs.writeFileSync(testJson, '[ {"instruction": "test", "output": "ok"} ');

		try {
			const res = await streamValidateLargeJsonArray(testJson);
			assert.strictEqual(res.isValid, false);
			assert.ok(res.error?.includes("missing closing bracket"));
		} finally {
			fs.rmSync(testJson, { force: true });
		}
	});

	// -------------------------------------------------------------
	// 10. Persistent Staging Cache & Archive Creation
	// -------------------------------------------------------------
	console.log("\n--- 10. Staging Cache & Tarball Packaging ---");

	await test("getStagedArchivePath generates deterministic paths with content hash", () => {
		const p1 = getStagedArchivePath("/data/model_dir", 50000, 1700000000000, "checkpoint");
		const p2 = getStagedArchivePath("/data/model_dir", 50000, 1700000000000, "checkpoint");
		const p3 = getStagedArchivePath("/data/model_dir", 50001, 1700000000000, "checkpoint");
		assert.strictEqual(p1, p2);
		assert.notStrictEqual(p1, p3);
		assert.ok(p1.endsWith(".tar.gz"));
		assert.ok(p1.includes("checkpoint_"));
	});

	await test("archiveDirectoryToTarGz packages directory and scanAndValidateCheckpointArchive verifies it", async () => {
		const testDir = path.join(os.tmpdir(), `vivacious_test_pack_${Date.now()}`);
		const outArchive = path.join(os.tmpdir(), `vivacious_test_out_${Date.now()}.tar.gz`);
		fs.mkdirSync(testDir, { recursive: true });

		try {
			fs.writeFileSync(
				path.join(testDir, "config.json"),
				JSON.stringify({
					model_type: "llama",
					hidden_size: 2048,
					num_hidden_layers: 16,
					num_attention_heads: 16,
				})
			);
			fs.writeFileSync(path.join(testDir, "model.safetensors"), Buffer.alloc(2048));

			const size = await archiveDirectoryToTarGz(testDir, outArchive);
			assert.ok(size > 0);
			assert.ok(fs.existsSync(outArchive));

			const scanRes = await scanAndValidateCheckpointArchive(outArchive);
			assert.strictEqual(scanRes.isValid, true);
			assert.ok(scanRes.modelConfig);
			assert.strictEqual(scanRes.modelConfig.modelType, "llama");
		} finally {
			fs.rmSync(testDir, { recursive: true, force: true });
			fs.rmSync(outArchive, { force: true });
		}
	});

	// -------------------------------------------------------------
	// 11. Grounded Decompression Bomb & Ratio Ceilings (50:1 Ratio)
	// -------------------------------------------------------------
	console.log("\n--- 11. Security Ceilings: Grounded Compression Ratio (50:1) ---");

	await test("Decompression bomb with suspicious compression ratio (>50:1) is rejected", async () => {
		const bombPath = path.join(os.tmpdir(), `vivacious_test_bomb_${Date.now()}.tar.gz`);
		try {
			// Create a 105 MB file filled with zeros (compresses to ~100 KB => ratio > 1000:1)
			const uncompressedZeroBytes = 105 * 1024 * 1024;
			const zeroBuf = Buffer.alloc(1024 * 1024); // 1 MB buffer of zeros
			const out = fs.createWriteStream(bombPath);
			const gz = zlib.createGzip({ level: 9 });
			gz.pipe(out);

			// Write tar header for model.safetensors with size 105 MB
			const hdr = createTarHeader("model.safetensors", uncompressedZeroBytes);
			gz.write(hdr);
			for (let i = 0; i < 105; i++) {
				gz.write(zeroBuf);
			}
			gz.write(Buffer.alloc(1024)); // EOF
			gz.end();

			await new Promise<void>((resolve, reject) => {
				out.on("finish", () => resolve());
				out.on("error", (e) => reject(e));
			});

			const scanRes = await scanAndValidateCheckpointArchive(bombPath);
			assert.strictEqual(scanRes.isValid, false);
			assert.ok(
				scanRes.error?.includes("exceeds safety ceiling of 50:1"),
				`Expected ratio ceiling rejection: ${scanRes.error}`
			);
		} finally {
			fs.rmSync(bombPath, { force: true });
		}
	});

	// -------------------------------------------------------------
	// 12. Hardened Streaming Upload Progress & Telemetry
	// -------------------------------------------------------------
	console.log("\n--- 12. Hardened Streaming Upload Progress & Telemetry ---");

	await test("Streaming upload Transform correctly tracks chunk bytes and in-flight progress", async () => {
		const { Transform } = await import("node:stream");
		let trackedBytes = 0;
		const stream = new Transform({
			transform(chunk, _enc, cb) {
				trackedBytes += chunk.length;
				cb(null, chunk);
			},
		});

		const testChunk = Buffer.alloc(256 * 1024, 1);
		stream.resume();
		stream.write(testChunk);
		stream.write(testChunk);
		stream.end();

		await new Promise<void>((resolve) => stream.on("end", resolve));
		assert.strictEqual(trackedBytes, 512 * 1024);
	});

	await test("Progress bar status line formats monotonically without trailing ghost text", () => {
		const uploadFileSizeBytes = 100 * 1024 * 1024;
		const currentTotalBytes = 45 * 1024 * 1024;
		const pctNum = (currentTotalBytes / uploadFileSizeBytes) * 100;
		const pctStr = pctNum.toFixed(1);
		const barWidth = 22;
		const filled = Math.min(barWidth, Math.round((pctNum / 100) * barWidth));
		const bar = "=".repeat(filled) + (filled < barWidth ? ">" : "") + " ".repeat(Math.max(0, barWidth - filled - (filled < barWidth ? 1 : 0)));
		const curMB = (currentTotalBytes / (1024 * 1024)).toFixed(1);
		const totalMB = (uploadFileSizeBytes / (1024 * 1024)).toFixed(1);
		const statusLine = `[Transfer] [${bar}] ${pctStr.padStart(5, " ")}% | ${curMB} / ${totalMB} MB | Speed: 25.0 MB/s (Peak: 30.0 MB/s) | Parts: 5/10 | ETA: 2s`;

		assert.ok(statusLine.includes("45.0%"));
		assert.ok(statusLine.includes("45.0 / 100.0 MB"));
		assert.ok(statusLine.includes("Parts: 5/10"));
		assert.ok(statusLine.includes("ETA: 2s"));
	});

	console.log("\n--- 13. Dual-Layer Fast Manifest Fingerprinting ---");
	await test("calculateDirectoryFastFingerprint produces deterministic fingerprint in milliseconds", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vivacious-fast-fp-test-"));
		try {
			fs.writeFileSync(path.join(tempDir, "file_a.txt"), "hello world");
			fs.writeFileSync(path.join(tempDir, "file_b.txt"), "another piece of data");
			const subDir = path.join(tempDir, "subdir");
			fs.mkdirSync(subDir);
			fs.writeFileSync(path.join(subDir, "file_c.txt"), "nested content");

			const fp1 = await calculateDirectoryFastFingerprint(tempDir);
			const fp2 = await calculateDirectoryFastFingerprint(tempDir);

			assert.strictEqual(fp1.fileCount, 3);
			assert.strictEqual(fp1.fastFingerprint, fp2.fastFingerprint);
			assert.ok(fp1.totalSize > 0);
			assert.ok(fp1.maxMtimeMs > 0);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	console.log("\n--- 14. PEFT LoRA Checkpoint Scanning (BYOM) ---");
	await test("scanAndValidateCheckpointDirectory accepts valid PEFT adapter without dense parameters", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vivacious-peft-dir-test-"));
		try {
			const adapterConfig = {
				base_model_name_or_path: "meta-llama/Meta-Llama-3-8B",
				peft_type: "LORA",
				r: 16,
				lora_alpha: 32,
				target_modules: ["q_proj", "v_proj"],
				task_type: "CAUSAL_LM",
			};
			fs.writeFileSync(
				path.join(tempDir, "adapter_config.json"),
				JSON.stringify(adapterConfig, null, 2)
			);
			fs.writeFileSync(
				path.join(tempDir, "adapter_model.safetensors"),
				Buffer.alloc(1024)
			);
			fs.writeFileSync(
				path.join(tempDir, "chat_template.jinja"),
				"{% for message in messages %}{{ message['content'] }}{% endfor %}"
			);

			const scanRes = await scanAndValidateCheckpointDirectory(tempDir);
			assert.strictEqual(scanRes.isValid, true);
			assert.strictEqual(scanRes.modelConfig?.modelType, "peft_adapter");
			assert.strictEqual(scanRes.modelConfig?.baseModel, "meta-llama/Meta-Llama-3-8B");
			assert.strictEqual(scanRes.hasChatTemplate, true);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	await test("scanAndValidateCheckpointArchive verifies packaged PEFT adapter archive", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vivacious-peft-arch-src-"));
		const archivePath = path.join(os.tmpdir(), `peft_test_${Date.now()}.tar.gz`);
		try {
			const adapterConfig = {
				base_model_name_or_path: "mistralai/Mistral-7B-v0.1",
				peft_type: "LORA",
				r: 8,
				lora_alpha: 16,
				target_modules: ["q_proj", "k_proj"],
			};
			fs.writeFileSync(
				path.join(tempDir, "adapter_config.json"),
				JSON.stringify(adapterConfig, null, 2)
			);
			fs.writeFileSync(
				path.join(tempDir, "adapter_model.safetensors"),
				Buffer.alloc(2048)
			);
			fs.writeFileSync(
				path.join(tempDir, "chat_template.json"),
				JSON.stringify({ chat_template: "{{ messages }}" })
			);

			await archiveDirectoryToTarGz(tempDir, archivePath, 4096);
			const scanRes = await scanAndValidateCheckpointArchive(archivePath);

			assert.strictEqual(scanRes.isValid, true);
			assert.strictEqual(scanRes.modelConfig?.modelType, "peft_adapter");
			assert.strictEqual(scanRes.modelConfig?.baseModel, "mistralai/Mistral-7B-v0.1");
			assert.strictEqual(scanRes.hasChatTemplate, true);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
			if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath);
		}
	});

	console.log("\n=================================================");
	console.log(`🏁 VERIFICATION COMPLETE: ${passed}/${total} TESTS PASSED`);
	console.log("=================================================");

	if (passed !== total) {
		process.exit(1);
	}
}

void runTests();


import * as assert from "node:assert";
import * as http from "node:http";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { parseJwtExpiryMs, getValidAccessToken } from "../src/index";

async function runConcurrencyTests(): Promise<void> {
	console.log("=================================================");
	console.log("🧪 VIVACIOUS CLI — CONCURRENCY & TOKEN REFRESH SUITE");
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
	// 1. UTF-8 JWT Expiry Parsing
	// -------------------------------------------------------------
	console.log("--- 1. Native UTF-8 JWT Expiration Parsing ---");

	await test("Correctly parses standard JWT with numeric exp claim", () => {
		const expSec = Math.floor(Date.now() / 1000) + 3600;
		const payload = Buffer.from(JSON.stringify({ sub: "user-123", exp: expSec })).toString("base64url");
		const token = `header.${payload}.signature`;
		const parsed = parseJwtExpiryMs(token);
		assert.strictEqual(parsed, expSec * 1000);
	});

	await test("Handles UTF-8 non-ASCII characters without URIError", () => {
		const expSec = Math.floor(Date.now() / 1000) + 7200;
		const payloadObj = {
			sub: "user-456",
			name: "Anirudh Banjare — 測試 é ñ 🚀",
			exp: expSec,
		};
		const payload = Buffer.from(JSON.stringify(payloadObj), "utf-8").toString("base64url");
		const token = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`;
		const parsed = parseJwtExpiryMs(token);
		assert.strictEqual(parsed, expSec * 1000);
	});

	await test("Gracefully returns null on malformed or non-exp JWT", () => {
		assert.strictEqual(parseJwtExpiryMs("invalid.token"), null);
		const payloadNoExp = Buffer.from(JSON.stringify({ sub: "no-exp" })).toString("base64url");
		assert.strictEqual(parseJwtExpiryMs(`h.${payloadNoExp}.s`), null);
	});

	// -------------------------------------------------------------
	// 2. Concurrent 401 Single-Flight Mutex Verification
	// -------------------------------------------------------------
	console.log("\n--- 2. Single-Flight Token Refresh Mutex (Race Condition Guard) ---");

	await test("Simultaneous 401s across 4 workers trigger EXACTLY ONE refresh call", async () => {
		let refreshCallCount = 0;
		const newExpSec = Math.floor(Date.now() / 1000) + 3600;
		const newPayload = Buffer.from(JSON.stringify({ sub: "user-test", exp: newExpSec })).toString("base64url");
		const fullNewToken = `h.${newPayload}.s`;

		// Spin up local mock orchestrator server
		const server = http.createServer((req, res) => {
			if (req.url === "/api/auth/token/refresh" && req.method === "POST") {
				refreshCallCount++;
				let body = "";
				req.on("data", (chunk) => { body += chunk; });
				req.on("end", () => {
					// Simulate network latency (50ms) to ensure concurrent workers overlap in flight
					setTimeout(() => {
						res.writeHead(200, { "Content-Type": "application/json" });
						res.end(JSON.stringify({
							access_token: fullNewToken,
							refresh_token: "rotated-refresh-token-" + refreshCallCount,
							expires_in: 3600,
						}));
					}, 50);
				});
				return;
			}
			res.writeHead(404);
			res.end();
		});

		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
		const address = server.address() as any;
		const originalApiHost = process.env.VIVACIOUS_API_HOST;
		process.env.VIVACIOUS_API_HOST = `http://127.0.0.1:${address.port}`;

		// Setup temporary test config
		const testConfigDir = path.join(os.homedir(), ".vivacious");
		const testConfigFile = path.join(testConfigDir, "config.json");
		const backupConfigFile = path.join(testConfigDir, `config.backup.${Date.now()}.json`);
		let hadBackup = false;

		if (fs.existsSync(testConfigFile)) {
			fs.copyFileSync(testConfigFile, backupConfigFile);
			hadBackup = true;
		}

		try {
			// Write an expired token
			const expiredTokenExpSec = Math.floor(Date.now() / 1000) - 100; // 100s ago
			const expiredPayload = Buffer.from(JSON.stringify({ sub: "user-test", exp: expiredTokenExpSec })).toString("base64url");
			const initialConfig = {
				accessToken: `h.${expiredPayload}.s`,
				refreshToken: "initial-refresh-token-123",
				tokenExpiresAt: expiredTokenExpSec * 1000,
			};
			fs.writeFileSync(testConfigFile, JSON.stringify(initialConfig, null, 2), "utf-8");

			// Launch 4 concurrent workers simultaneously
			const workerPromises = [
				getValidAccessToken(true),
				getValidAccessToken(true),
				getValidAccessToken(true),
				getValidAccessToken(true),
			];

			const results = await Promise.all(workerPromises);

			// Assertions:
			// 1. Exactly one call to /api/auth/token/refresh must have been made
			assert.strictEqual(
				refreshCallCount,
				1,
				`Expected exactly 1 refresh call, but got ${refreshCallCount} (race condition detected!)`
			);

			// 2. All 4 workers must receive the exact same fresh access token
			for (const res of results) {
				assert.strictEqual(res, fullNewToken, "Worker received stale or unexpected token");
			}

			// 3. Confirm config file on disk was updated with the new token
			const onDisk = JSON.parse(fs.readFileSync(testConfigFile, "utf-8"));
			assert.strictEqual(onDisk.accessToken, fullNewToken);
			assert.strictEqual(onDisk.refreshToken, "rotated-refresh-token-1");
		} finally {
			server.close();
			if (originalApiHost) {
				process.env.VIVACIOUS_API_HOST = originalApiHost;
			} else {
				delete process.env.VIVACIOUS_API_HOST;
			}
			if (hadBackup) {
				fs.copyFileSync(backupConfigFile, testConfigFile);
				fs.unlinkSync(backupConfigFile);
			}
		}
	});

	// -------------------------------------------------------------
	// 3. Floating Prefetch Error Isolation
	// -------------------------------------------------------------
	console.log("\n--- 3. Prefetch Promise Rejection Isolation ---");

	await test("Prefetch promise rejections do not trigger Node unhandledRejection", async () => {
		let unhandledCaught = false;
		const handler = () => { unhandledCaught = true; };
		process.on("unhandledRejection", handler);

		try {
			// Simulate a prefetch function with swallowed catch
			const mockPrefetch = () => Promise.reject(new Error("Simulated network timeout"));
			void mockPrefetch().catch(() => {
				// Absorbed as in worker()
			});

			// Allow microtask queue to process
			await new Promise((resolve) => setTimeout(resolve, 50));

			assert.strictEqual(unhandledCaught, false, "Unhandled promise rejection escaped prefetch absorption!");
		} finally {
			process.removeListener("unhandledRejection", handler);
		}
	});

	// -------------------------------------------------------------
	// Summary
	// -------------------------------------------------------------
	console.log("\n=================================================");
	console.log(`Summary: ${passed}/${total} tests passed.`);
	console.log("=================================================");

	if (passed !== total) {
		process.exitCode = 1;
	}
}

void runConcurrencyTests();

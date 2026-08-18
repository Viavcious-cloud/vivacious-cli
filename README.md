# Vivacious Cloud CLI

The official command-line interface for [Vivacious Cloud](https://vivaciouscloud.com) — seamlessly prepare datasets, estimate training permits, deploy fine-tuning jobs, track balances, and download model weights.

## Installation

### Linux & macOS
```bash
curl -fsSL https://vivaciouscloud.com/install.sh | sh
```

### Windows (PowerShell)
```powershell
iwr https://vivaciouscloud.com/install.ps1 -useb | iex
```

## Quick Start

1. **Log in to your workspace**:
   ```bash
   vivacious login anirudha-s
   ```

2. **Prepare a dataset locally** (generates manifest & SHA-256 fingerprint without consuming GPU or uploading):
   ```bash
   vivacious prepare ./my-dataset
   ```

3. **Check pre-flight financial permit & estimated costs**:
   ```bash
   vivacious permit anirudha-s ambition --model unsloth/Llama-3.2-3B-Instruct --method lora
   ```

4. **Deploy training job**:
   ```bash
   vivacious deploy anirudha-s
   ```

5. **Check account balance & limits**:
   ```bash
   vivacious balance
   ```

6. **Download trained model weights**:
   ```bash
   vivacious download <job-id>
   ```

## Development

```bash
bun install
bun run start
```

### Build Binaries

```bash
bun build --compile --target=bun-linux-x64 ./src/index.ts --outfile dist/vivacious-linux-x64
bun build --compile --target=bun-linux-arm64 ./src/index.ts --outfile dist/vivacious-linux-arm64
bun build --compile --target=bun-darwin-x64 ./src/index.ts --outfile dist/vivacious-macos-x64
bun build --compile --target=bun-darwin-arm64 ./src/index.ts --outfile dist/vivacious-macos-arm64
bun build --compile --target=bun-windows-x64 ./src/index.ts --outfile dist/vivacious-windows-x64.exe
```

## License
MIT

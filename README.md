# Vivacious Cloud

<p align="center">
  <a href="https://vivaciouscloud.com">
    <img src="https://vivaciouscloud.com/assets/logo.svg" alt="Vivacious Cloud Logo" width="120" height="120" />
  </a>
</p>

<h3 align="center">
  Your training job, always on the cheapest GPU alive.
</h3>

<p align="center">
  <strong>Autonomous Multi-Cloud GPU Routing for LLM Fine-Tuning & Training</strong>
</p>

<p align="center">
  <a href="https://vivaciouscloud.com"><img src="https://img.shields.io/badge/Web-vivaciouscloud.com-00DC82?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Vivacious Cloud Website" /></a>
  <a href="https://github.com/Viavcious-cloud/vivacious-cli/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue?style=for-the-badge" alt="Release" /></a>
  <a href="https://github.com/Viavcious-cloud/vivacious-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" /></a>
  <a href="https://t.me/iEverYours"><img src="https://img.shields.io/badge/Community-Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Community" /></a>
</p>

---

## 🚀 Welcome to Vivacious Cloud

**[Vivacious Cloud](https://vivaciouscloud.com)** is a fully managed, zero-code LLM fine-tuning and training platform built for developers, indie hackers, researchers, and enterprise AI teams.

Instead of locking you into a single cloud provider or forcing you to manually hunt for cheap GPUs across fragmented websites, Vivacious Cloud's **autonomous multi-cloud routing engine shops 12+ cloud broker networks in real-time** (AWS, GCP, Azure, Lambda Labs, RunPod, CoreWeave, Vast.ai, Paperspace, TensorDock, FluidStack, Crusoe Cloud, and Oracle Cloud) every 60 seconds to automatically secure the lowest spot rate alive for your training run.

**One terminal command in, production-grade model weights out. No `train.py`. No CUDA drivers. Zero DevOps.**

---

## ⚡ The Pain Points Vivacious Cloud Solves

Fine-tuning open-source models (Llama 3, Mistral, Qwen, DeepSeek, Gemma, Phi) should be simple. In reality, traditional cloud providers make it painful, expensive, and fragile. Here is how Vivacious Cloud solves each pain point:

### 1. 💸 The Cloud Price Gouging & Fragmented Market Trap
- **The Problem**: Manually comparing spot prices across AWS, RunPod, Vast.ai, and Lambda Labs takes forever. Capacity fluctuates constantly, and locking into a single vendor means paying up to 400% more than necessary.
- **The Vivacious Cloud Solution**: Our autonomous routing engine monitors wholesale GPU spot markets continuously. When you dispatch a training job, it automatically places your container onto whichever certified provider offers the absolute lowest price at that exact second.

### 2. 💥 Out-Of-Memory (OOM) Budget Drain
- **The Problem**: You spin up a high-end GPU instance, pay for initialization, wait for dependencies to download, start training, and 15 minutes later PyTorch throws `CUDA out of memory`. You've paid for wasted compute and received zero progress.
- **The Vivacious Cloud Solution**: **Guaranteed Preflight OOM Guard**. Before any remote GPU instance is booted or billed, our analytical preflight probe evaluates your dataset token length, model architecture, precision, and LoRA rank to guarantee VRAM headroom. If it won't fit, it halts safely at **₹0 cost**.

### 3. 📉 Spot Preemption & Wiped Progress
- **The Problem**: Spot instances are affordable, but cloud providers can reclaim them without notice. When a node is killed mid-epoch, you lose uncommitted checkpoints, hours of compute, and money.
- **The Vivacious Cloud Solution**: **Autonomous Mid-Job Migration**. If a spot provider triggers a preemption signal or spot rates surge, Vivacious Cloud instantly snapshots the training state to high-speed object storage, migrates your job to an alternative provider, and resumes seamlessly—with zero data loss and zero manual babysitting.

### 4. 🛠️ The "DevOps & CUDA Hell" Time Sink
- **The Problem**: Setting up PyTorch versions, CUDA toolkits, flash-attention compilation, bitsandbytes, and writing multi-GPU training scripts distracts you from your actual AI product.
- **The Vivacious Cloud Solution**: **Zero-Code LLM Fine-Tuning**. You never write a single line of `train.py` or debug a CUDA driver. Simply supply your dataset (`.jsonl`) and base model ID. Vivacious Cloud handles tokenization, optimal LoRA / 4-bit QLoRA hyperparameters, and training orchestration automatically.

### 5. 👻 Hidden Subscriptions, Idle VMs & Egress Fees
- **The Problem**: Traditional clouds charge you hourly for idle VMs you forgot to shut down, plus exorbitant bandwidth egress fees to download your trained checkpoints.
- **The Vivacious Cloud Solution**: **Transparent Prepaid Compute & Zero Egress**.
  - **Zero Idle Cost**: No monthly subscriptions, no idle machine charges. You only pay for exact training minutes.
  - **Zero Egress Fees**: Datasets and checkpoints live on Cloudflare R2 with free egress.
  - **10% Price Protection Policy**: If live spot rates fluctuate more than 10% above your pre-flight quoted estimate mid-run, the engine automatically pauses into a safe state.

---

## 📊 Comparison: Vivacious Cloud vs. Traditional Approaches

| Feature | Vivacious Cloud | RunPod / Vast.ai | AWS / GCP / Azure |
| :--- | :---: | :---: | :---: |
| **GPU Provider Sourcing** | **Autonomous (12+ clouds)** | Manual selection | Single vendor lock-in |
| **Code Required** | **Zero code (No `train.py`)** | Manual script writing | Full ML & DevOps stack |
| **Spot Preemption Defense** | **Auto-checkpoint & migrate** | Job dies, progress lost | Job dies, progress lost |
| **Preflight OOM Protection** | **Included (₹0 pre-check)** | None (Billed on crash) | None (Billed on crash) |
| **CUDA / PyTorch Setup** | **Zero setup** | Manual Docker setup | Manual configuration |
| **Egress Fees for Weights** | **₹0 (Zero Egress)** | Varies / Billable | Expensive bandwidth fees |
| **Idle Machine Charges** | **₹0 (Pay strictly per run)** | Billed until stopped | Billed until stopped |
| **CLI Experience** | **Unified across OS** | Provider-specific | Complex AWS/gcloud CLI |

---

## 💻 Universal Installation

Install the official Vivacious Cloud CLI in seconds:

### Linux & macOS
```bash
curl -fsSL https://vivaciouscloud.com/install.sh | sh
```

### Windows (PowerShell)
```powershell
iwr https://vivaciouscloud.com/install.ps1 -useb | iex
```

---

## 🎯 3-Step Quick Start

Train your custom LLM from your terminal in three easy steps:

### 1. Log in to your workspace
Create your account at [vivaciouscloud.com](https://vivaciouscloud.com), then authenticate your CLI:
```bash
vivacious login <your-workspace-slug>
```

### 2. Prepare your dataset locally
Generate your dataset manifest and cryptographic SHA-256 fingerprint locally without consuming GPU compute or bandwidth:
```bash
vivacious prepare ./my-dataset.jsonl
```

### 3. Check pre-flight permit & deploy to the cheapest GPU alive
Check live spot rate estimates, VRAM headroom verification, and launch your run:
```bash
# Verify financial permit & analytical VRAM fit
vivacious permit <your-workspace-slug> <run-name> --model unsloth/Llama-3.2-3B-Instruct --method lora

# Deploy training run across 12+ cloud networks
vivacious deploy <your-workspace-slug>
```

### 4. Monitor & download your model weights
```bash
# Check credit balance and active jobs
vivacious balance

# Download trained weights post-completion
vivacious download <job-id>
```

---

## 🛠️ Supported Models & Methods

- **Training Methods**:
  - LoRA (Low-Rank Adaptation)
  - 4-bit QLoRA (Quantized Low-Rank Adaptation)
  - Full Precision Fine-Tuning
- **Base Models**:
  - Any public Hugging Face model repository (e.g., Llama 3/3.1/3.2, Mistral, Qwen 2.5, DeepSeek, Gemma 2, Phi-3/4)
  - Custom weights archive (`.tar.gz`)
- **Dataset Format**:
  - Standard JSON Lines (`.jsonl`) instruction-response or conversational formats.

---

## 🌐 Get Started with Vivacious Cloud

Ready to fine-tune your models faster and cheaper than ever before?

- 🌐 **Official Website & Console**: [https://vivaciouscloud.com](https://vivaciouscloud.com)
- 💬 **Telegram Community & Support**: [https://t.me/iEverYours](https://t.me/iEverYours)
- 📧 **Technical Support**: `support@vivaciouscloud.com`
- 💳 **Billing & Inquiries**: `help@vivaciouscloud.com`

---

## 💻 Developer & Source Compilation

If you want to build the CLI binary from source:

```bash
bun install
bun run start
```

### Build Platform Binaries
```bash
bun build --compile --target=bun-linux-x64 ./src/index.ts --outfile dist/vivacious-linux-x64
bun build --compile --target=bun-linux-arm64 ./src/index.ts --outfile dist/vivacious-linux-arm64
bun build --compile --target=bun-darwin-x64 ./src/index.ts --outfile dist/vivacious-macos-x64
bun build --compile --target=bun-darwin-arm64 ./src/index.ts --outfile dist/vivacious-macos-arm64
bun build --compile --target=bun-windows-x64 ./src/index.ts --outfile dist/vivacious-windows-x64.exe
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { chromium } = require('playwright');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const OUTPUT_DIR = path.join(PROJECT_ROOT, 'output');
const PYTHON_PATH = path.join(PROJECT_ROOT, '.venv', 'bin', 'python');
const PYTHON_SCRIPT = path.join(PROJECT_ROOT, 'pqc_compare.py');
const TERMINAL_SCREENSHOT = path.join(
  PROJECT_ROOT,
  'Screenshot 2026-03-26 at 23.36.01.png'
);
const REPORT_PDF_PATH = path.join(OUTPUT_DIR, 'pqc-analysis.pdf');
const SCREENSHOT_FULL_PATH = path.join(OUTPUT_DIR, 'report-screenshot-full.png');
const SCREENSHOT_KEYSIZE_PATH = path.join(OUTPUT_DIR, 'report-screenshot-keysize.png');

function parseRunsArg() {
  const runsArgIndex = process.argv.indexOf('--runs');
  if (runsArgIndex === -1) {
    return 10;
  }

  const value = Number(process.argv[runsArgIndex + 1]);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error('Invalid --runs value. Provide a positive integer.');
  }
  return value;
}

function ensurePrerequisites() {
  if (!fs.existsSync(PYTHON_PATH)) {
    throw new Error(`Python virtual environment not found at ${PYTHON_PATH}.`);
  }

  if (!fs.existsSync(PYTHON_SCRIPT)) {
    throw new Error(`Python script not found at ${PYTHON_SCRIPT}.`);
  }

  if (!fs.existsSync(TERMINAL_SCREENSHOT)) {
    throw new Error(
      `Terminal screenshot not found at ${TERMINAL_SCREENSHOT}. Please keep it in the project root.`
    );
  }

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

function runPythonComparison(runs) {
  const output = execFileSync(PYTHON_PATH, [PYTHON_SCRIPT, '--runs', String(runs)], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  return output.trim();
}

function parseMetrics(output) {
  const patterns = {
    rsaMedianMs: /RSA-3072 keygen\s*:\s*([\d.]+)\s*ms/i,
    mlkemMedianMs: /ML-KEM-768 keygen\s*:\s*([\d.]+)\s*ms/i,
    rsaPublicKey: /RSA-3072 public key\s*:\s*(\d+)/i,
    mlkemPublicKey: /ML-KEM-768 public key\s*:\s*(\d+)/i,
    rsaCiphertext: /RSA-OAEP ciphertext\s*:\s*(\d+)/i,
    mlkemCiphertext: /ML-KEM ciphertext\s*:\s*(\d+)/i,
    secretMatch: /Shared secret match:\s*(True|False)/i,
  };

  const parsed = {};
  for (const [key, pattern] of Object.entries(patterns)) {
    const match = output.match(pattern);
    if (!match) {
      throw new Error(`Could not parse ${key} from Python output.`);
    }
    parsed[key] = match[1];
  }

  parsed.rsaMedianMs = Number(parsed.rsaMedianMs);
  parsed.mlkemMedianMs = Number(parsed.mlkemMedianMs);
  parsed.rsaPublicKey = Number(parsed.rsaPublicKey);
  parsed.mlkemPublicKey = Number(parsed.mlkemPublicKey);
  parsed.rsaCiphertext = Number(parsed.rsaCiphertext);
  parsed.mlkemCiphertext = Number(parsed.mlkemCiphertext);
  parsed.secretMatch = /^true$/i.test(parsed.secretMatch);

  parsed.publicKeySizeRatio = Number((parsed.mlkemPublicKey / parsed.rsaPublicKey).toFixed(2));
  parsed.ciphertextSizeRatio = Number((parsed.mlkemCiphertext / parsed.rsaCiphertext).toFixed(2));

  return parsed;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function buildReportHtml({ runs, terminalOutput, metrics, terminalScreenshotBase64 }) {
  const secretStatus = metrics.secretMatch ? 'Yes' : 'No';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PQC vs Classical Analysis Report</title>
  <style>
    :root {
      --bg: #f3f7fb;
      --surface: #ffffff;
      --text: #14213d;
      --muted: #3f4d63;
      --accent: #ef476f;
      --accent-soft: #ffe0e7;
      --border: #d5deea;
      --terminal-bg: #0f172a;
      --terminal-text: #e2e8f0;
      --good: #0b6e4f;
      --font-body: "IBM Plex Sans", "Segoe UI", sans-serif;
      --font-mono: "JetBrains Mono", "SFMono-Regular", Menlo, monospace;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: var(--font-body);
      color: var(--text);
      background: radial-gradient(circle at top right, #d8efff 0%, #f3f7fb 45%, #eef2f7 100%);
      line-height: 1.5;
    }

    .page {
      max-width: 980px;
      margin: 28px auto;
      padding: 24px;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 18px;
      box-shadow: 0 8px 24px rgba(20, 33, 61, 0.08);
      break-inside: avoid;
    }

    h1, h2, h3 {
      margin-top: 0;
      color: var(--text);
      letter-spacing: 0.2px;
    }

    h1 {
      font-size: 2rem;
      margin-bottom: 6px;
    }

    .subtitle {
      color: var(--muted);
      margin: 0;
    }

    .badge {
      display: inline-block;
      margin-top: 10px;
      padding: 6px 10px;
      border-radius: 999px;
      font-weight: 600;
      font-size: 0.85rem;
      background: var(--accent-soft);
      color: #8a1c3a;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .metric {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      background: #f8fbff;
    }

    .metric strong {
      display: block;
      font-size: 0.9rem;
      color: var(--muted);
      margin-bottom: 4px;
    }

    .metric span {
      font-weight: 700;
      font-size: 1.2rem;
    }

    .analysis {
      border-left: 5px solid var(--accent);
      background: #fff6f8;
      padding: 12px 14px;
      border-radius: 8px;
    }

    ol {
      margin: 0;
      padding-left: 22px;
    }

    pre {
      margin: 0;
      border-radius: 12px;
      background: var(--terminal-bg);
      color: var(--terminal-text);
      padding: 14px;
      overflow: auto;
      font-family: var(--font-mono);
      font-size: 0.88rem;
      border: 1px solid #243147;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .terminal-shot {
      width: 100%;
      border-radius: 12px;
      border: 1px solid var(--border);
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
    }

    .footnote {
      font-size: 0.9rem;
      color: var(--muted);
      margin-top: 8px;
    }

    .status-yes {
      color: var(--good);
      font-weight: 700;
    }

    .repo-link {
      word-break: break-all;
      color: #0c4a6e;
      font-weight: 600;
      text-decoration: none;
    }

    @media (max-width: 780px) {
      .page {
        margin: 16px auto;
        padding: 10px;
      }

      .metrics-grid {
        grid-template-columns: 1fr;
      }

      .card {
        padding: 16px;
      }
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="card" id="report-header">
      <h1>PQC vs Classical Cryptography Report</h1>
      <div class="badge">Run count: ${runs}</div>
    </section>

    <section class="card" id="key-size-section">
      <h2>Critical Analysis: Massive Key-Size Difference</h2>
      <div class="metrics-grid">
        <div class="metric"><strong>RSA-3072 public key</strong><span>${metrics.rsaPublicKey} bytes</span></div>
        <div class="metric"><strong>ML-KEM-768 public key</strong><span>${metrics.mlkemPublicKey} bytes</span></div>
        <div class="metric"><strong>RSA-OAEP ciphertext</strong><span>${metrics.rsaCiphertext} bytes</span></div>
        <div class="metric"><strong>ML-KEM ciphertext</strong><span>${metrics.mlkemCiphertext} bytes</span></div>
      </div>
      <p class="analysis">
        ML-KEM-768 public keys are approximately <strong>${metrics.publicKeySizeRatio}x</strong> larger than RSA-3072 public keys in this PoC.
        ML-KEM ciphertexts are approximately <strong>${metrics.ciphertextSizeRatio}x</strong> larger than RSA-OAEP ciphertexts.
        This is the key engineering trade-off: post-quantum security generally requires larger transmitted artifacts, which has direct implications for storage, bandwidth, and protocol framing.
      </p>
      <p class="footnote">Shared secret verification: <span class="${metrics.secretMatch ? 'status-yes' : ''}">${secretStatus}</span></p>
    </section>

    <section class="card" id="timing-section">
      <h2>Performance Snapshot</h2>
      <div class="metrics-grid">
        <div class="metric"><strong>RSA-3072 median keygen</strong><span>${metrics.rsaMedianMs.toFixed(3)} ms</span></div>
        <div class="metric"><strong>ML-KEM-768 median keygen</strong><span>${metrics.mlkemMedianMs.toFixed(3)} ms</span></div>
      </div>
    </section>

    <section class="card" id="terminal-output">
      <h2>Terminal Output Evidence</h2>
      <pre>${escapeHtml(terminalOutput)}</pre>
      <p class="footnote">Screenshot captured from project folder:</p>
      <img class="terminal-shot" src="data:image/png;base64,${terminalScreenshotBase64}" alt="Terminal output screenshot" />
    </section>

    <section class="card" id="project-link">
      <h2>Python Project Repository</h2>
      <a class="repo-link" href="https://github.com/shklasith/Post-Quantum-Proof-of-Concept.git">
        https://github.com/shklasith/Post-Quantum-Proof-of-Concept.git
      </a>
    </section>
  </main>
</body>
</html>`;
}

async function generateArtifacts(html) {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 2600 } });
  await page.setContent(html, { waitUntil: 'networkidle' });

  const keySizeSection = page.locator('#key-size-section');
  await keySizeSection.screenshot({ path: SCREENSHOT_KEYSIZE_PATH });

  await page.screenshot({ path: SCREENSHOT_FULL_PATH, fullPage: true });

  await page.pdf({
    path: REPORT_PDF_PATH,
    format: 'A4',
    printBackground: true,
    margin: {
      top: '12mm',
      bottom: '12mm',
      left: '10mm',
      right: '10mm',
    },
  });

  await browser.close();
}

async function main() {
  const runs = parseRunsArg();
  ensurePrerequisites();

  const terminalOutput = runPythonComparison(runs);
  const metrics = parseMetrics(terminalOutput);
  const terminalScreenshotBase64 = fs.readFileSync(TERMINAL_SCREENSHOT).toString('base64');
  const html = buildReportHtml({ runs, terminalOutput, metrics, terminalScreenshotBase64 });

  await generateArtifacts(html);

  console.log('Generated report artifacts:');
  console.log(`- ${REPORT_PDF_PATH}`);
  console.log(`- ${SCREENSHOT_FULL_PATH}`);
  console.log(`- ${SCREENSHOT_KEYSIZE_PATH}`);
}

main().catch((error) => {
  console.error('Failed to generate report:', error.message);
  process.exit(1);
});

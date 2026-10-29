# Local Evaluation Results — 2026-10-29

Measured at **2026-10-29T10:21:26.730074Z** on a local Windows AMD64 host (Python 3.13.15, 16 logical CPUs). These are illustrative local results, not deployed/mobile performance claims.

## Image analysis

Input: `frontend/src/assets/hero.png` (343×361 PNG asset with palette transparency), 3 repeated runs. Transparent pixels are composited on white before grayscale analysis.

| Metric | Mean/result |
|---|---:|
| Plain-image entropy | 1.176114 bits/byte |
| Ciphertext entropy | 7.998511 bits/byte |
| Controlled one-bit NPCR | 0.000808% |
| Controlled one-bit UACI | 0.000003% |
| Ciphertext adjacent correlation H / V / diagonal | -0.002406 / -0.000410 / -0.000732 |
| Decrypted MSE / PSNR | 0.0 / ∞ dB |
| Mean AES-GCM encrypt / decrypt | 0.5859 / 0.1291 ms |
| Mean image-analysis wall time | 32.9761 ms |

### Image size sweep

Each target long-side size was run 3 times; throughput and crypto timings are for this local Python process.

| Target side | Actual shape | Encrypt mean (ms) | Decrypt mean (ms) | Cipher entropy | NPCR (%) | UACI (%) | MSE |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 61×64 | 0.0187 | 0.0053 | 7.950357 | 0.025615 | 0.000100 | 0.0 |
| 128 | 122×128 | 0.0122 | 0.0521 | 7.986572 | 0.006404 | 0.000025 | 0.0 |
| 256 | 243×256 | 0.0304 | 0.0105 | 7.996888 | 0.001608 | 0.000006 | 0.0 |
| 512 | 486×512 | 0.1781 | 0.0782 | 7.999228 | 0.000402 | 0.000002 | 0.0 |
| 1024 | 973×1024 | 0.5040 | 0.2717 | 7.999819 | 0.000100 | 0.000000 | 0.0 |

AES-GCM is an authenticated stream construction; these ciphertext-byte statistics are illustrative. NPCR/UACI are from an isolated same-key/same-nonce, one-bit differential experiment and are not measurements of safe production nonce reuse. They should not be compared to classic image-cipher thresholds.

## AES processing comparison

The baseline is an in-memory byte copy. AES-GCM adds a 12-byte nonce and 16-byte authentication tag (28 bytes total). This does not compare two network deployments and excludes HTTP, database, and device time.

| Payload | Copy baseline mean (ms) | AES encrypt mean (ms) | AES decrypt mean (ms) | AES total mean (ms) | Round-trip throughput (MiB/s) | Overhead |
|---:|---:|---:|---:|---:|---:|---:|
| 1,024 B | 0.0009 | 0.0061 | 0.0040 | 0.0102 | 96.09 | 28 B (2.7344%) |
| 65,536 B | 0.0072 | 0.0134 | 0.0150 | 0.0284 | 2201.67 | 28 B (0.0427%) |
| 262,144 B | 0.0169 | 0.0374 | 0.0433 | 0.0808 | 3095.98 | 28 B (0.0107%) |
| 1,048,576 B | 0.2142 | 0.2961 | 0.2966 | 0.5927 | 1687.12 | 28 B (0.0027%) |

Benchmark used 8 rounds per size: 1 KiB, 64 KiB, 256 KiB, and 1 MiB. Sub-millisecond figures, especially the copy baseline, are sensitive to timer resolution and process noise.

## Text crypto and teaching metrics

Input: `82` UTF-8 bytes of a fixed SentinelDrop demo sentence. Timings and block-cipher statistics use fresh temporary cryptographic material.

| Metric | Result |
|---|---:|
| AES-GCM encryption | 0.1931 ms |
| AES-GCM decryption | 0.0088 ms |
| Encryption + decryption | 0.2019 ms |
| AES confusion (mean output bits changed) | 49.22% |
| AES diffusion (mean output bits changed) | 50.16% |
| AES avalanche (16 one-bit plaintext flips) | 50.34% |
| SHA-256 avalanche (one input-bit flip) | 53.52% |

SHA-256 preimage and collision resistance are theoretical properties rather than sample-run measurements; for SHA-256, generic work estimates are about 2^256 for preimage search and 2^128 for collision search. Decryption recovery matched: **True**.

## Not measured in this run

- Real voice recognition accuracy: no speech recording was supplied. The Vosk model and browser archive were smoke-tested with a one-second silent WAV, which validates model loading but not word recognition.
- Render/Vercel latency, Android/iOS CPU and microphone accuracy, secured-vs-unsecured end-to-end network baseline, and two-device transfer timing.
- The image source is a project icon/illustration, not a natural image dataset. Rerun Admin image analysis with representative project photos before using image statistics as general findings.

Complete raw values are in [`local_evaluation_results_2026-10-29.json`](local_evaluation_results_2026-10-29.json).

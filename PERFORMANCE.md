# Measured performance

Measurements come from the final repository Playwright/Chromium run against the checked-in 14,614-record capture over a local HTTP server. They are repeatable acceptance-test observations, not claims about public GitHub Pages latency or physical low-end devices.

The compact Explore index is **13,428,927 bytes**, below its **16,777,216-byte** ceiling. The first Explore load fetched the index and the **807,447-byte** EPSS sidecar (**14,236,374 bytes total**) and fetched **zero** full-record shards. One measured dossier opened exactly one required **45,373-byte** day shard and rendered in **0.161 seconds**; the separate loader/integrity scenario also verified a current-day shard of **295,777 bytes**.

The measured first Explore load took **1.08 seconds** from navigation through index visibility and service-worker control. The instrumented index verification-to-first-list-render interval was **897.2 ms**. At 14,614 indexed records, typing an exact CVE ID and rendering its one matching row took **93.36 ms**; the synchronous list-render portion took **5.4 ms**. The `app.js` resource timing was **9.4 ms** for **145,725 transfer bytes**.

Chromium reported a **92.13 MiB** JavaScript heap at the measurement point. Its Long Task observer recorded **two** tasks, with a maximum of **446 ms**. The unchanged repeat load took **0.909 seconds**, revalidated the manifest with **304 Not Modified**, and transferred **zero** repeat index/EPSS sidecar bodies.

Responsive checks exercised all five views from **320 through 1,440 CSS pixels** without horizontal document overflow. The sticky-search audit separately confirmed stable geometry while scrolling at 320, 360, 390, 412, 768, 1,024 and 1,440 pixels. Transfer timing and memory vary by browser, device, connection and compression; public GitHub Pages was not benchmarked.

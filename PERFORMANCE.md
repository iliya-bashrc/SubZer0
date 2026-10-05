# Measured performance

The before measurements were captured against the original 14,614-record build in `/workspace/subzero-rebuild-evidence/before/metrics.json`. The final numbers below come from the passing local Chromium Playwright run against the same source-record and EPSS capture, after the compact index and compression changes. These are local HTTP observations, not public GitHub Pages or physical low-end-device measurements.

| First-view data bodies | Before | Current | Difference |
|---|---:|---:|---:|
| Search index | 13,428,927 B raw JSON | 1,494,118 B gzip | 88.87% fewer bytes |
| Index + EPSS sidecar | 14,236,374 B | 2,301,565 B | 11,934,809 B saved (83.83%) |

The current v3 index expands to 7,904,199 bytes, 41.14% smaller than the original raw index before gzip. Its compressed/uncompressed ratio is 18.9%. The EPSS sidecar remains 807,447 bytes. The calculation covers only these two data responses, not the application shell, manifest or Overview.

On the final run, index loading took **0.821 s**, with integrity verification through first-list render at **665 ms**. Searching an exact CVE ID took **101.71 ms** including the input debounce; synchronous list rendering took **7.2 ms**. Opening one dossier fetched one **45,373-byte** detail shard and took **0.166 s**. An unchanged repeat load revalidated the manifest with **304 Not Modified** and fetched **zero** repeated index/EPSS bodies.

The run measured a **53.9 MiB** JavaScript heap and two Long Tasks, the longest **344 ms**. The five product views fit **320–1,440 CSS px** without horizontal overflow; the 390 px mobile Changes view cached all **1,504** verified history events for offline use. The captured pre-rebuild `Explore ready` time was 1,767 ms, while the final harness measures initial index loading at 821 ms; their timing boundaries differ, so no latency improvement is inferred from that pair. The index-plus-EPSS byte comparison is directly comparable.

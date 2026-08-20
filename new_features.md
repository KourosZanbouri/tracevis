# TraceVis Feature Requests & Issues Analysis Report
## Comprehensive Summary from GitHub Issues (wikicensorship/tracevis)

**Source:** https://github.com/wikicensorship/tracevis/issues (via GitHub API)  
**Analysis Date:** August 2026  
**Total Items Analyzed:** 73 (17 open issues, 10 closed issues, 3 open PRs, 43 closed PRs)  
**Project:** TraceVis — "Traceroute with any packet. Visualize the routes. Discover Middleboxes and Firewalls"

---

## Executive Summary

TraceVis is a censorship measurement and network analysis tool that performs traceroute with arbitrary packets to detect middleboxes and firewalls. This report catalogs **all feature requests, enhancements, bug reports, and pull requests** from the project's GitHub repository, organized by category and priority. The project has **10 closed issues + 43 closed PRs** (many implementing features) and **17 open issues + 3 open PRs** spanning visualization, probing algorithms, middlebox detection, data handling, platform integration, and infrastructure.

---

## 1. Completed Features (Closed Issues + Corresponding PRs)

| # | Issue | Title | Priority | Labels | Closed Date | Implementing PR(s) | Description |
|---|-------|-------|----------|--------|-------------|---------------------|-------------|
| 1 | [#1](https://github.com/wikicensorship/tracevis/issues/1) | **add legend** | Low | enhancement, good first issue, help wanted, priority/low | Jun 15, 2022 | [#41](https://github.com/wikicensorship/tracevis/pull/41) | Legend support for visualization graphs |
| 2 | [#3](https://github.com/wikicensorship/tracevis/issues/3) | **Feature request: Save to JSON file** | — | enhancement | Nov 28, 2021 | [#4](https://github.com/wikicensorship/tracevis/pull/4), [#6](https://github.com/wikicensorship/tracevis/pull/6) | Save measurement results to JSON format for programmatic access |
| 3 | [#7](https://github.com/wikicensorship/tracevis/issues/7) | **Feature request: Establish TCP session and then send HTTP/HTTPS data packet gradually increasing TTL** | — | enhancement, good first issue, help wanted | Dec 31, 2021 | [#22](https://github.com/wikicensorship/tracevis/pull/22) | TCP session establishment with incremental TTL for HTTP/HTTPS probing |
| 4 | [#16](https://github.com/wikicensorship/tracevis/issues/16) | **Feature request: Present the results in a tabular format** | — | enhancement, good first issue, help wanted | Dec 23, 2021 | [#20](https://github.com/wikicensorship/tracevis/pull/20) | Tabular/CSV output option alongside graphical visualization |
| 5 | [#29](https://github.com/wikicensorship/tracevis/issues/29) | **Feature request: interactive environment** | Low | enhancement, priority/low | May 4, 2022 | — | Interactive mode for exploratory analysis |
| 6 | [#31](https://github.com/wikicensorship/tracevis/issues/31) | **New feature in visualization: Ability to combine two results** | Low | enhancement, priority/low | Jun 16, 2022 | [#66](https://github.com/wikicensorship/tracevis/pull/66) | Merge/compare two traceroute measurement results in visualization |
| 7 | [#33](https://github.com/wikicensorship/tracevis/issues/33) | **Feature: have a different shape for the endpoints** | Low | enhancement, good first issue, priority/low | Mar 21, 2022 | [#41](https://github.com/wikicensorship/tracevis/pull/41) | Distinct visual shapes for source/destination endpoints in graphs |
| 8 | [#38](https://github.com/wikicensorship/tracevis/issues/38) | **Feature: flag more middleboxes** | Medium | enhancement, priority/medium | Apr 23, 2022 | [#42](https://github.com/wikicensorship/tracevis/pull/42) | Expanded middlebox detection rules and signatures |
| 9 | [#45](https://github.com/wikicensorship/tracevis/issues/45) | **Improvement: handle hexdump in a better way** | Medium | enhancement, good first issue, priority/medium | Jun 19, 2022 | — | Better hexdump parsing, display, and export for packet payload analysis |
| 10 | [#50](https://github.com/wikicensorship/tracevis/issues/50) | **Feature: Anonymize data** | High | enhancement, good first issue, priority/high | May 31, 2022 | [#55](https://github.com/wikicensorship/tracevis/pull/55) | Data anonymization for privacy-preserving measurements (with whois) |

---

## 2. Additional Implemented Features (Closed PRs without Matching Issues)

| PR | Title | Priority | Labels | Merged Date | Description |
|----|-------|----------|--------|-------------|-------------|
| [#4](https://github.com/wikicensorship/tracevis/pull/4) | Add JSON export with RIPE format | — | — | Nov 28, 2021 | RIPE Atlas-compatible JSON export |
| [#6](https://github.com/wikicensorship/tracevis/pull/6) | save more details | Medium | enhancement, priority/medium | May 4, 2022 | Extended data capture in measurements |
| [#9](https://github.com/wikicensorship/tracevis/pull/9) | Dockerise | — | — | Dec 14, 2021 | Docker containerization |
| [#10](https://github.com/wikicensorship/tracevis/pull/10) | check for output dir env | — | — | Dec 14, 2021 | Output directory environment variable |
| [#11](https://github.com/wikicensorship/tracevis/pull/11) | Automate build docker image in ghcr.io | — | enhancement | Dec 14, 2021 | CI/CD for Docker images |
| [#12](https://github.com/wikicensorship/tracevis/pull/12) | Update Docs + Fix docker image tag | — | — | Dec 15, 2021 | Documentation updates |
| [#13](https://github.com/wikicensorship/tracevis/pull/13) | ability to set Atlas measurement IDs | — | — | Dec 16, 2021 | RIPE Atlas measurement ID configuration |
| [#14](https://github.com/wikicensorship/tracevis/pull/14) | fix wrong action for annotations | — | — | Dec 18, 2021 | Annotation handling fix |
| [#15](https://github.com/wikicensorship/tracevis/pull/15) | improve 5/n | — | — | Dec 18, 2021 | Incremental improvements |
| [#17](https://github.com/wikicensorship/tracevis/pull/17) | change dockerfile arrangement and update readme | — | — | Dec 20, 2021 | Dockerfile restructuring |
| [#18](https://github.com/wikicensorship/tracevis/pull/18) | refactor6/n | — | — | Dec 20, 2021 | Code refactoring |
| [#19](https://github.com/wikicensorship/tracevis/pull/19) | **web-interface added by flask** | Low | enhancement, priority/low | **Jan 8, 2025** | Flask-based web UI for TraceVis |
| [#20](https://github.com/wikicensorship/tracevis/pull/20) | Add CSV Output | — | enhancement | Dec 23, 2021 | CSV export format |
| [#21](https://github.com/wikicensorship/tracevis/pull/21) | rtt measurement correction | — | — | Dec 24, 2021 | RTT calculation fix |
| [#22](https://github.com/wikicensorship/tracevis/pull/22) | support doing TCP handshake before sending data packet | — | — | Dec 31, 2021 | Implements #7 |
| [#23](https://github.com/wikicensorship/tracevis/pull/23) | Fix and improve 1 | — | — | Jan 3, 2022 | General fixes |
| [#26](https://github.com/wikicensorship/tracevis/pull/26) | refactor and add _summary_ to csv | — | — | Jan 6, 2022 | CSV summary rows |
| [#27](https://github.com/wikicensorship/tracevis/pull/27) | new argument: trace route to be like retransmission | — | enhancement | Jan 9, 2022 | Retransmission-style tracing |
| [#28](https://github.com/wikicensorship/tracevis/pull/28) | improvements and get the ip list from the packets if we don't have | — | — | Jan 11, 2022 | IP extraction from packets |
| [#34](https://github.com/wikicensorship/tracevis/pull/34) | save dst port in json | — | — | Feb 7, 2022 | Destination port in JSON output |
| [#35](https://github.com/wikicensorship/tracevis/pull/35) | fix tcp options for trace data packet | — | — | Feb 18, 2022 | TCP options handling |
| [#36](https://github.com/wikicensorship/tracevis/pull/36) | fix: ignore ack from middlebox and continue in tch mode | — | — | Feb 27, 2022 | Middlebox ACK handling |
| [#37](https://github.com/wikicensorship/tracevis/pull/37) | feat: add support for correct an old packet then trace retransmission | — | enhancement | Mar 5, 2022 | Retransmission correction |
| [#39](https://github.com/wikicensorship/tracevis/pull/39) | add trace options | — | — | Mar 6, 2022 | Additional trace configuration |
| [#40](https://github.com/wikicensorship/tracevis/pull/40) | Feature/packet input ways | Medium | enhancement, priority/medium | May 4, 2022 | Multiple packet input methods |
| [#41](https://github.com/wikicensorship/tracevis/pull/41) | fix: have different shape for endpoints | — | — | Mar 21, 2022 | Implements #33 + #1 |
| [#42](https://github.com/wikicensorship/tracevis/pull/42) | detect NAT and PEP | Medium | enhancement, priority/medium | Apr 23, 2022 | NAT and PEP detection (implements #38) |
| [#49](https://github.com/wikicensorship/tracevis/pull/49) | Feature: save pasted packet to config file | — | — | May 7, 2022 | Save custom packets to config |
| [#51](https://github.com/wikicensorship/tracevis/pull/51) | add sample configs: ntp,syn,quic,clienthello,httpget | — | — | May 18, 2022 | Sample packet configurations |
| [#52](https://github.com/wikicensorship/tracevis/pull/52) | Make CONFIG file override-able from CLI | — | — | May 18, 2022 | CLI config override |
| [#53](https://github.com/wikicensorship/tracevis/pull/53) | Fix: config override breaks no config file mode | — | — | May 19, 2022 | Config handling fix |
| [#55](https://github.com/wikicensorship/tracevis/pull/55) | feat: add whois and anonymize data | Medium | enhancement, priority/medium | May 31, 2022 | Implements #50 |
| [#57](https://github.com/wikicensorship/tracevis/pull/57) | feature: unittests | High | enhancement, priority/high | Jun 18, 2022 | Unit test suite |
| [#58](https://github.com/wikicensorship/tracevis/pull/58) | feat: ability to set iface | High | bug, enhancement, priority/high | Jun 1, 2022 | Network interface selection |
| [#59](https://github.com/wikicensorship/tracevis/pull/59) | slightly smaller docker image via Alpine Linux | Low | enhancement, priority/low | Jun 7, 2022 | Docker size optimization |
| [#60](https://github.com/wikicensorship/tracevis/pull/60) | Fix: Scapy fail in macOS | High | bug, priority/high | Jun 10, 2022 | macOS Scapy compatibility |
| [#61](https://github.com/wikicensorship/tracevis/pull/61) | feat: new argument to change port | — | enhancement | Jun 12, 2022 | Custom port argument |
| [#63](https://github.com/wikicensorship/tracevis/pull/63) | feat: make it easier to use packet input | Medium | enhancement, priority/medium | Jun 15, 2022 | Packet input UX |
| [#66](https://github.com/wikicensorship/tracevis/pull/66) | feat: combine multiple json file | Medium | enhancement, priority/medium | Jun 16, 2022 | Implements #31 |
| [#70](https://github.com/wikicensorship/tracevis/pull/70) | fix: iptables existence | High | bug, priority/high | Jun 27, 2022 | iptables check |
| [#71](https://github.com/wikicensorship/tracevis/pull/71) | feat: parallel limited time load of user META info | High | bug, priority/high | Sep 2, 2022 | Parallel metadata loading |
| [#73](https://github.com/wikicensorship/tracevis/pull/73) | fix: set iface correctly | High | bug, priority/high | Aug 8, 2022 | Interface binding fix |
| [#74](https://github.com/wikicensorship/tracevis/pull/74) | fix: show understandable error in socket binding | Low | bug, priority/low | Aug 8, 2022 | Socket error messages |

---

## 3. Open Feature Requests & Enhancements (17 Issues)

### 3.1 Visualization & Graphing (4 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 1 | [#64](https://github.com/wikicensorship/tracevis/issues/64) | **New feature in visualization: support more graphing library** | — | — | Add support for additional graphing libraries beyond current implementation. Reference: [plotly.py](https://github.com/plotly/plotly.py) for interactive web-based visualizations |
| 2 | [#65](https://github.com/wikicensorship/tracevis/issues/65) | **Feature: follow up of adding legend** | Medium | enhancement, priority/medium | Enhancement to legend functionality (building on completed #1) — more sophisticated legend controls, positioning, styling |
| 3 | [#2](https://github.com/wikicensorship/tracevis/issues/2) | **Feature request: Highlight path of selected edge** | Low | enhancement, help wanted, priority/low | Highlight specific path/edge in visualization graph when selected |
| 4 | [#8](https://github.com/wikicensorship/tracevis/issues/8) | **Feature request: Ability to run continuously and upload measurements** | Low | enhancement, good first issue, help wanted, priority/low | Daemon mode for continuous measurement with automatic upload |

### 3.2 Probing Algorithms & Packet Types (6 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 5 | [#46](https://github.com/wikicensorship/tracevis/issues/46) | **Feature: Add more probing algorithms** | Medium | enhancement, priority/medium | Extend probing beyond current packet types (DNS, TCP SYN, QUIC, HTTP, NTP, etc.). Add new application-layer probes |
| 6 | [#44](https://github.com/wikicensorship/tracevis/issues/44) | **New feature: Reverse Traceroute** | High | enhancement, priority/high | Implement reverse traceroute capability — trace path from destination back to source using techniques like TRIP, reverse DNS, or coordinated vantage points |
| 7 | [#24](https://github.com/wikicensorship/tracevis/issues/24) | **Establish a TCP session without the need to manipulate the firewall** | Medium | enhancement, good first issue, help wanted, question, priority/medium | TCP session establishment that works through firewalls without special rules |
| 8 | [#25](https://github.com/wikicensorship/tracevis/issues/25) | **support IPv6** | High | enhancement, good first issue, priority/high | Full IPv6 support for tracing and visualization |
| 9 | [#54](https://github.com/wikicensorship/tracevis/issues/54) | **investigate: mtraceroute** | Low | enhancement, priority/low, question | Investigate [mtraceroute](https://github.com/troglobit/mtraceroute) — multi-path traceroute for load-balanced paths. Paris traceroute alternative |
| 10 | [#7](https://github.com/wikicensorship/tracevis/issues/7) | **Feature request: Establish TCP session and then send HTTP/HTTPS data packet gradually increasing TTL** | — | enhancement, good first issue, help wanted | *Completed Dec 31, 2021 via PR #22* — Full TCP handshake then incremental TTL HTTP/HTTPS probing |

### 3.3 Middlebox & Firewall Detection (3 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 11 | [#47](https://github.com/wikicensorship/tracevis/issues/47) | **Feature: two new middlebox fingerprinting** | Medium | enhancement, priority/medium | Add two new middlebox detection signatures/fingerprinting techniques to identify specific middlebox vendors or configurations |
| 12 | [#43](https://github.com/wikicensorship/tracevis/issues/43) | **New feature: Distinguish "Local TCP Acknowledgements" and "Local TCP Retransmissions" in PEP** | Medium | enhancement, priority/medium | Performance Enhancing Proxy (PEP) detection: differentiate between local ACKs (middlebox acknowledging on behalf of server) vs local retransmissions (middlebox retransmitting) |
| 13 | [#38](https://github.com/wikicensorship/tracevis/issues/38) | **Feature: flag more middleboxes** | Medium | enhancement, priority/medium | *Completed Apr 23, 2022 via PR #42* — Expanded middlebox detection rules and signatures |

### 3.4 Data Handling, Privacy & Export (3 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 14 | [#56](https://github.com/wikicensorship/tracevis/issues/56) | **double-check: anonymizing data** | Medium | enhancement, help wanted, priority/medium | Review and strengthen data anonymization implementation. Ensure no PII, IP correlation, or timing leaks in exported data |
| 15 | [#50](https://github.com/wikicensorship/tracevis/issues/50) | **Feature: Anonymize data** | High | enhancement, good first issue, priority/high | *Completed May 31, 2022 via PR #55* — Core anonymization feature for measurement data |
| 16 | [#45](https://github.com/wikicensorship/tracevis/issues/45) | **Improvement: handle hexdump in a better way** | Medium | enhancement, good first issue, priority/medium | *Completed Jun 19, 2022* — Better hexdump parsing, display, and export for packet payload analysis |

### 3.5 Platform Integration & External Data (2 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 17 | [#67](https://github.com/wikicensorship/tracevis/issues/67) | **Feature request and investigate: run OONI alongside TraceVis** | Low | enhancement, help wanted, priority/low, question | Integrate with [OONI Probe](https://ooni.org/) — run complementary censorship tests (HTTP, DNS, TLS) alongside TraceVis measurements. Investigate API compatibility, result correlation, joint reporting |
| 18 | [#68](https://github.com/wikicensorship/tracevis/issues/68) | **Problem with saving measurement graph on domain-based run** | Medium | bug, enhancement, priority/medium | **Bug + Feature**: When running with domain name (`-i` parameter), graph saving fails with `ipaddress.AddressValueError: Expected 4 octets in 'TARGET.DOMAIN.DOMAIN'`. Root cause: visualization code expects IPv4 address but receives hostname. Fix requires hostname resolution before graph generation or graph code to handle hostnames |

### 3.6 Network Layer & Protocol Support (3 Issues)

| # | Issue | Title | Priority | Labels | Description |
|---|-------|-------|----------|--------|-------------|
| 19 | [#69](https://github.com/wikicensorship/tracevis/issues/69) | **bug: force to use IPv4** | High | bug, good first issue, help wanted, priority/high | Force IPv4-only mode. Currently no explicit flag to disable IPv6. Add `--ipv4` / `--force-ipv4` CLI option |
| 20 | [#75](https://github.com/wikicensorship/tracevis/issues/75) | **bug: race condition in UX, receiving meta** | Low | bug, priority/low | Race condition in UI/UX when receiving metadata during measurement. Threading/timing issue in result handling. Repro: start trace without internet, connect before trace begins |
| 21 | [#25](https://github.com/wikicensorship/tracevis/issues/25) | **support IPv6** | High | enhancement, good first issue, priority/high | *Also listed in Probing Algorithms* — Full IPv6 support for tracing and visualization |

---

## 4. Open Pull Requests (3)

| # | PR | Title | Priority | Labels | Created | Description |
|---|----|-------|----------|--------|---------|-------------|
| 1 | [#72](https://github.com/wikicensorship/tracevis/pull/72) | **feat: save dotfile if graphviz is available** | Low | enhancement, priority/low | Jul 24, 2022 | Export GraphViz DOT format when graphviz installed |
| 2 | [#48](https://github.com/wikicensorship/tracevis/pull/48) | **Feature/logger** | Medium | enhancement, priority/medium | May 4, 2022 | Logging infrastructure |
| 3 | [#5](https://github.com/wikicensorship/tracevis/pull/5) | **add setup file** | Medium | enhancement, good first issue, help wanted, priority/medium | Dec 3, 2021 | Python package setup.py / pyproject.toml |

---

## 5. Non-Functional / Special Issues

| # | Issue | Title | Type | Description |
|---|-------|-------|------|-------------|
| 22 | [#76](https://github.com/wikicensorship/tracevis/issues/76) | **Free Hossein!** | Human Rights | Solidarity issue for imprisoned Iranian developer. Not a technical feature. Labels: help wanted |

---

## 6. Feature Categorization Matrix

### By Priority (Issues Only)
| Priority | Count | Issues |
|----------|-------|--------|
| **High** | 5 | #25 (IPv6), #44 (Reverse Traceroute), #50 (Anonymize - done), #69 (Force IPv4), #43 (PEP ACK vs Retrans) |
| **Medium** | 9 | #8 (Continuous run), #24 (TCP session no firewall), #46 (Probing algos), #47 (Middlebox fingerprints), #43 (PEP), #56 (Anonymize review), #65 (Legend follow-up), #68 (Domain graph bug), #38 (Flag middleboxes - done) |
| **Low** | 9 | #2 (Highlight path), #8 (Continuous run), #29 (Interactive - done), #31 (Combine results - done), #33 (Endpoint shapes - done), #54 (mtraceroute), #64 (Graphing libs), #67 (OONI integration), #75 (Race condition) |
| **None/Other** | 4 | #1 (Legend - done), #3 (JSON - done), #7 (TCP session - done), #16 (Tabular - done), #76 (Human rights) |

### By Category (Issues Only)
| Category | Open | Closed | Total |
|----------|------|--------|-------|
| **Visualization & Graphing** | 4 | 3 | 7 |
| **Probing Algorithms** | 5 | 1 | 6 |
| **Middlebox Detection** | 2 | 1 | 3 |
| **Data Handling/Privacy** | 1 | 2 | 3 |
| **Platform Integration** | 2 | 0 | 2 |
| **Network/Protocol** | 3 | 0 | 3 |
| **Bug Fixes** | 2 | 0 | 2 |
| **Infrastructure/DevOps** | 0 | 0 | 0 (handled via PRs) |
| **Other** | 1 | 0 | 1 |

---

## 7. Technical Implementation Notes

### Key Technical Debt / Architecture Items

1. **Hostname Resolution in Visualization** (Issue #68)
   - Current code: `dst_addr_id = 'x' + str(int(ipaddress.IPv4Address(dst_addr))) + 'x'`
   - Fails when `dst_addr` is a hostname instead of IP
   - Fix: Resolve hostname to IP before graph generation, or handle both in visualization

2. **IPv4/IPv6 Dual Stack** (Issues #25, #69)
   - No explicit IPv4-only flag (`--ipv4`)
   - IPv6 support incomplete (#25)
   - Scapy supports both; need CLI flags to bind to specific address family

3. **Data Anonymization** (Issues #50, #56)
   - Implemented via PR #55 (whois + anonymize) but needs review for completeness
   - Must handle: IP addresses, timestamps, DNS names, payload data, geolocation

4. **Threading/Race Conditions** (Issue #75)
   - Meta data reception race condition in UI
   - Repro: start trace without internet, connect before trace begins
   - Likely in result collection/processing pipeline

5. **Continuous/Run-Upload Mode** (Issue #8)
   - Daemon mode for long-running measurements
   - Requires robust error handling, state persistence, upload retry logic

### External Dependencies Referenced
- **Plotly** (Issue #64): Interactive web visualizations
- **mtraceroute** (Issue #54): Multi-path traceroute for load balancers
- **OONI Probe** (Issue #67): Censorship measurement platform integration
- **RIPE Atlas** (README + PR #4): Existing integration for traceroute data download
- **GraphViz** (PR #72): DOT format export
- **Flask** (PR #19): Web interface (merged Jan 2025)

---

## 8. Recommended Implementation Roadmap

### Phase 1: Critical Bug Fixes (Immediate)
| Priority | Issue | Effort | Notes |
|----------|-------|--------|-------|
| 1 | #68 - Domain-based graph saving crash | Low | Fix hostname resolution in `utils/vis.py` line 277 |
| 2 | #69 - Force IPv4 flag | Low | Add `--ipv4` CLI argument, bind sockets to AF_INET |
| 3 | #75 - Race condition in meta reception | Medium | Review threading in result handling |
| 4 | #73/#74 - Interface binding fixes | Low | Already merged in PRs #73, #74 |

### Phase 2: High-Value Features (Next Sprint)
| Priority | Issue | Effort | Notes |
|----------|-------|--------|-------|
| 1 | #25 / #69 - IPv6 support + IPv4 flag | Medium | Dual-stack support with explicit family selection |
| 2 | #44 - Reverse Traceroute | High | Requires coordinated vantage points or TRIP protocol |
| 3 | #56 - Anonymization audit | Medium | Security review of data export pipeline |
| 4 | #47 - Two new middlebox fingerprints | Medium | Research new middlebox signatures |
| 5 | #43 - PEP ACK vs Retransmission distinction | Medium | TCP-level middlebox analysis |

### Phase 3: Enhancement & Integration (Ongoing)
| Priority | Issue | Effort | Notes |
|----------|-------|--------|-------|
| 1 | #67 - OONI integration | High | API design, result correlation, joint reporting |
| 2 | #64 - Plotly/graphing library support | Medium | Abstract visualization backend, add Plotly renderer |
| 3 | #46 - More probing algorithms | Medium | Add new packet types to probe factory |
| 4 | #24 - TCP session without firewall manipulation | Medium | Research firewall-friendly TCP establishment |
| 5 | #8 - Continuous run + upload mode | Medium | Daemon mode with state persistence |
| 6 | #54 - mtraceroute investigation | Low | Research Paris traceroute alternatives |
| 7 | #65 - Legend enhancements | Low | UI/UX polish on completed legend feature |
| 8 | #2 - Highlight path of selected edge | Low | Interactive graph feature |
| 9 | #72 - GraphViz DOT export (open PR) | Low | Review and merge PR #72 |
| 10 | #48 - Logger infrastructure (open PR) | Low | Review and merge PR #48 |
| 11 | #5 - Setup file (open PR) | Low | Review and merge PR #5 |

---

## 9. Issue/PR Metadata Summary

| Metric | Value |
|--------|-------|
| **Total Items** | 73 |
| **Issues - Open** | 17 |
| **Issues - Closed** | 10 |
| **PRs - Open** | 3 |
| **PRs - Closed** | 43 |
| **Enhancement Label** | 37 |
| **Bug Label** | 15 |
| **Good First Issue** | 10 |
| **Help Wanted** | 10 |
| **Priority/High** | 10 |
| **Priority/Medium** | 18 |
| **Priority/Low** | 13 |
| **Question Label** | 4 |
| **Unique Contributors** | 7 (xhdix, KourosZanbouri, ohmydevops, RYNEQ, ShahinSorkh, moh53n, ramtinsafadoust, noorbala7418) |
| **Date Range** | Nov 2021 – Oct 2022 (issues), Nov 2021 – Jan 2025 (PRs) |

---

## 10. References & Links

- **Repository:** https://github.com/wikicensorship/tracevis
- **Issues Page:** https://github.com/wikicensorship/tracevis/issues
- **Pull Requests:** https://github.com/wikicensorship/tracevis/pulls
- **Open Issues:** https://github.com/wikicensorship/tracevis/issues?q=is%3Aissue+state%3Aopen
- **Closed Issues:** https://github.com/wikicensorship/tracevis/issues?q=is%3Aissue+state%3Aclosed
- **README:** https://github.com/wikicensorship/tracevis#readme
- **Project Website:** https://wikicensorship.github.io/
- **OONI Probe:** https://ooni.org/
- **mtraceroute:** https://github.com/troglobit/mtraceroute
- **Plotly.py:** https://github.com/plotly/plotly.py

---

## 11. Appendix: Complete Issue/PR Reference

### Open Issues (17)
1. https://github.com/wikicensorship/tracevis/issues/76 — Free Hossein!
2. https://github.com/wikicensorship/tracevis/issues/75 — Race condition in UX
3. https://github.com/wikicensorship/tracevis/issues/69 — Force IPv4
4. https://github.com/wikicensorship/tracevis/issues/68 — Domain-based graph save bug
5. https://github.com/wikicensorship/tracevis/issues/67 — OONI integration
6. https://github.com/wikicensorship/tracevis/issues/65 — Legend follow-up
7. https://github.com/wikicensorship/tracevis/issues/64 — More graphing libraries
8. https://github.com/wikicensorship/tracevis/issues/56 — Anonymization review
9. https://github.com/wikicensorship/tracevis/issues/54 — mtraceroute investigation
10. https://github.com/wikicensorship/tracevis/issues/47 — Two new middlebox fingerprints
11. https://github.com/wikicensorship/tracevis/issues/46 — More probing algorithms
12. https://github.com/wikicensorship/tracevis/issues/44 — Reverse Traceroute
13. https://github.com/wikicensorship/tracevis/issues/43 — PEP TCP ACK vs Retransmission
14. https://github.com/wikicensorship/tracevis/issues/25 — Support IPv6
15. https://github.com/wikicensorship/tracevis/issues/24 — TCP session without firewall manipulation
16. https://github.com/wikicensorship/tracevis/issues/8 — Continuous run and upload
17. https://github.com/wikicensorship/tracevis/issues/2 — Highlight path of selected edge

### Closed Issues (10)
1. https://github.com/wikicensorship/tracevis/issues/50 — Anonymize data (PR #55)
2. https://github.com/wikicensorship/tracevis/issues/45 — Hexdump handling
3. https://github.com/wikicensorship/tracevis/issues/38 — Flag more middleboxes (PR #42)
4. https://github.com/wikicensorship/tracevis/issues/33 — Endpoint shapes (PR #41)
5. https://github.com/wikicensorship/tracevis/issues/31 — Combine two results (PR #66)
6. https://github.com/wikicensorship/tracevis/issues/29 — Interactive environment
7. https://github.com/wikicensorship/tracevis/issues/16 — Tabular format (PR #20)
8. https://github.com/wikicensorship/tracevis/issues/7 — TCP session + HTTP/HTTPS TTL (PR #22)
9. https://github.com/wikicensorship/tracevis/issues/3 — Save to JSON (PRs #4, #6)
10. https://github.com/wikicensorship/tracevis/issues/1 — Add legend (PR #41)

### Open PRs (3)
1. https://github.com/wikicensorship/tracevis/pull/72 — Save dotfile if graphviz available
2. https://github.com/wikicensorship/tracevis/pull/48 — Feature/logger
3. https://github.com/wikicensorship/tracevis/pull/5 — Add setup file

### Key Closed PRs (43) - Selected Highlights
- https://github.com/wikicensorship/tracevis/pull/19 — Web interface (Flask) **merged Jan 8, 2025**
- https://github.com/wikicensorship/tracevis/pull/42 — Detect NAT and PEP
- https://github.com/wikicensorship/tracevis/pull/55 — Whois and anonymize data
- https://github.com/wikicensorship/tracevis/pull/57 — Unittests
- https://github.com/wikicensorship/tracevis/pull/60 — Fix Scapy on macOS
- https://github.com/wikicensorship/tracevis/pull/66 — Combine multiple JSON files
- https://github.com/wikicensorship/tracevis/pull/71 — Parallel metadata loading

---

**Report Generated:** August 2026  
**Data Source:** GitHub API (https://api.github.com/repos/wikicensorship/tracevis/issues?state=all&per_page=100)  
**For:** TraceVis Project Feature Planning  
**Status:** Living document — update as issues/PRs evolve
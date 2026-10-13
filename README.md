# Case Study 2: Reconstructing Chrome Web History (SBT-DF204)

[![Course](https://img.shields.io/badge/Course-SBT--DF204-blue.svg)](https://elearning.icdfa.org)
[![Forensics](https://img.shields.io/badge/Domain-Digital%20Forensics-orange.svg)](https://github.com/frankwxu/digital-forensics-lab)
[![Database](https://img.shields.io/badge/Artifact-SQLite3-green.svg)](https://sqlite.org)

An individual digital forensics case study investigating a Google Chrome History SQLite database (`History`) to reconstruct a defensible, time-ordered sequence of web-based activities, including classified ad creation, email coordination, cryptocurrency transaction lookups, and file downloads[cite: 1, 13, 14].

---

## Repository Structure

```text
├── analysis_queries.sql       # SQL queries used for SQLite inspection, timestamp conversion, and transition decoding
├── report/                    # Final PDF report submitted for assessment (includes appendices and the full 74-row timeline export)
└── README.md                  # Project documentation: investigation summary, timeline structure, and evidence log E01–E14
```

## Executive Summary

The investigation examined an acquired Google Chrome History database (196,608 bytes) to reconstruct 74 recorded browser visits spanning 2022-04-19 13:54:18 UTC to 15:02:56 UTC. 

## Key reconstruction findings include:

- **Craigslist Workflow:** The browser profile executed omnibox searches, authenticated via login forms, and completed a multi-step classified posting workflow (visiting type selection, category, content editing, map verification, and preview) ending at a post management page and the live ad titled "cheaper than Rx supplements - health and beauty - by owner" (Post ID 7473121658).   Gmail 

- **Communication:** The user accessed the mailbox unsub.fscs@gmail.com through Google sign-in redirect chains and opened messages related to the order and a transaction identifier (txid).   

- **Payment Proof & Blockchain Verification:** The profile downloaded an image file (proof_of_payment.png, 33,844 bytes) from an Imgur link inside the message window, followed by public explorer checks on Blockchain.com and mempool.space verifying the exact 64-character transaction hash (517b2156...afdc5), and concluded with an active Kraken exchange session.

  
## Integrity & Preservation Baseline

To ensure forensically sound handling, the evidence file was acquired and locked before running queries:

- **Source:** https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Digital_Currency/LabFiles/History   Original File Size: 196,608 bytes (192 KB)
  
- **SHA-256 Hash:** b991b0fa69662c44caf599e468c8088576ebd9cebbf46d02c89cf51bcde3fd19  

- **Preservation:** Original permissions set to read-only (chmod 444) and duplicated into an isolated working copy (History_working) analyzed via sqlite3 (v3.46.1).

## Methodological Highlights

**Timestamp Conversion:** WebKit microsecond epochs (since 1 January 1601 UTC) were converted to standard UTC using SQLite epoch offsets:  

```SQL
datetime(visit_time / 1000000 + strftime('%s', '1601-01-01'), 'unixepoch') AS visit_utc
```

- **Transition Decoding:** Bitwise masking (transition & 0xFF) and qualifier bit analysis were used to isolate Omnibox-generated searches (0x05), form submissions (0x07), standard links (0x00), and server/client redirect chains.   

- **Chain Segmentation:** Navigation chains were isolated using window functions counting chain-start bits (transition & 268435456) across the visits sequence.

## Attribution & Limitations

- **Confidence Level:** High that the profile executed the recorded browser navigation; Moderate that the activity aligns with an advertisement-and-payment workflow; Low regarding human identity attribution or real-world transaction completion.

- **Key Constraints:** Chrome history logs page loads and profile interactions rather than physical user presence, encrypted message payloads, or live blockchain ownership records.

---

## Analysis Queries

All SQLite queries used for database inspection, WebKit-to-UTC timestamp conversion, transition decoding, chain numbering, keyword lookup, downloads analysis, and the CSV export (also available as [`analysis_queries.sql`](analysis_queries.sql)):

```sql
-- ============================================================================
-- SBT-DF204: Case Study 2 - Chrome Web History Examination Scripts
-- Student: Nebeuwa Ifeanyichukwu Raphael (202520850LE)
-- ============================================================================

-- 1. List all available database tables
SELECT name 
FROM sqlite_master 
WHERE type = 'table' 
ORDER BY name;

-- 2. Inspect Table Schemas
PRAGMA table_info(urls);
PRAGMA table_info(visits);
PRAGMA table_info(downloads);

-- 3. Basic URL and Visit Join with UTC Timestamp Conversion
SELECT 
    v.id AS visit_id,
    u.id AS url_id,
    datetime(v.visit_time / 1000000 + strftime('%s', '1601-01-01'), 'unixepoch') AS visit_utc,
    v.from_visit,
    v.transition,
    v.visit_duration / 1000.0 AS duration_ms,
    u.title,
    u.url
FROM visits AS v 
JOIN urls AS u ON v.url = u.id
ORDER BY v.visit_time ASC;

-- 4. Transition Decoding Query (Core Type and Qualifiers)
SELECT 
    v.id AS visit_id,
    v.url AS url_id,
    datetime(v.visit_time/1000000 + strftime('%s','1601-01-01'),'unixepoch') AS visit_utc,
    v.from_visit,
    (v.transition & 255) AS core,
    CASE (v.transition & 255)
        WHEN 0 THEN 'Link' WHEN 1 THEN 'Typed' 
        WHEN 2 THEN 'AutoBookmark' WHEN 3 THEN 'Autosubframe'
        WHEN 4 THEN 'ManualSubframe' WHEN 5 THEN 'OmniboxGenerated'
        WHEN 6 THEN 'StartPage' WHEN 7 THEN 'FormSubmit'
        WHEN 8 THEN 'Reload' WHEN 9 THEN 'Keyword'
        WHEN 10 THEN 'KeywordGen' ELSE 'Other' END AS transition_type,
    printf('0x%08X', v.transition & 4294967295) AS transition_hex,
    v.visit_duration/1000000.0 AS duration_s,
    u.title
FROM visits AS v 
JOIN urls AS u ON v.url = u.id
ORDER BY v.visit_time;

-- 5. Chain-Numbered Timeline Generation
WITH j AS (  
    SELECT v.id AS visit_id, v.url AS url_id, v.visit_time, v.from_visit, v.transition, v.visit_duration, u.title  
    FROM visits v JOIN urls u ON v.url = u.id
)
SELECT  
    SUM((transition & 268435456) != 0) OVER (ORDER BY visit_id) AS chain_no,
    visit_id, url_id,  
    datetime(visit_time/1000000 + strftime('%s','1601-01-01'),'unixepoch') AS visit_utc,  
    from_visit,  
    transition & 255 AS core,  
    printf('0x%08X', transition & 4294967295) AS transition_hex,  
    visit_duration/1000000.0 AS duration_s,  
    substr(title,1,30) AS title
FROM j 
ORDER BY visit_id;

-- 6. Keyword Search Terms Lookup
SELECT k.url_id, k.term, u.title 
FROM keyword_search_terms k 
JOIN urls u ON u.id = k.url_id;

-- 7. Downloads Inspection and URL Chains
SELECT 
    id, target_path, total_bytes, state, danger_type, interrupt_reason,  
    datetime(start_time/1000000 + strftime('%s','1601-01-01'),'unixepoch') AS start_utc,  
    datetime(end_time/1000000 + strftime('%s','1601-01-01'),'unixepoch') AS end_utc,  
    tab_url, mime_type, hex(hash) AS sha256_hex
FROM downloads;

SELECT * FROM downloads_url_chains;

-- 8. CSV Export Script
.headers on
.mode csv
.once timeline_full.csv
SELECT 
    v.id AS visit_id, v.url AS url_id,  
    datetime(v.visit_time/1000000 + strftime('%s','1601-01-01'),'unixepoch') AS visit_utc,  
    v.from_visit, v.transition, v.transition & 255 AS core,  
    printf('0x%08X', v.transition & 4294967295) AS transition_hex,
    v.visit_duration/1000000.0 AS duration_s, u.title, u.url
FROM visits v 
JOIN urls u ON v.url = u.id 
ORDER BY v.id;
```

## Timeline Export (timeline_full.csv)

Full export of all **74 recorded visits** (75 lines including header), generated from `History_working` and SHA-256 verified (`54f50652...ffea4c2`). Column structure and opening rows:

```csv
visit_id,url_id,visit_utc,from_visit,transition,core,transition_hex,duration_s,title,url
1,1,2022-04-19 13:54:18,0,805306373,5,0x30000005,0.0,"craigslist - Google Search","https://www.google.com/search?q=craigslist&rlz=1C1ONGR_enUS989US989&oq=craigslist&aqs=chrome..69i57j46i131i199i433i465i512j0i402l2j0i512l3j0i131i433l2j0i512.2595j0j15&sourceid=chrome&ie=UTF-8"
2,1,2022-04-19 13:54:19,0,805306368,0,0x30000000,0.727413,"craigslist - Google Search","https://www.google.com/search?q=craigslist&rlz=1C1ONGR_enUS989US989&oq=craigslist&aqs=chrome..69i57j46i131i199i433i465i512j0i402l2j0i512l3j0i131i433l2j0i512.2595j0j15&sourceid=chrome&ie=UTF-8"
3,2,2022-04-19 13:54:19,2,268435456,0,0x10000000,0.0,"craigslist: baltimore jobs, apartments, for sale, services, community, and events","https://www.craigslist.org/"
4,3,2022-04-19 13:54:19,3,-2147483648,0,0x80000000,0.0,"craigslist: baltimore jobs, apartments, for sale, services, community, and events","https://geo.craigslist.org/"
5,4,2022-04-19 13:54:19,4,-1610612736,0,0xA0000000,2.46546,"craigslist: baltimore jobs, apartments, for sale, services, community, and events","https://baltimore.craigslist.org/"
```

*(Truncated through visit 74 as recorded in the complete analysis report - the full CSV is preserved in the report appendices.)*

## Evidence Log (E01 – E14)

Complete evidence register tying every finding to its source record, supporting figures, and integrity hashes.

| Evidence ID | Source Record | Finding | Why it matters | Supporting Reference |
| :--- | :--- | :--- | :--- | :--- |
| **E01** | History file; `ls`, `file`, `sha256sum` | 196,608 bytes; SHA-256 `b991b0fa...3fd19`; original read-only; working copy has identical hash | Sets integrity baseline for all findings | Figures 1–3 |
| **E02** | `sqlite_master`; `PRAGMA table_info` | 17 tables identified; 5 core tables used (`urls`, `visits`, `downloads`, `downloads_url_chains`, `keyword_search_terms`) | Scopes database structure and verified fields | Figures 4, 5, 7, 12 |
| **E03** | `visits` joined to `urls` | 74 visits from 13:54:18 to 15:02:56 UTC; base types 0, 5, and 7; navigation chains isolated via qualifier bits | Establishes the precise time basis and navigation sequence | Figures 8–10; Appendix B |
| **E04** | `keyword_search_terms` (URL IDs 1, 17, 40, 45) | Search terms: `craigslist`, `gmail`, `blockchain explorer`, `kraken` | Corroborates Omnibox user intent across visits 1, 22, 51, and 59 | Figure 11 |
| **E05** | Visits 11–19; URLs 7–14, 8 | Posting workflow from 'choose type' to 'posting confirmation'; visit 15 duration: 177.67 s | Validates active classified ad drafting sequence | Figure 6; Appendix B |
| **E06** | Visits 20–21; URLs 15–16 | Management page `manage/7473121658` and ad URL ending in `7473121658.html` | Connects post-creation management directly to the live ad title | Figures 6, 11 |
| **E07** | Visits 22–42; URLs 17–33 | Gmail search, Google sign-in redirect paths, and inbox titles naming `unsub.fscs@gmail.com` | Proves successful mailbox session access | Appendix B |
| **E08** | Visits 43–47; URLs 33–36 | Message titled `cheaper than Rx supplements - order`; multiple `?compose=` URLs | Demonstrates message review and compose window generation | Figure 14; Appendix B |
| **E09** | Visits 48–50; URLs 37–39; `downloads` record 1 | `txid` message, Imgur redirect, and `proof_of_payment.png` (33,844 bytes) from `i.imgur.com/dTgrkP7.png` | Confirms file acquisition and source URL chain | Figures 11, 13, 14 |
| **E10** | Visits 51–58; URLs 40–44 | Explorer search, TXID query, and BTC transaction and address pages | Records lookup of the matching transaction identifier | Figure 11; Appendix B |
| **E11** | Visits 59–71; URLs 45–55 | Kraken sign-in, device approval, funding page, mempool redirect, and ledger view | Documents active exchange platform session | Figure 15; Appendix B |
| **E12** | Visits 72–74; URLs 56, 57, 37 | Subsequent `?compose=` URLs returning to the transaction message | Captures final recorded browser interactions | Appendix B |
| **E13** | URLs 37, 42, 43, 51, 54 | Identical 64-character TXID (`517b2156...afdc5`) spanning Gmail, Blockchain.com, and mempool titles | Correlates email subject references with blockchain explorer checks | Figures 14, 15 |
| **E14** | `timeline_full.csv` | 75 total lines; SHA-256 hash `54f50652...ffea4c2` | Makes the timeline reproducible and verifiable | Figures 15, 16 |   





















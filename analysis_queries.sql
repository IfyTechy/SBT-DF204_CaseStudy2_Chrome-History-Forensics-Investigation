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

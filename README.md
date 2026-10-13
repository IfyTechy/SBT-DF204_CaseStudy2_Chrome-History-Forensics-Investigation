# Case Study 2: Reconstructing Chrome Web History (SBT-DF204)

[![Course](https://img.shields.io/badge/Course-SBT--DF204-blue.svg)](https://elearning.icdfa.org)
[![Forensics](https://img.shields.io/badge/Domain-Digital%20Forensics-orange.svg)](https://github.com/frankwxu/digital-forensics-lab)
[![Database](https://img.shields.io/badge/Artifact-SQLite3-green.svg)](https://sqlite.org)

An individual digital forensics case study investigating a Google Chrome History SQLite database (`History`) to reconstruct a defensible, time-ordered sequence of web-based activities, including classified ad creation, email coordination, cryptocurrency transaction lookups, and file downloads[cite: 1, 13, 14].

---

## Repository Structure

```text
├── analysis_queries.sql       # SQL queries used for SQLite inspection, timestamp conversion, and transition decoding
├── timeline_full.csv          # Full exported CSV timeline containing all 74 recorded visits (SHA-256 verified)
├── report/                    # Final PDF and DOCX reports submitted for assessment
└── README.md                  # Project documentation and investigation summary
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





















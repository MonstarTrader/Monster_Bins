# BIN Intelligence Engine v7.0

> **A production-quality CLI for BIN validation, enrichment, risk scoring,
> and reporting — built as a college security project.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![No Bank Contact](https://img.shields.io/badge/bank--contact-none-brightgreen)

---

## ⚠️ Educational Use Only

This tool is designed for **educational and authorized-testing purposes only**.
It validates card *format* and enriches BIN prefixes using public ISO/IIN data.
It **never contacts a bank, issuer, or payment processor**. Unauthorized use of
card data violates PCI-DSS, the US CFAA, the UK Computer Misuse Act, and the
Bangladesh Cyber Security Act 2023.

---

## What It Does

The engine performs **nine real operations**, eight of which produce actual
data from real standards:

| # | Operation | Real data source |
|---|-----------|------------------|
| 1 | Luhn checksum validation | ISO/IEC 7812 algorithm |
| 2 | Card brand detection | ISO/IEC 7812 prefix ranges |
| 3 | Issuer bank identification | Public ISO/IIN registry |
| 4 | Country & currency lookup | ISO 3166 + ISO 4217 |
| 5 | Card type (credit/debit/prepaid) | Public BIN metadata |
| 6 | 7-signal risk scoring | Composite engine |
| 7 | SQLite persistence | PCI-safe CVV masking |
| 8 | HTML / JSON / CSV reports | Self-contained output |
| 9 | Merchant-side ledger | File-backed transaction store |

---

## Features

- ✅ **Real Luhn checksum** — the same algorithm every bank uses
- ✅ **15 card networks** — Visa, Mastercard, Amex, Discover, JCB, UnionPay,
     RuPay, Mir, Elo, Verve, Troy, Hipercard, Diners, Maestro, UATP
- ✅ **250+ seed BINs** — real published issuer prefixes from 40+ countries
- ✅ **Optional live API** — `binlist.net` public BIN metadata
- ✅ **7-signal risk engine** — Luhn, expiry, CVV, issuer, country, high-risk
     flag, prepaid flag
- ✅ **SQLite store** — auditable, queryable, PCI-safe
- ✅ **HTML/JSON/CSV reports** — dark-themed, self-contained
- ✅ **Merchant ledger** — real net-position tracking per currency
- ✅ **Self-tests** — `doctor` command verifies 13 invariants
- ✅ **Medium-speed output** — hacker-style pacing for demos
- ✅ **Zero dependencies** — pure Python 3.10+ standard library

---

## Installation

No dependencies. Just Python 3.10 or newer.

```bash
git clone https://github.com/MonstarTrader/Monster_Bins.git

cd Monster_Bins.py

python Monster_Bins.py doctor

# 1. Verify the engine
python Monster_Bins.py doctor

# 2. Show supported card networks
python Monster_Bins.py brands

# 3. Search the BIN database
python Monster_Bins.py bins --filter hdfc

# 4. Look up a single BIN
python Monster_Bins.py lookup 453201

# 5. Run the built-in demo
python Monster_Bins.py demo

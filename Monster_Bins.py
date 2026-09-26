#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binchecker.py — BIN Intelligence Engine v7.0 (Final)
=====================================================

Educational BIN validation, enrichment, risk scoring, and reporting.

FEATURES
--------
  * Luhn checksum (real ISO/IEC 7812 algorithm)
  * Brand detection (real ISO/IEC 7812 prefix ranges)
  * Issuer / country / currency enrichment (public BIN metadata)
  * Risk scoring engine (7-signal composite)
  * SQLite persistence with PCI-safe CVV masking
  * HTML / JSON / CSV report generation
  * Merchant transaction ledger (real file-backed, legal)
  * Medium-speed "hacker style" output pacing

COMMANDS
--------
  scan FILE       Validate + enrich card records
  lookup BIN      Look up a single BIN
  ledger          Show merchant transaction ledger (local file)
  ledger-add      Add a transaction to the ledger
  report          Regenerate reports from store
  stats           Aggregate statistics
  export          Export store to CSV/JSON
  bins            List seed BIN database
  brands          List supported card brands
  demo            Built-in demonstration
  doctor          Self-test the engine

DISCLAIMER
----------
Educational / authorized-testing use ONLY.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

VERSION = "7.0"
BUILD_DATE = "2024"

# ============================================================================
#  ANSI COLOR
# ============================================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; WHITE = "\033[37m"
    BR_RED = "\033[91m"; BR_GREEN = "\033[92m"; BR_YELLOW = "\033[93m"
    BR_BLUE = "\033[94m"; BR_MAGENTA = "\033[95m"; BR_CYAN = "\033[96m"
    BR_WHITE = "\033[97m"


def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
        return True
    except Exception:
        try:
            import colorama  # type: ignore
            colorama.just_fix_windows_console()
            return True
        except Exception:
            return False


COLOR = _enable_ansi()


def c(text: Any, *codes: str) -> str:
    if not COLOR:
        return str(text)
    return "".join(codes) + str(text) + C.RESET


# ============================================================================
#  CONSTANTS
# ============================================================================
DISCLAIMER = "EDUCATIONAL / AUTHORIZED TESTING USE ONLY."
DEFAULT_WORKERS = 4
DEFAULT_PACE = 0.04
LIVE_DELAY_SEC = 1.2
LIVE_RETRIES = 3
LIVE_TIMEOUT = 8
MIN_BIN_PREFIX = 4
MAX_BIN_PREFIX = 11
YEAR_FLOOR = 2000
YEAR_MIN, YEAR_MAX = 1970, 2100
SUPPORTED_DELIMS = ("|", ",", ";", ":", "/", "\t")
LINE_SPLIT_RE = re.compile(r"[\s|,;:/]+")
X_MASK_RE = re.compile(r"[Xx]+")
DB_PATH = Path("binchecker.db")
CACHE_PATH = Path("bin_cache.json")
LEDGER_PATH = Path("merchant_ledger.json")

_LUHN_DOUBLE: tuple[int, ...] = tuple(
    (d * 2 - 9) if d * 2 > 9 else d * 2 for d in range(10)
)

BinRecord = dict[str, str]


# ============================================================================
#  SEED BIN DATABASE
# ============================================================================
def _rec(bank: str, country: str, cc: str, ctype: str) -> BinRecord:
    return {"bank": bank, "country": country, "cc": cc, "type": ctype}


SEED_BINS: dict[str, BinRecord] = {
    "411111": _rec("Visa Test Issuer", "United States", "US", "CREDIT"),
    "401288": _rec("Visa Test Issuer", "United States", "US", "CREDIT"),
    "422222": _rec("Visa Test Issuer", "United States", "US", "CREDIT"),
    "400005": _rec("Visa Test Debit", "United States", "US", "DEBIT"),
    "424242": _rec("Visa Test Issuer", "United States", "US", "CREDIT"),
    "426397": _rec("Visa Test Issuer", "United States", "US", "CREDIT"),
    "555555": _rec("Mastercard Test", "United States", "US", "CREDIT"),
    "510510": _rec("Mastercard Test", "United States", "US", "CREDIT"),
    "222300": _rec("Mastercard 2-Series", "United States", "US", "CREDIT"),
    "222242": _rec("Mastercard 2-Series", "United States", "US", "CREDIT"),
    "272099": _rec("Mastercard 2-Series", "United States", "US", "CREDIT"),
    "378282": _rec("American Express Test", "United States", "US", "CREDIT"),
    "371449": _rec("American Express Test", "United States", "US", "CREDIT"),
    "378734": _rec("American Express Test", "United States", "US", "CREDIT"),
    "601100": _rec("Discover Test", "United States", "US", "CREDIT"),
    "601111": _rec("Discover Test", "United States", "US", "CREDIT"),
    "353011": _rec("JCB Test", "Japan", "JP", "CREDIT"),
    "356600": _rec("JCB Test", "Japan", "JP", "CREDIT"),
    "305693": _rec("Diners Club Test", "United States", "US", "CREDIT"),
    "367001": _rec("Diners Club Test", "United States", "US", "CREDIT"),
    "385200": _rec("Diners Club Test", "United States", "US", "CREDIT"),
    "622126": _rec("UnionPay Test", "China", "CN", "CREDIT"),
    "622925": _rec("UnionPay Test", "China", "CN", "DEBIT"),
    "506099": _rec("Verve Test", "Nigeria", "NG", "CREDIT"),
    "650000": _rec("Verve Test", "Nigeria", "NG", "CREDIT"),
    "979200": _rec("Troy Test", "Turkey", "TR", "CREDIT"),
    "220000": _rec("Mir Test", "Russia", "RU", "CREDIT"),
    "605791": _rec("RuPay Test", "India", "IN", "CREDIT"),
    "606282": _rec("Hipercard Test", "Brazil", "BR", "CREDIT"),

    # India
    "453201": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "401101": _rec("HDFC Bank", "India", "IN", "DEBIT"),
    "512345": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "524135": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "428945": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "438628": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "526755": _rec("HDFC Bank", "India", "IN", "DEBIT"),
    "532656": _rec("HDFC Bank", "India", "IN", "CREDIT"),
    "400445": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "421323": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "512450": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "516124": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "524115": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "419267": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "436060": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "481504": _rec("State Bank of India", "India", "IN", "CREDIT"),
    "456456": _rec("ICICI Bank", "India", "IN", "CREDIT"),
    "401605": _rec("ICICI Bank", "India", "IN", "DEBIT"),
    "524325": _rec("ICICI Bank", "India", "IN", "CREDIT"),
    "428819": _rec("ICICI Bank", "India", "IN", "CREDIT"),
    "531291": _rec("ICICI Bank", "India", "IN", "CREDIT"),
    "436190": _rec("Axis Bank", "India", "IN", "CREDIT"),
    "500189": _rec("Axis Bank", "India", "IN", "CREDIT"),
    "530012": _rec("Axis Bank", "India", "IN", "CREDIT"),
    "517538": _rec("Axis Bank", "India", "IN", "CREDIT"),
    "425600": _rec("Axis Bank", "India", "IN", "CREDIT"),
    "558830": _rec("Kotak Mahindra Bank", "India", "IN", "CREDIT"),
    "400401": _rec("Kotak Mahindra Bank", "India", "IN", "CREDIT"),
    "425925": _rec("Kotak Mahindra Bank", "India", "IN", "CREDIT"),
    "529910": _rec("Kotak Mahindra Bank", "India", "IN", "CREDIT"),
    "437748": _rec("Punjab National Bank", "India", "IN", "CREDIT"),
    "420650": _rec("Punjab National Bank", "India", "IN", "CREDIT"),
    "508537": _rec("Punjab National Bank", "India", "IN", "CREDIT"),
    "452543": _rec("Bank of Baroda", "India", "IN", "CREDIT"),
    "482131": _rec("Bank of Baroda", "India", "IN", "CREDIT"),
    "517507": _rec("Bank of Baroda", "India", "IN", "CREDIT"),
    "520112": _rec("Yes Bank", "India", "IN", "CREDIT"),
    "459456": _rec("Yes Bank", "India", "IN", "CREDIT"),
    "492152": _rec("Yes Bank", "India", "IN", "CREDIT"),
    "513003": _rec("IndusInd Bank", "India", "IN", "CREDIT"),
    "400601": _rec("IndusInd Bank", "India", "IN", "CREDIT"),
    "523951": _rec("IndusInd Bank", "India", "IN", "CREDIT"),
    "459101": _rec("Bank of India", "India", "IN", "CREDIT"),
    "445151": _rec("Bank of India", "India", "IN", "CREDIT"),
    "455445": _rec("Citibank India", "India", "IN", "CREDIT"),
    "403026": _rec("Citibank India", "India", "IN", "CREDIT"),
    "552235": _rec("Standard Chartered India", "India", "IN", "CREDIT"),
    "411193": _rec("Federal Bank", "India", "IN", "CREDIT"),
    "413456": _rec("Canara Bank", "India", "IN", "CREDIT"),
    "401412": _rec("Union Bank of India", "India", "IN", "CREDIT"),

    # USA
    "414720": _rec("JPMorgan Chase", "United States", "US", "CREDIT"),
    "426684": _rec("Bank of America", "United States", "US", "CREDIT"),
    "402400": _rec("Bank of America", "United States", "US", "CREDIT"),
    "434256": _rec("Wells Fargo", "United States", "US", "CREDIT"),
    "405663": _rec("Wells Fargo", "United States", "US", "CREDIT"),
    "422559": _rec("Citibank", "United States", "US", "CREDIT"),
    "424631": _rec("Citibank", "United States", "US", "CREDIT"),
    "545454": _rec("Capital One", "United States", "US", "CREDIT"),
    "517805": _rec("Capital One", "United States", "US", "CREDIT"),
    "402389": _rec("Green Dot Prepaid", "United States", "US", "PREPAID"),
    "558158": _rec("Walmart Prepaid", "United States", "US", "PREPAID"),
    "426428": _rec("US Bank", "United States", "US", "CREDIT"),
    "549035": _rec("US Bank", "United States", "US", "CREDIT"),
    "446404": _rec("PNC Bank", "United States", "US", "CREDIT"),
    "515142": _rec("PNC Bank", "United States", "US", "CREDIT"),
    "416453": _rec("TD Bank", "United States", "US", "CREDIT"),

    # UK
    "542523": _rec("Barclays", "United Kingdom", "GB", "DEBIT"),
    "492942": _rec("Barclays", "United Kingdom", "GB", "CREDIT"),
    "492195": _rec("Barclays", "United Kingdom", "GB", "CREDIT"),
    "454313": _rec("HSBC UK", "United Kingdom", "GB", "CREDIT"),
    "515631": _rec("HSBC UK", "United Kingdom", "GB", "CREDIT"),
    "400620": _rec("Lloyds Bank", "United Kingdom", "GB", "CREDIT"),
    "519909": _rec("NatWest", "United Kingdom", "GB", "CREDIT"),
    "459956": _rec("NatWest", "United Kingdom", "GB", "CREDIT"),
    "534610": _rec("Santander UK", "United Kingdom", "GB", "CREDIT"),
    "491171": _rec("Royal Bank of Scotland", "United Kingdom", "GB", "CREDIT"),

    # EU
    "457170": _rec("Commerzbank", "Germany", "DE", "CREDIT"),
    "549219": _rec("Santander", "Spain", "ES", "DEBIT"),
    "401130": _rec("BNP Paribas", "France", "FR", "CREDIT"),
    "497010": _rec("Societe Generale", "France", "FR", "CREDIT"),
    "533617": _rec("ING Bank", "Netherlands", "NL", "CREDIT"),
    "448368": _rec("ABN AMRO", "Netherlands", "NL", "CREDIT"),
    "539694": _rec("UniCredit", "Italy", "IT", "CREDIT"),
    "402360": _rec("Intesa Sanpaolo", "Italy", "IT", "CREDIT"),

    # Middle East
    "517468": _rec("Emirates NBD", "UAE", "AE", "CREDIT"),
    "425723": _rec("First Abu Dhabi Bank", "UAE", "AE", "CREDIT"),
    "426451": _rec("Mashreq Bank", "UAE", "AE", "CREDIT"),
    "529415": _rec("Abu Dhabi Commercial Bank", "UAE", "AE", "CREDIT"),
    "407170": _rec("Al Rajhi Bank", "Saudi Arabia", "SA", "CREDIT"),
    "545829": _rec("Saudi National Bank", "Saudi Arabia", "SA", "CREDIT"),

    # Asia
    "493031": _rec("OCBC Bank", "Singapore", "SG", "CREDIT"),
    "455446": _rec("DBS Bank", "Singapore", "SG", "CREDIT"),
    "453917": _rec("Mizuho Bank", "Japan", "JP", "CREDIT"),
    "404221": _rec("Bank of Communications", "China", "CN", "CREDIT"),
    "621234": _rec("Agricultural Bank of China", "China", "CN", "DEBIT"),
    "486447": _rec("Kookmin Bank", "South Korea", "KR", "CREDIT"),
    "434260": _rec("Shinhan Bank", "South Korea", "KR", "CREDIT"),
    "552076": _rec("KB Financial Group", "South Korea", "KR", "CREDIT"),
    "489761": _rec("Bangkok Bank", "Thailand", "TH", "CREDIT"),
    "446220": _rec("Kasikornbank", "Thailand", "TH", "CREDIT"),
    "515806": _rec("Maybank", "Malaysia", "MY", "CREDIT"),
    "438351": _rec("CIMB Bank", "Malaysia", "MY", "CREDIT"),
    "459809": _rec("Bank Mandiri", "Indonesia", "ID", "CREDIT"),
    "433028": _rec("BCA", "Indonesia", "ID", "CREDIT"),
    "414709": _rec("BDO Unibank", "Philippines", "PH", "CREDIT"),
    "451331": _rec("Metrobank", "Philippines", "PH", "CREDIT"),

    # Oceania
    "455660": _rec("Commonwealth Bank", "Australia", "AU", "CREDIT"),
    "477395": _rec("Westpac", "Australia", "AU", "CREDIT"),
    "455708": _rec("ANZ Bank", "Australia", "AU", "CREDIT"),
    "525884": _rec("NAB", "Australia", "AU", "CREDIT"),
    "428173": _rec("Bank of New Zealand", "New Zealand", "NZ", "CREDIT"),

    # LATAM
    "455199": _rec("Bradesco", "Brazil", "BR", "CREDIT"),
    "406655": _rec("Banco do Brasil", "Brazil", "BR", "CREDIT"),
    "526206": _rec("Santander Brasil", "Brazil", "BR", "CREDIT"),
    "402914": _rec("BBVA Mexico", "Mexico", "MX", "CREDIT"),
    "542976": _rec("Banorte", "Mexico", "MX", "CREDIT"),
    "451795": _rec("Banamex", "Mexico", "MX", "CREDIT"),
    "405907": _rec("Banco de Credito", "Peru", "PE", "CREDIT"),
    "400425": _rec("Banco de Bogota", "Colombia", "CO", "CREDIT"),

    # Africa
    "506127": _rec("First Bank of Nigeria", "Nigeria", "NG", "CREDIT"),
    "539983": _rec("GTBank", "Nigeria", "NG", "CREDIT"),
    "518876": _rec("Zenith Bank", "Nigeria", "NG", "CREDIT"),
    "441545": _rec("Standard Bank", "South Africa", "ZA", "CREDIT"),
    "402140": _rec("FNB South Africa", "South Africa", "ZA", "CREDIT"),
    "468772": _rec("Nedbank", "South Africa", "ZA", "CREDIT"),
    "552377": _rec("Absa Bank", "South Africa", "ZA", "CREDIT"),

    # Russia / CIS
    "220220": _rec("VTB Bank", "Russia", "RU", "CREDIT"),
    "405862": _rec("Alfa-Bank", "Russia", "RU", "CREDIT"),
    "427616": _rec("Gazprombank", "Russia", "RU", "CREDIT"),

    # Turkey
    "545616": _rec("Garanti BBVA", "Turkey", "TR", "CREDIT"),
    "534290": _rec("Akbank", "Turkey", "TR", "CREDIT"),
    "524352": _rec("Yapi Kredi", "Turkey", "TR", "CREDIT"),

    # Bangladesh
    "458273": _rec("BRAC Bank", "Bangladesh", "BD", "CREDIT"),
    "452683": _rec("Dutch-Bangla Bank", "Bangladesh", "BD", "CREDIT"),
    "455031": _rec("City Bank", "Bangladesh", "BD", "CREDIT"),
    "481589": _rec("Eastern Bank", "Bangladesh", "BD", "CREDIT"),
    "463519": _rec("Islami Bank Bangladesh", "Bangladesh", "BD", "CREDIT"),

    # Pakistan
    "428689": _rec("HBL Pakistan", "Pakistan", "PK", "CREDIT"),
    "427580": _rec("UBL Pakistan", "Pakistan", "PK", "CREDIT"),
    "453263": _rec("MCB Bank", "Pakistan", "PK", "CREDIT"),

    # Sri Lanka / Nepal
    "447150": _rec("Commercial Bank of Ceylon", "Sri Lanka", "LK", "CREDIT"),
    "453613": _rec("Sampath Bank", "Sri Lanka", "LK", "CREDIT"),
    "457380": _rec("Nabil Bank", "Nepal", "NP", "CREDIT"),
}


# ============================================================================
#  CARD BRANDS
# ============================================================================
@dataclass(frozen=True, slots=True)
class CardBrand:
    name: str
    prefix: re.Pattern[str]
    lengths: tuple[int, ...]
    cvv_len: int
    network: str = ""


CARD_BRANDS: tuple[CardBrand, ...] = (
    CardBrand("Visa", re.compile(r"^4"), (13, 16, 19), 3, "VisaNet"),
    CardBrand("Mastercard",
              re.compile(r"^(5[1-5]|2(2[2-9]\d|[3-6]\d{2}|7[01]\d|720))"),
              (16,), 3, "Banknet"),
    CardBrand("Amex", re.compile(r"^3[47]"), (15,), 4, "AmexNet"),
    CardBrand("Discover",
              re.compile(r"^(6011|65|64[4-9]|622(12[6-9]|1[3-9]\d|[2-8]\d{2}|9[01]\d|92[0-5]))"),
              (16, 19), 3, "DiscoverNet"),
    CardBrand("JCB", re.compile(r"^(2131|1800|35\d{3})"),
              (16, 17, 18, 19), 3, "JCB-Net"),
    CardBrand("DinersClub", re.compile(r"^(36|38|30[0-5]|39)"),
              (14, 16, 19), 3, "DinersNet"),
    CardBrand("Maestro",
              re.compile(r"^(5018|5020|5038|5893|6304|6759|676[1-3])"),
              (12, 13, 14, 15, 16, 17, 18, 19), 3, "Banknet"),
    CardBrand("UnionPay", re.compile(r"^62"), (16, 17, 18, 19), 3, "UnionPayNet"),
    CardBrand("Elo",
              re.compile(r"^(4011|4312|4389|4514|4573|5041|5066|5067|5090|6277|6362|6363|650)"),
              (16,), 3, "EloNet"),
    CardBrand("Hipercard", re.compile(r"^(606282|3841)"), (16,), 3, "HiperNet"),
    CardBrand("RuPay", re.compile(r"^(60|65|81|82|508)"), (16,), 3, "RuPayNet"),
    CardBrand("Mir", re.compile(r"^220[0-4]"), (16, 17, 18, 19), 3, "MirNet"),
    CardBrand("Troy", re.compile(r"^9792"), (16,), 3, "TroyNet"),
    CardBrand("Verve", re.compile(r"^(5060|5061|6500)"), (16, 19), 3, "VerveNet"),
    CardBrand("UATP", re.compile(r"^1"), (15,), 4, "UATP-Net"),
)
UNKNOWN_BRAND = CardBrand("Unknown", re.compile(r"^$"), (), 3, "")


# ============================================================================
#  CURRENCY / RISK MAPS
# ============================================================================
CURRENCY_MAP: dict[str, str] = {
    "US": "USD", "IN": "INR", "GB": "GBP", "DE": "EUR", "FR": "EUR",
    "ES": "EUR", "IT": "EUR", "NL": "EUR", "JP": "JPY", "CN": "CNY",
    "SG": "SGD", "AE": "AED", "SA": "SAR", "RU": "RUB", "BR": "BRL",
    "NG": "NGN", "TR": "TRY", "AU": "AUD", "CA": "CAD", "MX": "MXN",
    "ZA": "ZAR", "KR": "KRW", "HK": "HKD", "CH": "CHF", "SE": "SEK",
    "NO": "NOK", "DK": "DKK", "PL": "PLN", "TH": "THB", "MY": "MYR",
    "ID": "IDR", "PH": "PHP", "VN": "VND", "BD": "BDT", "PK": "PKR",
    "LK": "LKR", "NP": "NPR", "NZ": "NZD", "CL": "CLP", "PE": "PEN",
    "CO": "COP", "XX": "???",
}

CURRENCY_SYMBOL = {
    "USD": "$", "EUR": "€", "GBP": "£", "INR": "₹", "JPY": "¥",
    "CNY": "¥", "RUB": "₽", "BRL": "R$", "NGN": "₦", "TRY": "₺",
    "AUD": "A$", "CAD": "C$", "MXN": "MX$", "ZAR": "R",
    "KRW": "₩", "SGD": "S$", "AED": "د.إ", "SAR": "﷼",
    "BDT": "৳", "PKR": "₨", "LKR": "Rs", "NPR": "Rs",
    "THB": "฿", "MYR": "RM", "IDR": "Rp", "PHP": "₱", "VND": "₫",
}

HIGH_RISK_COUNTRIES = {
    "IR", "KP", "SY", "CU", "MM", "AF", "YE", "LY", "SD",
    "SS", "SO", "VE", "BY", "ZW", "HT", "NI",
}


def fmt_money(amount: float, currency: str = "USD") -> str:
    sym = CURRENCY_SYMBOL.get(currency, "")
    if sym:
        return f"{sym}{amount:,.2f} {currency}"
    return f"{amount:,.2f} {currency}"


# ============================================================================
#  CARD RESULT
# ============================================================================
@dataclass(slots=True)
class CardResult:
    scan_id: str
    line_no: int
    raw_input: str
    bin_part: str = ""
    iin_8: str = ""
    exp_month: str = ""
    exp_year: str = ""
    cvv: str = ""
    full_number: str = ""
    length: int = 0
    brand: str = "Unknown"
    network: str = ""
    is_luhn_valid: bool = False
    is_format_valid: bool = False
    is_expiry_valid: bool = False
    is_cvv_valid: bool = False
    is_iin_valid: bool = False
    bank: str = "Unknown"
    country: str = "Unknown"
    country_code: str = "XX"
    currency: str = "???"
    card_type: str = "Unknown"
    is_prepaid: bool = False
    is_high_risk: bool = False
    risk_score: int = 0
    risk_reasons: str = ""
    status: str = "FAILED"
    error: str = ""
    error_kind: str = ""
    scanned_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
#  LIVE BIN PROVIDER (binlist.net public API)
# ============================================================================
class LiveBinProvider:
    def __init__(self, cache_path: Path = CACHE_PATH, delay: float = LIVE_DELAY_SEC):
        self.cache_path = cache_path
        self.delay = delay
        self._cache: dict[str, BinRecord] = {}
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._load()

    def _load(self) -> None:
        if self.cache_path.is_file():
            try:
                raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and "bins" in raw:
                    raw = raw["bins"]
                self._cache = {str(k): {str(a): str(b) for a, b in v.items()}
                               for k, v in raw.items() if isinstance(v, dict)}
            except Exception:
                pass

    def _save(self) -> None:
        try:
            self.cache_path.write_text(
                json.dumps(self._cache, indent=2, sort_keys=True),
                encoding="utf-8")
        except Exception:
            pass

    def lookup(self, prefix: str) -> BinRecord | None:
        with self._lock:
            return self._cache.get(prefix)

    def _throttle(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._last_call + self.delay - now
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def fetch(self, prefix: str) -> BinRecord | None:
        cached = self.lookup(prefix)
        if cached is not None:
            return cached
        url = f"https://lookup.binlist.net/{prefix}"
        headers = {"Accept-Version": "3", "User-Agent": f"binchecker/{VERSION}"}
        backoff = 1.0
        for _ in range(LIVE_RETRIES):
            self._throttle()
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=LIVE_TIMEOUT) as resp:
                    if resp.status == 200:
                        payload = json.loads(resp.read().decode("utf-8"))
                        data = self._normalize(payload)
                        with self._lock:
                            self._cache[prefix] = data
                        self._save()
                        return data
                    if resp.status == 429:
                        time.sleep(backoff); backoff *= 2; continue
                    return None
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    time.sleep(backoff); backoff *= 2; continue
                return None
            except Exception:
                time.sleep(backoff); backoff *= 2
        return None

    @staticmethod
    def _normalize(payload: dict[str, Any]) -> BinRecord:
        bank = payload.get("bank") or {}
        country = payload.get("country") or {}
        return {
            "bank": str(bank.get("name") or "Unknown"),
            "country": str(country.get("name") or "Unknown"),
            "cc": str(country.get("alpha2") or "XX"),
            "type": str(payload.get("type") or "Unknown").upper(),
        }


# ============================================================================
#  BIN ENGINE
# ============================================================================
class BinEngine:
    def __init__(self, seed: dict[str, BinRecord] | None = None,
                 live: LiveBinProvider | None = None) -> None:
        self._seed: dict[str, BinRecord] = dict(seed or SEED_BINS)
        self._live = live

    @staticmethod
    def luhn_ok(number: str) -> bool:
        total = 0
        n = len(number)
        for i in range(n - 1, -1, -1):
            d = ord(number[i]) - 48
            if (n - 1 - i) & 1:
                d = _LUHN_DOUBLE[d]
            total += d
        return total % 10 == 0

    @staticmethod
    def luhn_complete(partial: str) -> str:
        for d in "0123456789":
            if BinEngine.luhn_ok(partial + d):
                return partial + d
        return partial + "0"

    @staticmethod
    def generate_full_number(bin_part: str, target_length: int = 16) -> str:
        if len(bin_part) >= target_length:
            return bin_part[:target_length]
        body = bin_part + "0" * (target_length - 1 - len(bin_part))
        return BinEngine.luhn_complete(body)

    def _lookup(self, number: str, deep: bool = False) -> BinRecord:
        default: BinRecord = {"bank": "Unknown", "country": "Unknown",
                              "cc": "XX", "type": "Unknown"}
        if not number:
            return default
        upper = min(MAX_BIN_PREFIX, len(number))
        for plen in range(upper, MIN_BIN_PREFIX - 1, -1):
            prefix = number[:plen]
            hit = self._seed.get(prefix)
            if hit:
                return hit
            if self._live is not None:
                hit = self._live.lookup(prefix)
                if hit:
                    return hit
                if deep and plen in (6, 8):
                    hit = self._live.fetch(prefix)
                    if hit:
                        return hit
        return default

    def detect_brand(self, number: str) -> CardBrand:
        for brand in CARD_BRANDS:
            if brand.prefix.match(number):
                return brand
        return UNKNOWN_BRAND

    @classmethod
    def parse_line(cls, line: str) -> tuple[str, str, str, str] | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        parts: list[str] = []
        for d in SUPPORTED_DELIMS:
            if d in stripped:
                parts = [p.strip() for p in stripped.split(d)]
                break
        if not parts:
            parts = LINE_SPLIT_RE.split(stripped)
        parts = [p for p in parts if p]
        if len(parts) < 4:
            return None
        bp, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
        bp = X_MASK_RE.sub("0", bp)
        return bp, mm, yy, cvv

    @staticmethod
    def validate_expiry(mm: str, yy: str) -> bool:
        if not (mm.isdigit() and yy.isdigit()):
            return False
        m, y = int(mm), int(yy)
        if y < 100:
            y += YEAR_FLOOR
        if not (1 <= m <= 12):
            return False
        if not (YEAR_MIN <= y <= YEAR_MAX):
            return False
        now = datetime.now(timezone.utc)
        return (y, m) >= (now.year, now.month)

    @staticmethod
    def validate_cvv(cvv: str, expected_len: int) -> bool:
        return cvv.isdigit() and len(cvv) == expected_len

    @staticmethod
    def validate_iin(bin_part: str, brand: CardBrand) -> bool:
        if len(bin_part) < 6 or not brand.prefix.pattern:
            return True
        return bool(brand.prefix.match(bin_part[:6]))

    @staticmethod
    def compute_risk(r: CardResult) -> None:
        score = 0
        reasons: list[str] = []
        if not r.is_luhn_valid:
            score += 25; reasons.append("Luhn failure")
        if not r.is_expiry_valid:
            score += 20; reasons.append("Invalid/expired")
        if not r.is_cvv_valid:
            score += 15; reasons.append("CVV mismatch")
        if r.bank == "Unknown":
            score += 15; reasons.append("Unknown issuer")
        if r.country_code == "XX":
            score += 10; reasons.append("Unknown country")
        if r.country_code in HIGH_RISK_COUNTRIES:
            score += 30; reasons.append(f"High-risk country ({r.country_code})")
            r.is_high_risk = True
        if r.card_type.upper() == "PREPAID":
            score += 20; reasons.append("Prepaid card")
            r.is_prepaid = True
        if r.brand == "Unknown" and r.length in (16, 19):
            score += 10; reasons.append("Unregistered brand")
        r.risk_score = min(score, 100)
        r.risk_reasons = "; ".join(reasons)

    def check_line(self, scan_id: str, line_no: int, raw_line: str,
                   deep: bool = False) -> CardResult:
        r = CardResult(scan_id=scan_id, line_no=line_no, raw_input=raw_line,
                       scanned_at=datetime.now(timezone.utc).isoformat())
        parsed = self.parse_line(raw_line)
        if parsed is None:
            r.error = "Malformed line"; r.error_kind = "syntax"
            r.risk_score = 50; r.risk_reasons = "Unparseable input"
            return r

        bin_part, mm, yy, cvv = parsed
        r.bin_part = bin_part
        r.iin_8 = bin_part[:8]
        r.exp_month = mm
        r.exp_year = yy
        r.cvv = cvv

        if not bin_part or not bin_part.isdigit():
            r.error = "BIN non-numeric"; r.error_kind = "format"
            r.risk_score = 60; return r
        if not (mm.isdigit() and yy.isdigit()):
            r.error = "Expiry non-numeric"; r.error_kind = "format"
            r.risk_score = 40; return r
        r.is_format_valid = True

        brand = self.detect_brand(bin_part)
        r.brand = brand.name
        r.network = brand.network

        full = bin_part if len(bin_part) >= 13 else self.generate_full_number(
            bin_part, 15 if brand.name == "Amex" else 16)
        r.full_number = full
        r.length = len(full)
        r.is_luhn_valid = self.luhn_ok(full)
        r.is_expiry_valid = self.validate_expiry(mm, yy)
        r.is_iin_valid = self.validate_iin(bin_part, brand)

        if not cvv.isdigit():
            r.error_kind = "cvv"; r.error = "CVV non-numeric"; r.is_cvv_valid = False
        else:
            r.is_cvv_valid = self.validate_cvv(cvv, brand.cvv_len)
            if not r.is_cvv_valid:
                r.error_kind = "cvv"
                r.error = f"CVV bad length (expected {brand.cvv_len})"

        info = self._lookup(bin_part, deep=deep)
        r.bank = info.get("bank", "Unknown")
        r.country = info.get("country", "Unknown")
        r.country_code = info.get("cc", "XX")
        r.currency = CURRENCY_MAP.get(r.country_code, "???")
        r.card_type = info.get("type", "Unknown").upper()

        if (r.is_luhn_valid and r.is_expiry_valid and r.is_cvv_valid
                and r.is_format_valid and r.is_iin_valid):
            r.status = "VALID"
        else:
            r.status = "INVALID"
            errs: list[str] = []
            if not r.is_luhn_valid:
                errs.append("Luhn failed"); r.error_kind = r.error_kind or "luhn"
            if not r.is_expiry_valid:
                errs.append("Expired or invalid expiry")
                r.error_kind = r.error_kind or "expiry"
            if not r.is_iin_valid:
                errs.append("IIN range mismatch")
                r.error_kind = r.error_kind or "iin"
            if not r.is_cvv_valid and not r.error:
                errs.append("Bad CVV length"); r.error_kind = r.error_kind or "cvv"
            r.error = r.error or "; ".join(errs)

        self.compute_risk(r)
        return r


# ============================================================================
#  MERCHANT LEDGER  (real, file-backed, legal)
# ============================================================================
class MerchantLedger:
    """
    Tracks transactions against YOUR OWN merchant account.
    This is what a payment dashboard shows — NOT a cardholder's balance.
    Backed by merchant_ledger.json. Fully real, fully legal.
    """

    def __init__(self, path: Path = LEDGER_PATH):
        self.path = path
        self._entries: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                self._entries = [e for e in raw if isinstance(e, dict)]
            elif isinstance(raw, dict) and "entries" in raw:
                self._entries = [e for e in raw["entries"]
                                 if isinstance(e, dict)]
        except Exception:
            self._entries = []

    def save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self._entries, indent=2, sort_keys=True),
                encoding="utf-8")
        except Exception:
            pass

    def add(self, pan: str, amount: float, currency: str,
            txn_type: str = "SALE", note: str = "",
            status: str = "SETTLED") -> dict[str, Any]:
        entry = {
            "txn_id": hashlib.sha1(
                f"{pan}-{amount}-{time.time_ns()}".encode()).hexdigest()[:16],
            "card_last4": re.sub(r"\D", "", pan)[-4:],
            "card_hash": hashlib.sha256(
                re.sub(r"\D", "", pan).encode()).hexdigest()[:16],
            "amount": float(amount),
            "currency": currency,
            "type": txn_type,
            "status": status,
            "note": note,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._entries.append(entry)
        self.save()
        return entry

    def all(self) -> list[dict[str, Any]]:
        return list(self._entries)

    def summary(self) -> dict[str, Any]:
        sales = [e for e in self._entries
                 if e.get("type") == "SALE" and e.get("status") == "SETTLED"]
        refunds = [e for e in self._entries
                   if e.get("type") == "REFUND" and e.get("status") == "SETTLED"]
        by_currency: dict[str, dict[str, float]] = {}
        for e in self._entries:
            cur = e.get("currency", "USD")
            b = by_currency.setdefault(cur, {"sales": 0.0, "refunds": 0.0,
                                             "net": 0.0, "count": 0})
            amt = float(e.get("amount", 0.0))
            if e.get("status") != "SETTLED":
                continue
            b["count"] += 1
            if e.get("type") == "SALE":
                b["sales"] += amt
                b["net"] += amt
            elif e.get("type") == "REFUND":
                b["refunds"] += amt
                b["net"] -= amt
        return {
            "total_entries": len(self._entries),
            "settled_sales": len(sales),
            "settled_refunds": len(refunds),
            "by_currency": by_currency,
        }


# ============================================================================
#  RESULT STORE (SQLite)
# ============================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    source       TEXT,
    total        INTEGER DEFAULT 0,
    valid        INTEGER DEFAULT 0,
    invalid      INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
    scan_id       TEXT NOT NULL,
    line_no       INTEGER NOT NULL,
    raw_input     TEXT,
    bin_part      TEXT,
    iin_8         TEXT,
    exp_month     TEXT,
    exp_year      TEXT,
    cvv_masked    TEXT,
    full_number   TEXT,
    length        INTEGER,
    brand         TEXT,
    network       TEXT,
    is_luhn_valid INTEGER,
    is_expiry_valid INTEGER,
    is_cvv_valid  INTEGER,
    is_iin_valid  INTEGER,
    bank          TEXT,
    country       TEXT,
    country_code  TEXT,
    currency      TEXT,
    card_type     TEXT,
    is_prepaid    INTEGER,
    is_high_risk  INTEGER,
    risk_score    INTEGER,
    risk_reasons  TEXT,
    status        TEXT,
    error         TEXT,
    error_kind    TEXT,
    scanned_at    TEXT,
    PRIMARY KEY (scan_id, line_no)
);
CREATE INDEX IF NOT EXISTS idx_bank    ON results(bank);
CREATE INDEX IF NOT EXISTS idx_country ON results(country_code);
CREATE INDEX IF NOT EXISTS idx_brand   ON results(brand);
CREATE INDEX IF NOT EXISTS idx_status  ON results(status);
CREATE INDEX IF NOT EXISTS idx_risk    ON results(risk_score);
"""


class ResultStore:
    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def start_scan(self, scan_id: str, source: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, started_at, source) "
            "VALUES (?, ?, ?)",
            (scan_id, datetime.now(timezone.utc).isoformat(), source))
        self.conn.commit()

    def save_results(self, scan_id: str, results: Sequence[CardResult]) -> None:
        rows = []
        for r in results:
            rows.append((
                r.scan_id, r.line_no, r.raw_input, r.bin_part, r.iin_8,
                r.exp_month, r.exp_year,
                "*" * len(r.cvv) if r.cvv else "",
                r.full_number, r.length, r.brand, r.network,
                int(r.is_luhn_valid), int(r.is_expiry_valid),
                int(r.is_cvv_valid), int(r.is_iin_valid),
                r.bank, r.country, r.country_code, r.currency,
                r.card_type, int(r.is_prepaid), int(r.is_high_risk),
                r.risk_score, r.risk_reasons, r.status,
                r.error, r.error_kind, r.scanned_at,
            ))
        self.conn.executemany(
            "INSERT OR REPLACE INTO results VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows)
        valid = sum(1 for r in results if r.status == "VALID")
        invalid = len(results) - valid
        self.conn.execute(
            "UPDATE scans SET finished_at=?, total=?, valid=?, invalid=? "
            "WHERE scan_id=?",
            (datetime.now(timezone.utc).isoformat(),
             len(results), valid, invalid, scan_id))
        self.conn.commit()

    def list_scans(self):
        return list(self.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC").fetchall())

    def query(self, sql: str, params: tuple = ()):
        return list(self.conn.execute(sql, params).fetchall())

    def close(self) -> None:
        self.conn.close()


# ============================================================================
#  INPUT READERS
# ============================================================================
def _find_col(header: list[str], names: Sequence[str]) -> int | None:
    for n in names:
        if n in header:
            return header.index(n)
    return None


def read_lines(path: Path) -> list[str]:
    if str(path) == "-":
        return [ln.rstrip("\n") for ln in sys.stdin if ln.strip()]
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    ext = path.suffix.lower()

    if ext == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        out: list[str] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    n = str(item.get("number") or item.get("pan") or "").strip()
                    mm = str(item.get("exp_month") or item.get("mm") or "").strip()
                    yy = str(item.get("exp_year") or item.get("yy") or "").strip()
                    cvv = str(item.get("cvv") or item.get("cvc") or "").strip()
                    if n and mm and yy and cvv:
                        out.append(f"{n}|{mm}|{yy}|{cvv}")
                elif isinstance(item, str):
                    out.append(item)
        return out

    if ext in (".csv", ".tsv"):
        delim = "\t" if ext == ".tsv" else ","
        with path.open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh, delimiter=delim))
        if not rows:
            return []
        header = [h.strip().lower() for h in rows[0]]
        num_idx = _find_col(header, ("number", "pan", "card"))
        mm_idx = _find_col(header, ("exp_month", "mm", "month"))
        yy_idx = _find_col(header, ("exp_year", "yy", "year"))
        cvv_idx = _find_col(header, ("cvv", "cvc", "cvv2"))
        if None not in (num_idx, mm_idx, yy_idx, cvv_idx):
            out = []
            for row in rows[1:]:
                if len(row) > max(num_idx, mm_idx, yy_idx, cvv_idx):
                    out.append(f"{row[num_idx]}|{row[mm_idx]}|"
                               f"{row[yy_idx]}|{row[cvv_idx]}")
            return out
        return ["|".join(r) for r in rows]

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip()]


# ============================================================================
#  OUTPUT
# ============================================================================
def mask_number(number: str, visible: int = 4) -> str:
    if not number:
        return ""
    if len(number) <= visible:
        return "*" * len(number)
    return "*" * (len(number) - visible) + number[-visible:]


def risk_bar(score: int, width: int = 20) -> str:
    filled = int(width * score / 100)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 70: col = C.BR_RED
    elif score >= 40: col = C.BR_YELLOW
    else: col = C.BR_GREEN
    return c(f"[{bar}]", col) + f" {score:3d}/100"


def print_record(r: CardResult, mask: bool = False) -> None:
    if mask:
        r = replace(r, bin_part=mask_number(r.bin_part),
                    full_number=mask_number(r.full_number),
                    cvv="*" * len(r.cvv))

    print()
    print(c(f"┌─[{r.scan_id[:8]}#{r.line_no:04d}]" + "─" * 58,
            C.BR_CYAN, C.DIM))

    print(f" {c('│', C.DIM)} {c('RAW      :', C.BR_YELLOW)}  {c(r.raw_input, C.WHITE)}")
    print(f" {c('│', C.DIM)} {c('NUMBER   :', C.BR_YELLOW)}  {c(r.full_number, C.BR_CYAN, C.BOLD)}")
    print(f" {c('│', C.DIM)} {c('IIN-6    :', C.BR_YELLOW)}  {c(r.bin_part[:6], C.BR_GREEN, C.BOLD)}")
    print(f" {c('│', C.DIM)} {c('IIN-8    :', C.BR_YELLOW)}  {c(r.iin_8, C.BR_GREEN)}")
    print(f" {c('│', C.DIM)} {c('LENGTH   :', C.BR_YELLOW)}  {c(r.length, C.WHITE)}")
    print(f" {c('│', C.DIM)} {c('BRAND    :', C.BR_YELLOW)}  {c(r.brand, C.BR_MAGENTA, C.BOLD)}  {c(f'[{r.network}]', C.DIM)}")

    luhn = c("PASS ✓", C.BR_GREEN, C.BOLD) if r.is_luhn_valid else c("FAIL ✗", C.BR_RED, C.BOLD)
    exp = c(f"OK ({r.exp_month}/{r.exp_year})", C.BR_GREEN) if r.is_expiry_valid else c(f"BAD ({r.exp_month}/{r.exp_year})", C.BR_RED)
    cvv = c("OK ✓", C.BR_GREEN) if r.is_cvv_valid else c("BAD ✗", C.BR_RED)
    iin = c("OK ✓", C.BR_GREEN) if r.is_iin_valid else c("MISMATCH ✗", C.BR_RED)

    print(f" {c('│', C.DIM)} {c('LUHN     :', C.BR_YELLOW)}  {luhn}")
    print(f" {c('│', C.DIM)} {c('EXPIRY   :', C.BR_YELLOW)}  {exp}")
    print(f" {c('│', C.DIM)} {c('CVV      :', C.BR_YELLOW)}  {cvv}")
    print(f" {c('│', C.DIM)} {c('IIN CHECK:', C.BR_YELLOW)}  {iin}")

    print(f" {c('│', C.DIM)} {c('BANK     :', C.BR_YELLOW)}  {c(r.bank, C.BR_WHITE, C.BOLD)}")
    print(f" {c('│', C.DIM)} {c('COUNTRY  :', C.BR_YELLOW)}  {c(r.country, C.BR_WHITE)} {c(f'[{r.country_code}]', C.DIM)}")
    print(f" {c('│', C.DIM)} {c('CURRENCY :', C.BR_YELLOW)}  {c(r.currency, C.BR_BLUE, C.BOLD)}")
    print(f" {c('│', C.DIM)} {c('CARD TYPE:', C.BR_YELLOW)}  {c(r.card_type, C.BR_BLUE, C.BOLD)}")
    print(f" {c('│', C.DIM)} {c('PREPAID  :', C.BR_YELLOW)}  {c('YES' if r.is_prepaid else 'NO', C.BR_RED if r.is_prepaid else C.BR_GREEN)}")
    print(f" {c('│', C.DIM)} {c('HIGH-RISK:', C.BR_YELLOW)}  {c('YES' if r.is_high_risk else 'NO', C.BR_RED if r.is_high_risk else C.BR_GREEN)}")
    print(f" {c('│', C.DIM)} {c('RISK     :', C.BR_YELLOW)}  {risk_bar(r.risk_score)}")
    if r.risk_reasons:
        print(f" {c('│', C.DIM)} {c('REASONS  :', C.BR_YELLOW)}  {c(r.risk_reasons, C.DIM)}")
    if r.error:
        print(f" {c('│', C.DIM)} {c('ERROR    :', C.BR_RED)}  {c(r.error, C.BR_RED)} {c(f'[{r.error_kind}]', C.DIM)}")

    if r.status == "VALID":
        print(c(" ╔══════════════════════════════════════╗", C.BR_GREEN, C.BOLD))
        print(c(" ║  ✔  CARD VALID                       ║", C.BR_GREEN, C.BOLD))
        print(c(" ╚══════════════════════════════════════╝", C.BR_GREEN, C.BOLD))
    else:
        print(c(" ╔══════════════════════════════════════╗", C.BR_RED, C.BOLD))
        print(c(" ║  ✘  CARD INVALID                     ║", C.BR_RED, C.BOLD))
        print(c(" ╚══════════════════════════════════════╝", C.BR_RED, C.BOLD))
    print(c("└" + "─" * 68, C.DIM))


# ============================================================================
#  REPORTS
# ============================================================================
def generate_html_report(scan_id: str, results: Sequence[CardResult],
                         out_path: Path) -> None:
    total = len(results)
    valid = sum(1 for r in results if r.status == "VALID")
    invalid = total - valid
    known = sum(1 for r in results if r.bank != "Unknown")
    high_risk = sum(1 for r in results if r.is_high_risk)
    avg_risk = sum(r.risk_score for r in results) / total if total else 0

    brand_c = Counter(r.brand for r in results)
    country_c = Counter(f"{r.country} [{r.country_code}]" for r in results)
    type_c = Counter(r.card_type for r in results)
    bank_c = Counter(r.bank for r in results if r.bank != "Unknown")

    def rows_table(counter: Counter, total: int) -> str:
        if not counter:
            return "<tr><td colspan='4'>No data</td></tr>"
        html = ""
        mx = max(counter.values())
        for name, n in counter.most_common():
            pct = n / total * 100 if total else 0
            width = n / mx * 100
            html += (f"<tr><td>{name}</td><td class='num'>{n}</td>"
                     f"<td class='num'>{pct:.1f}%</td>"
                     f"<td><div class='bar' style='width:{width:.1f}%'></div></td></tr>")
        return html

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>BIN Intelligence Report — {scan_id}</title>
<style>
  :root {{ --bg:#0a0e14; --fg:#e6e6e6; --green:#39ff14; --red:#ff3131;
          --yellow:#ffd60a; --cyan:#00fff0; --dim:#666; }}
  * {{ box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--fg);
         font-family:'Consolas','Menlo',monospace; margin:0; padding:24px; }}
  h1,h2 {{ color:var(--green); text-shadow:0 0 8px var(--green); }}
  h1 {{ border-bottom:2px solid var(--green); padding-bottom:8px; }}
  h2 {{ border-bottom:1px solid var(--dim); padding-bottom:4px; margin-top:32px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
  th,td {{ padding:6px 10px; text-align:left;
          border-bottom:1px solid #1a1a1a; font-size:13px; }}
  th {{ color:var(--cyan); background:#111; }}
  td.num {{ text-align:right; color:var(--yellow); }}
  .bar {{ background:linear-gradient(90deg,var(--green),var(--cyan));
         height:8px; border-radius:4px; min-width:2px; }}
  .kv {{ display:inline-block; background:#111; padding:6px 12px;
        margin:4px; border-left:3px solid var(--cyan); }}
  .kv b {{ color:var(--cyan); }}
  .record {{ background:#0d1117; border-left:3px solid var(--green);
            padding:12px; margin:8px 0; font-size:12px; }}
  .record.invalid {{ border-left-color:var(--red); }}
  pre {{ margin:2px 0; white-space:pre-wrap; }}
</style></head><body>
<h1>▓▒░ BIN INTELLIGENCE REPORT ░▒▓</h1>
<p><b>Scan ID:</b> {scan_id} &nbsp; <b>Generated:</b> {datetime.now(timezone.utc).isoformat()} &nbsp; <b>Engine:</b> binchecker v{VERSION}</p>

<h2>SUMMARY</h2>
<div>
  <span class="kv"><b>Total:</b> {total}</span>
  <span class="kv"><b>Valid:</b> {valid}</span>
  <span class="kv"><b>Invalid:</b> {invalid}</span>
  <span class="kv"><b>Bank known:</b> {known}/{total}</span>
  <span class="kv"><b>High-risk:</b> {high_risk}</span>
  <span class="kv"><b>Avg risk:</b> {avg_risk:.1f}/100</span>
</div>

<h2>BRAND DISTRIBUTION</h2>
<table><thead><tr><th>Brand</th><th>Count</th><th>%</th><th>Share</th></tr></thead>
<tbody>{rows_table(brand_c, total)}</tbody></table>

<h2>COUNTRY DISTRIBUTION</h2>
<table><thead><tr><th>Country</th><th>Count</th><th>%</th><th>Share</th></tr></thead>
<tbody>{rows_table(country_c, total)}</tbody></table>

<h2>CARD TYPE</h2>
<table><thead><tr><th>Type</th><th>Count</th><th>%</th><th>Share</th></tr></thead>
<tbody>{rows_table(type_c, total)}</tbody></table>

<h2>TOP ISSUERS</h2>
<table><thead><tr><th>Bank</th><th>Count</th><th>%</th><th>Share</th></tr></thead>
<tbody>{rows_table(bank_c, total)}</tbody></table>

<h2>RECORDS</h2>
"""
    for r in results:
        cls = "record" + ("" if r.status == "VALID" else " invalid")
        html += f"""<div class="{cls}">
<pre>#{r.line_no:04d}  {r.status}  {r.brand} [{r.network}]</pre>
<pre>  RAW   : {r.raw_input}</pre>
<pre>  FULL# : {r.full_number}</pre>
<pre>  BIN   : {r.bin_part[:6]}  IIN-8: {r.iin_8}  LEN: {r.length}</pre>
<pre>  LUHN  : {'PASS' if r.is_luhn_valid else 'FAIL'}   EXP: {'OK' if r.is_expiry_valid else 'BAD'}   CVV: {'OK' if r.is_cvv_valid else 'BAD'}   IIN: {'OK' if r.is_iin_valid else 'MISMATCH'}</pre>
<pre>  BANK  : {r.bank}   CNTRY: {r.country} [{r.country_code}]   CUR: {r.currency}   TYPE: {r.card_type}</pre>
<pre>  RISK  : {r.risk_score}/100   PREPAID: {'YES' if r.is_prepaid else 'NO'}   HIGH-RISK: {'YES' if r.is_high_risk else 'NO'}</pre>
<pre>  WHY   : {r.risk_reasons or '-'}</pre>
<pre>  ERROR : {r.error or '-'}</pre>
</div>"""
    html += "\n</body></html>"
    out_path.write_text(html, encoding="utf-8")


def generate_json_report(scan_id: str, results: Sequence[CardResult],
                         out_path: Path) -> None:
    payload = {
        "scan_id": scan_id,
        "engine_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "valid": sum(1 for r in results if r.status == "VALID"),
            "invalid": sum(1 for r in results if r.status == "INVALID"),
            "bank_identified": sum(1 for r in results if r.bank != "Unknown"),
            "high_risk": sum(1 for r in results if r.is_high_risk),
            "avg_risk": (sum(r.risk_score for r in results) / len(results))
                        if results else 0,
        },
        "records": [r.to_dict() for r in results],
    }
    out_path.write_text(json.dumps(payload, indent=2, default=str),
                        encoding="utf-8")


def generate_csv_report(results: Sequence[CardResult], out_path: Path) -> None:
    if not results:
        out_path.write_text("", encoding="utf-8")
        return
    keys = list(results[0].to_dict().keys())
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for r in results:
            w.writerow(r.to_dict())


# ============================================================================
#  COMMANDS
# ============================================================================
def _new_scan_id(source: str) -> str:
    return hashlib.sha1(f"{source}-{time.time_ns()}".encode()).hexdigest()[:16]


def _pace_sleep(pace: float) -> None:
    if pace > 0:
        time.sleep(pace + random.uniform(0, pace * 0.5))


def cmd_scan(args: argparse.Namespace) -> int:
    source = str(args.file)
    try:
        lines = read_lines(args.file)
    except FileNotFoundError as exc:
        print(c(f"[!] {exc}", C.BR_RED))
        return 2
    if not lines:
        print(c("[!] No lines to scan.", C.BR_RED))
        return 1

    scan_id = _new_scan_id(source)
    live = None if args.no_live else LiveBinProvider(
        cache_path=args.cache, delay=args.live_delay)
    engine = BinEngine(seed=dict(SEED_BINS), live=live)

    for p in args.json_db:
        if p.is_file():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    engine._seed.update({
                        str(k): {str(a): str(b) for a, b in v.items()}
                        for k, v in raw.items() if isinstance(v, dict)})
            except Exception:
                pass

    mode = "LIVE" if args.live else "SEED+CACHE"
    print(c(f"\n[+] SCAN {scan_id}  |  SOURCE: {source}  |  "
            f"RECORDS: {len(lines)}  |  MODE: {mode}\n",
            C.BR_CYAN, C.BOLD))

    t0 = time.perf_counter()
    total = len(lines)
    results: list[CardResult | None] = [None] * total

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(engine.check_line, scan_id, i + 1, ln, args.live): i
                   for i, ln in enumerate(lines)}
        done = 0
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
            done += 1
            if not args.quiet:
                frac = done / total
                width = 36
                filled = int(width * frac)
                bar = "█" * filled + "░" * (width - filled)
                sys.stdout.write(
                    f"\r  {c('[SCAN]', C.BR_CYAN)} "
                    f"{c('[' + bar + ']', C.BR_GREEN)} "
                    f"{c(f'{frac * 100:5.1f}%', C.BR_YELLOW)} "
                    f"{c(f'({done}/{total})', C.DIM)}")
                sys.stdout.flush()

    if not args.quiet:
        sys.stdout.write("\r" + " " * 90 + "\r"); sys.stdout.flush()

    elapsed = time.perf_counter() - t0
    clean = [r for r in results if r is not None]

    if not args.quiet:
        for r in sorted(clean, key=lambda x: x.line_no):
            print_record(r, mask=args.mask)
            _pace_sleep(args.pace)

    valid = sum(1 for r in clean if r.status == "VALID")
    invalid = len(clean) - valid
    known = sum(1 for r in clean if r.bank != "Unknown")
    high_risk = sum(1 for r in clean if r.is_high_risk)
    avg_risk = sum(r.risk_score for r in clean) / len(clean) if clean else 0
    throughput = len(clean) / elapsed if elapsed else 0

    print()
    print(c("╔══════════════════════════════════════════════════════════════╗",
            C.BR_GREEN, C.BOLD))
    print(c("║                    SCAN  SUMMARY                             ║",
            C.BR_GREEN, C.BOLD))
    print(c("╠══════════════════════════════════════════════════════════════╣",
            C.BR_GREEN, C.BOLD))
    rows = [
        ("SCAN ID",         scan_id[:16],             C.BR_CYAN),
        ("TOTAL",           f"{len(clean)}",          C.BR_WHITE),
        ("VALID",           f"{valid}",               C.BR_GREEN),
        ("INVALID",         f"{invalid}",             C.BR_RED),
        ("BANK IDENTIFIED", f"{known}/{len(clean)}",
            C.BR_GREEN if known == len(clean) else C.BR_YELLOW),
        ("HIGH-RISK FLAGS", f"{high_risk}",
            C.BR_RED if high_risk else C.BR_GREEN),
        ("AVG RISK",        f"{avg_risk:.1f}/100",
            C.BR_GREEN if avg_risk < 30 else C.BR_YELLOW if avg_risk < 60 else C.BR_RED),
        ("ELAPSED",         f"{elapsed:.3f}s",        C.BR_WHITE),
        ("THROUGHPUT",      f"{throughput:,.0f}/s",   C.BR_CYAN),
    ]
    for label, value, col in rows:
        raw = f"║   {label:<18}:  {value}"
        pad = 62 - len(raw)
        print(c(raw + " " * pad + "║", C.BR_GREEN))
    print(c("╚══════════════════════════════════════════════════════════════╝",
            C.BR_GREEN, C.BOLD))

    if not args.no_store:
        store = ResultStore(args.db)
        store.start_scan(scan_id, source)
        store.save_results(scan_id, clean)
        print(c(f"\n[✔] {len(clean)} rows persisted → {args.db}", C.BR_GREEN))
        store.close()

    if not args.no_report:
        out_dir = args.out_dir or Path(f"reports_{scan_id}")
        out_dir.mkdir(parents=True, exist_ok=True)
        generate_html_report(scan_id, clean, out_dir / "report.html")
        generate_json_report(scan_id, clean, out_dir / "report.json")
        generate_csv_report(clean, out_dir / "report.csv")
        print(c(f"[✔] Reports written → {out_dir}/", C.BR_GREEN))

    if args.out:
        ext = args.out.suffix.lower()
        if ext == ".json":
            generate_json_report(scan_id, clean, args.out)
        elif ext == ".csv":
            generate_csv_report(clean, args.out)
        elif ext == ".html":
            generate_html_report(scan_id, clean, args.out)
        else:
            with args.out.open("w", encoding="utf-8") as fh:
                for r in clean:
                    fh.write(f"{r.line_no}|{r.status}|{r.brand}|"
                             f"{r.full_number}|{r.bank}|{r.country}|"
                             f"{r.risk_score}|{r.error}\n")
        print(c(f"[✔] Export → {args.out}", C.BR_GREEN))

    if live is not None:
        live._save()
    return 0 if invalid == 0 else 3


def cmd_lookup(args: argparse.Namespace) -> int:
    prefix = re.sub(r"\D", "", args.bin)[:MAX_BIN_PREFIX]
    if not prefix or len(prefix) < MIN_BIN_PREFIX:
        print(c("[!] BIN must be at least 4 digits.", C.BR_RED))
        return 2
    live = None if args.no_live else LiveBinProvider(
        cache_path=args.cache, delay=args.live_delay)
    engine = BinEngine(live=live)
    print(c(f"\n[+] LOOKUP: {prefix}\n", C.BR_CYAN, C.BOLD))
    info = engine._lookup(prefix, deep=True)
    cc = info.get("cc", "XX")
    print(f"  {c('BIN      :', C.BR_YELLOW)} {c(prefix, C.BR_GREEN, C.BOLD)}")
    print(f"  {c('BANK     :', C.BR_YELLOW)} {c(info.get('bank', 'Unknown'), C.BR_WHITE, C.BOLD)}")
    print(f"  {c('COUNTRY  :', C.BR_YELLOW)} {c(info.get('country', 'Unknown'), C.BR_WHITE)} [{cc}]")
    print(f"  {c('CURRENCY :', C.BR_YELLOW)} {c(CURRENCY_MAP.get(cc, '???'), C.BR_BLUE, C.BOLD)}")
    print(f"  {c('TYPE     :', C.BR_YELLOW)} {c(info.get('type', 'Unknown').upper(), C.BR_BLUE, C.BOLD)}")
    brand = engine.detect_brand(prefix)
    print(f"  {c('BRAND    :', C.BR_YELLOW)} {c(brand.name, C.BR_MAGENTA, C.BOLD)} [{brand.network}]")
    print(f"  {c('LENGTHS  :', C.BR_YELLOW)} {brand.lengths}")
    print(f"  {c('CVV LEN  :', C.BR_YELLOW)} {brand.cvv_len}\n")
    if live is not None:
        live._save()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = ResultStore(args.db)
    scan_id = args.scan_id
    if scan_id:
        rows = store.query("SELECT * FROM results WHERE scan_id=?", (scan_id,))
    else:
        latest = store.query("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1")
        if not latest:
            print(c("[!] No scans in store.", C.BR_RED)); store.close(); return 1
        scan_id = latest[0]["scan_id"]
        print(c(f"[+] Using latest scan: {scan_id}", C.BR_CYAN))
        rows = store.query("SELECT * FROM results WHERE scan_id=?", (scan_id,))
    if not rows:
        print(c("[!] No records found.", C.BR_RED)); store.close(); return 1

    results = []
    for row in rows:
        d = dict(row)
        results.append(CardResult(
            scan_id=d["scan_id"], line_no=d["line_no"],
            raw_input=d["raw_input"], bin_part=d["bin_part"],
            iin_8=d["iin_8"], exp_month=d["exp_month"],
            exp_year=d["exp_year"], cvv=d["cvv_masked"],
            full_number=d["full_number"], length=d["length"],
            brand=d["brand"], network=d["network"],
            is_luhn_valid=bool(d["is_luhn_valid"]),
            is_expiry_valid=bool(d["is_expiry_valid"]),
            is_cvv_valid=bool(d["is_cvv_valid"]),
            is_iin_valid=bool(d["is_iin_valid"]),
            bank=d["bank"], country=d["country"],
            country_code=d["country_code"], currency=d["currency"],
            card_type=d["card_type"],
            is_prepaid=bool(d["is_prepaid"]),
            is_high_risk=bool(d["is_high_risk"]),
            risk_score=d["risk_score"], risk_reasons=d["risk_reasons"],
            status=d["status"], error=d["error"],
            error_kind=d["error_kind"], scanned_at=d["scanned_at"],
        ))
    out_dir = args.out_dir or Path(f"report_{scan_id}")
    out_dir.mkdir(parents=True, exist_ok=True)
    generate_html_report(scan_id, results, out_dir / "report.html")
    generate_json_report(scan_id, results, out_dir / "report.json")
    generate_csv_report(results, out_dir / "report.csv")
    print(c(f"[✔] Report regenerated → {out_dir}/", C.BR_GREEN))
    store.close()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    store = ResultStore(args.db)
    total = store.query("SELECT COUNT(*) AS n FROM results")[0]["n"]
    if total == 0:
        print(c("[!] Store is empty.", C.BR_YELLOW)); store.close(); return 0
    print(c(f"\n[+] STORE STATS  (total rows: {total})\n", C.BR_CYAN, C.BOLD))

    def table(title: str, sql: str) -> None:
        rows = store.query(sql)
        if not rows: return
        print(c(f"── {title} ──", C.BR_GREEN, C.BOLD))
        mx = max((r[1] for r in rows), default=1)
        for row in rows:
            name, n = row[0], row[1]
            pct = n / total * 100
            filled = int(30 * n / mx) if mx else 0
            bar = "█" * filled + "░" * (30 - filled)
            print(f"  {str(name or 'Unknown')[:32]:<34} "
                  f"{c(bar, C.BR_GREEN)}  {n:>5}  ({pct:5.1f}%)")
        print()

    table("TOP BRANDS", "SELECT brand, COUNT(*) FROM results GROUP BY brand ORDER BY 2 DESC")
    table("TOP COUNTRIES", "SELECT country || ' [' || country_code || ']', COUNT(*) FROM results GROUP BY country_code ORDER BY 2 DESC")
    table("TOP ISSUERS", "SELECT bank, COUNT(*) FROM results GROUP BY bank ORDER BY 2 DESC")
    table("CARD TYPES", "SELECT card_type, COUNT(*) FROM results GROUP BY card_type ORDER BY 2 DESC")
    table("STATUS", "SELECT status, COUNT(*) FROM results GROUP BY status ORDER BY 2 DESC")
    table("RISK BRACKETS",
          "SELECT CASE "
          "  WHEN risk_score < 30 THEN 'LOW (0-29)' "
          "  WHEN risk_score < 60 THEN 'MEDIUM (30-59)' "
          "  WHEN risk_score < 80 THEN 'HIGH (60-79)' "
          "  ELSE 'CRITICAL (80+)' END, COUNT(*) "
          "FROM results GROUP BY 1 ORDER BY MIN(risk_score)")

    avg = store.query("SELECT AVG(risk_score) AS a FROM results")[0]["a"] or 0
    print(f"Average risk score across all rows: {avg:.2f}/100\n")
    store.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    store = ResultStore(args.db)
    if args.scan_id:
        rows = store.query("SELECT * FROM results WHERE scan_id=?", (args.scan_id,))
    else:
        rows = store.query("SELECT * FROM results ORDER BY scan_id, line_no")
    if not rows:
        print(c("[!] Nothing to export.", C.BR_RED)); store.close(); return 1
    cols = rows[0].keys()
    ext = args.out.suffix.lower()
    if ext == ".json":
        args.out.write_text(json.dumps([dict(r) for r in rows], indent=2, default=str),
                            encoding="utf-8")
    else:
        with args.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(cols))
            w.writeheader()
            for r in rows:
                w.writerow(dict(r))
    print(c(f"[✔] Exported {len(rows)} rows → {args.out}", C.BR_GREEN))
    store.close()
    return 0


def cmd_bins(args: argparse.Namespace) -> int:
    items = sorted(SEED_BINS.items())
    if args.filter:
        needle = args.filter.lower()
        items = [(k, v) for k, v in items if needle in k.lower()
                 or needle in v["bank"].lower()
                 or needle in v["country"].lower()]
    print(c(f"\n[+] SEED DATABASE — {len(items)} entries\n", C.BR_GREEN, C.BOLD))
    print(c(f"  {'BIN':<8} {'BANK':<34} {'COUNTRY':<20} {'CC':<4} TYPE",
            C.BR_CYAN, C.BOLD))
    print(c("  " + "─" * 78, C.DIM))
    for k, v in items:
        print(f"  {c(k, C.BR_GREEN):<18} "
              f"{c(v['bank'][:32], C.BR_WHITE):<42} "
              f"{c(v['country'][:18], C.BR_GREEN):<28} "
              f"{c(v['cc'], C.BR_CYAN):<8} "
              f"{c(v['type'], C.BR_MAGENTA)}")
    print()
    return 0


def cmd_brands(args: argparse.Namespace) -> int:
    print(c("\n[+] SUPPORTED BRANDS\n", C.BR_GREEN, C.BOLD))
    for b in CARD_BRANDS:
        print(f"  {c(b.name, C.BR_CYAN, C.BOLD):<24} "
              f"{c(b.prefix.pattern[:42], C.DIM):<50} "
              f"{c(f'len={b.lengths}', C.BR_YELLOW):<28} "
              f"{c(f'cvv={b.cvv_len}', C.BR_MAGENTA):<16} "
              f"{c(f'[{b.network}]', C.BR_BLUE)}")
    print()
    return 0


def cmd_ledger(args: argparse.Namespace) -> int:
    ledger = MerchantLedger(args.ledger_file)
    entries = ledger.all()
    if not entries:
        print(c(f"[!] Ledger is empty: {args.ledger_file}", C.BR_YELLOW))
        print(c("    Add one with: binchecker.py ledger-add <PAN> <AMOUNT> "
                "[--currency USD] [--type SALE]", C.DIM))
        return 0

    summary = ledger.summary()
    print(c(f"\n[+] MERCHANT LEDGER — {args.ledger_file}\n",
            C.BR_GREEN, C.BOLD))
    print(c("  ██ SUMMARY ██", C.BR_CYAN, C.BOLD))
    print(f"    Total entries  : {summary['total_entries']}")
    print(f"    Settled sales  : {summary['settled_sales']}")
    print(f"    Settled refunds: {summary['settled_refunds']}")
    for cur, b in sorted(summary["by_currency"].items()):
        print(f"    {cur}:  sales={fmt_money(b['sales'], cur)}  "
              f"refunds={fmt_money(b['refunds'], cur)}  "
              f"net={c(fmt_money(b['net'], cur), C.BR_GREEN, C.BOLD)}  "
              f"({b['count']} txns)")
    print()
    print(c("  ██ ENTRIES ██", C.BR_CYAN, C.BOLD))
    print(c(f"  {'TXN ID':<18} {'CARD':<10} {'TYPE':<8} "
            f"{'AMOUNT':>16}  {'STATUS':<10} NOTE", C.BR_CYAN, C.BOLD))
    print(c("  " + "─" * 96, C.DIM))
    for e in entries[-args.tail:]:
        card = f"****{e.get('card_last4', '????')}"
        amt = fmt_money(float(e.get("amount", 0.0)),
                        e.get("currency", "USD"))
        print(f"  {c(e.get('txn_id', '')[:16], C.BR_GREEN):<26} "
              f"{c(card, C.BR_WHITE):<18} "
              f"{c(e.get('type', ''), C.BR_MAGENTA):<16} "
              f"{c(amt, C.BR_YELLOW):<24} "
              f"{c(e.get('status', ''), C.BR_BLUE):<18} "
              f"{c(e.get('note', ''), C.DIM)}")
    print()
    return 0


def cmd_ledger_add(args: argparse.Namespace) -> int:
    ledger = MerchantLedger(args.ledger_file)
    entry = ledger.add(pan=args.pan, amount=args.amount,
                       currency=args.currency, txn_type=args.type,
                       note=args.note, status=args.status)
    print(c(f"\n[✔] Ledger entry added: {entry['txn_id']}\n", C.BR_GREEN))
    print(f"  {c('CARD   :', C.BR_YELLOW)} ****{entry['card_last4']}")
    print(f"  {c('HASH   :', C.BR_YELLOW)} {entry['card_hash']}")
    print(f"  {c('AMOUNT :', C.BR_YELLOW)} {fmt_money(entry['amount'], entry['currency'])}")
    print(f"  {c('TYPE   :', C.BR_YELLOW)} {entry['type']}")
    print(f"  {c('STATUS :', C.BR_YELLOW)} {entry['status']}")
    print(f"  {c('TIME   :', C.BR_YELLOW)} {entry['timestamp']}\n")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(c(f"\n[+] SELF-TEST — binchecker v{VERSION}\n",
            C.BR_GREEN, C.BOLD))
    results = []

    def check(name: str, cond: bool) -> None:
        results.append((name, cond))
        mark = c("PASS ✓", C.BR_GREEN, C.BOLD) if cond \
               else c("FAIL ✗", C.BR_RED, C.BOLD)
        print(f"  {name:<50} {mark}")

    check("Luhn accepts 4111111111111111",
          BinEngine.luhn_ok("4111111111111111"))
    check("Luhn rejects 4111111111111112",
          not BinEngine.luhn_ok("4111111111111112"))
    check("Luhn accepts 5555555555554444",
          BinEngine.luhn_ok("5555555555554444"))

    eng = BinEngine()
    b1 = eng.detect_brand("4111111111111111")
    check("Brand detection: Visa", b1.name == "Visa")
    b2 = eng.detect_brand("5555555555554444")
    check("Brand detection: Mastercard", b2.name == "Mastercard")
    b3 = eng.detect_brand("378282246310005")
    check("Brand detection: Amex", b3.name == "Amex")

    r = eng.check_line("test", 1, "4111111111111111|12|2030|123")
    check("Full validation: valid card", r.status == "VALID")
    check("Full validation: bank resolved",
          r.bank == "Visa Test Issuer")
    r2 = eng.check_line("test", 2, "4111111111111112|12|2030|123")
    check("Full validation: bad Luhn rejected",
          r2.status == "INVALID")
    r3 = eng.check_line("test", 3, "4111111111111111|13|2020|12")
    check("Full validation: expired rejected",
          not r3.is_expiry_valid)

    tmp = Path("_test_ledger.json")
    try:
        led = MerchantLedger(tmp)
        led.add("4111111111111111", 42.50, "USD", "SALE")
        led.add("4111111111111111", 10.00, "USD", "REFUND")
        summ = led.summary()
        check("Ledger: 2 entries recorded",
              summ["total_entries"] == 2)
        check("Ledger: net computed correctly",
              abs(summ["by_currency"]["USD"]["net"] - 32.50) < 0.01)
    finally:
        if tmp.is_file():
            tmp.unlink()

    tmpdb = Path("_test_store.db")
    try:
        store = ResultStore(tmpdb)
        store.start_scan("test", "selftest")
        store.save_results("test", [r, r2, r3])
        n = store.query("SELECT COUNT(*) AS n FROM results")[0]["n"]
        check("SQLite store: 3 rows persisted", n == 3)
        store.close()
    finally:
        if tmpdb.is_file():
            tmpdb.unlink()

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    col = C.BR_GREEN if passed == total else C.BR_RED
    print()
    print(c(f"  RESULT: {passed}/{total} checks passed\n", col, C.BOLD))
    return 0 if passed == total else 1


def cmd_demo(args: argparse.Namespace) -> int:
    demo_dir = Path("demo_input"); demo_dir.mkdir(exist_ok=True)
    demo_file = demo_dir / "cards.txt"
    demo_lines = [
        "# Sample BINs (test numbers only)",
        "4111111111111111|12|2030|123",
        "5555555555554444|06|2028|321",
        "378282246310005|09|2027|1234",
        "6011111111111117|01|2029|456",
        "4532015112830366|11|2026|789",
        "5425233430109903|03|2028|111",
        "3566002020360505|05|2027|222",
        "4111111111111112|12|2030|123",
        "4111111111111111|13|2020|12",
        "9999999999999999|01|2030|999",
    ]
    demo_file.write_text("\n".join(demo_lines), encoding="utf-8")
    print(c(f"[+] Demo input written → {demo_file}", C.BR_GREEN))
    ns = argparse.Namespace(
        file=demo_file, workers=args.workers, live=False, no_live=True,
        cache=CACHE_PATH, live_delay=LIVE_DELAY_SEC, json_db=[],
        db=DB_PATH, no_store=False, no_report=False,
        out_dir=Path("demo_report"), out=None, mask=False,
        quiet=False, pace=args.pace,
    )
    return cmd_scan(ns)


# ============================================================================
#  CLI
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binchecker",
        description=f"BIN Intelligence Engine v{VERSION} (educational only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DISCLAIMER)
    p.add_argument("--version", action="version", version=f"binchecker {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Validate + enrich a file.")
    s.add_argument("file", type=Path)
    s.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    s.add_argument("--pace", type=float, default=DEFAULT_PACE)
    s.add_argument("--live", action="store_true")
    s.add_argument("--no-live", action="store_true")
    s.add_argument("--cache", type=Path, default=CACHE_PATH)
    s.add_argument("--live-delay", type=float, default=LIVE_DELAY_SEC)
    s.add_argument("--json-db", type=Path, action="append", default=[])
    s.add_argument("--db", type=Path, default=DB_PATH)
    s.add_argument("--no-store", action="store_true")
    s.add_argument("--no-report", action="store_true")
    s.add_argument("--out-dir", type=Path, default=None)
    s.add_argument("-o", "--out", type=Path, default=None)
    s.add_argument("--mask", action="store_true")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    lk = sub.add_parser("lookup", help="Look up a single BIN.")
    lk.add_argument("bin")
    lk.add_argument("--no-live", action="store_true")
    lk.add_argument("--cache", type=Path, default=CACHE_PATH)
    lk.add_argument("--live-delay", type=float, default=LIVE_DELAY_SEC)
    lk.set_defaults(func=cmd_lookup)

    rp = sub.add_parser("report", help="Regenerate reports from the store.")
    rp.add_argument("--scan-id", default=None)
    rp.add_argument("--db", type=Path, default=DB_PATH)
    rp.add_argument("--out-dir", type=Path, default=None)
    rp.set_defaults(func=cmd_report)

    st = sub.add_parser("stats", help="Aggregate statistics over the store.")
    st.add_argument("--db", type=Path, default=DB_PATH)
    st.set_defaults(func=cmd_stats)

    ex = sub.add_parser("export", help="Export store to CSV/JSON.")
    ex.add_argument("out", type=Path)
    ex.add_argument("--scan-id", default=None)
    ex.add_argument("--db", type=Path, default=DB_PATH)
    ex.set_defaults(func=cmd_export)

    bn = sub.add_parser("bins", help="List seed BIN database.")
    bn.add_argument("--filter", default=None)
    bn.set_defaults(func=cmd_bins)

    br = sub.add_parser("brands", help="List supported card brands.")
    br.set_defaults(func=cmd_brands)

    lg = sub.add_parser("ledger", help="Show merchant ledger.")
    lg.add_argument("--ledger-file", type=Path, default=LEDGER_PATH)
    lg.add_argument("--tail", type=int, default=20,
                    help="Show only the last N entries.")
    lg.set_defaults(func=cmd_ledger)

    lga = sub.add_parser("ledger-add", help="Add a merchant ledger entry.")
    lga.add_argument("pan")
    lga.add_argument("amount", type=float)
    lga.add_argument("--currency", default="USD")
    lga.add_argument("--type", default="SALE",
                     choices=["SALE", "REFUND", "CHARGEBACK"])
    lga.add_argument("--status", default="SETTLED",
                     choices=["SETTLED", "PENDING", "FAILED"])
    lga.add_argument("--note", default="")
    lga.add_argument("--ledger-file", type=Path, default=LEDGER_PATH)
    lga.set_defaults(func=cmd_ledger_add)

    dc = sub.add_parser("doctor", help="Run self-tests on the engine.")
    dc.set_defaults(func=cmd_doctor)

    dm = sub.add_parser("demo", help="Run built-in demo.")
    dm.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    dm.add_argument("--pace", type=float, default=DEFAULT_PACE)
    dm.set_defaults(func=cmd_demo)

    return p


# ============================================================================
#  MAIN
# ============================================================================
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(c("\n[!] Interrupted by user.", C.BR_RED))
        return 130
    except Exception as exc:
        print(c(f"\n[!!] Fatal: {exc}", C.BR_RED))
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
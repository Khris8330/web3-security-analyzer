# src/contract_scanner.py
# Contract vulnerability + backdoor scanner

import sys
import os
import re
sys.path.append(os.path.dirname(__file__))

from utils import fetch_etherscan
from exploit_db import get_all_exploits

# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

VULNERABILITY_PATTERNS = [
    {
        "name"       : "Reentrancy Vulnerability",
        "severity"   : "CRITICAL",
        "pattern"    : r"\.call\.value\(|\.call\{value|transfer\(.*\).*\n.*balance",
        "description": (
            "Contract may be vulnerable to reentrancy attacks. "
            "External calls are made before state is updated — "
            "similar to The DAO hack that lost $60M in 2016."
        ),
        "patterns_db": ["reentrancy"]
    },
    {
        "name"       : "Integer Overflow/Underflow",
        "severity"   : "HIGH",
        "pattern"    : r"uint\d*\s+\w+\s*=\s*\w+\s*[\+\-\*](?!.*SafeMath)(?!.*unchecked)",
        "description": (
            "Arithmetic operations without SafeMath or overflow checks. "
            "Can allow attackers to wrap values around to unexpected amounts."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Unchecked Return Value",
        "severity"   : "HIGH",
        "pattern"    : r"\.call\(|\.send\((?!.*require)(?!.*assert)",
        "description": (
            "Return values of low level calls are not checked. "
            "Failed transfers may go unnoticed allowing silent fund loss."
        ),
        "patterns_db": []
    },
    {
        "name"       : "tx.origin Authentication",
        "severity"   : "HIGH",
        "pattern"    : r"tx\.origin",
        "description": (
            "Contract uses tx.origin for authentication. "
            "This can be exploited via phishing attacks to impersonate users."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Selfdestruct Vulnerability",
        "severity"   : "CRITICAL",
        "pattern"    : r"selfdestruct\(|suicide\(",
        "description": (
            "Contract contains selfdestruct function. "
            "If unprotected, attackers can permanently destroy the contract "
            "— similar to the Parity Multisig hack."
        ),
        "patterns_db": ["selfdestruct"]
    },
    {
        "name"       : "Delegatecall Injection",
        "severity"   : "CRITICAL",
        "pattern"    : r"delegatecall\(",
        "description": (
            "Contract uses delegatecall which executes external code "
            "in the context of the calling contract. "
            "Can allow attackers to inject malicious logic."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Timestamp Dependence",
        "severity"   : "MEDIUM",
        "pattern"    : r"block\.timestamp|now\b",
        "description": (
            "Contract relies on block.timestamp for logic. "
            "Miners can manipulate timestamps by up to 15 seconds "
            "to influence outcomes."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Unprotected Initialization",
        "severity"   : "CRITICAL",
        "pattern"    : r"function\s+init\w*\s*\(|function\s+initialize\s*\(",
        "description": (
            "Contract has an initialization function that may be callable "
            "by anyone. Attacker could reinitialize and take ownership "
            "— similar to Parity Multisig hack."
        ),
        "patterns_db": ["unprotected_initialization"]
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# BACKDOOR PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

BACKDOOR_PATTERNS = [
    {
        "name"       : "Hidden Mint Function",
        "severity"   : "CRITICAL",
        "pattern"    : r"function\s+mint\s*\(|_mint\s*\(",
        "description": (
            "Contract contains a mint function. "
            "If unprotected or owner-controlled, unlimited tokens "
            "can be created to dilute holders or drain liquidity."
        ),
        "patterns_db": ["unchecked_mint"]
    },
    {
        "name"       : "Ownership Not Renounced",
        "severity"   : "MEDIUM",
        "pattern"    : r"onlyOwner|Ownable|owner\s*==",
        "description": (
            "Contract has owner privileges. "
            "If ownership is not renounced, the owner can "
            "modify contract behavior at any time."
        ),
        "patterns_db": ["weak_access_control"]
    },
    {
        "name"       : "Pausable Without Timelock",
        "severity"   : "HIGH",
        "pattern"    : r"function\s+pause\s*\(|whenNotPaused|Pausable",
        "description": (
            "Contract can be paused instantly with no timelock. "
            "Owner can freeze all user funds without warning."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Blacklist Function",
        "severity"   : "HIGH",
        "pattern"    : r"blacklist|blocklist|isBlocked|addToBlacklist",
        "description": (
            "Contract can blacklist wallet addresses. "
            "Owner can block specific users from transferring funds."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Fee Manipulation",
        "severity"   : "HIGH",
        "pattern"    : r"setFee\s*\(|updateFee\s*\(|_fee\s*=|taxFee",
        "description": (
            "Contract allows fees to be changed dynamically. "
            "Owner could silently raise fees to 100% to drain transactions."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Proxy Upgrade Backdoor",
        "severity"   : "CRITICAL",
        "pattern"    : r"upgradeTo\s*\(|_upgradeTo\s*\(|upgradeToAndCall",
        "description": (
            "Contract is upgradeable without timelock or governance. "
            "Owner can swap contract logic silently at any time."
        ),
        "patterns_db": []
    },
    {
        "name"       : "Hidden Drain Function",
        "severity"   : "CRITICAL",
        "pattern"    : r"function\s+withdraw\s*\(.*onlyOwner|emergencyWithdraw|rugpull",
        "description": (
            "Contract contains an owner-only withdrawal function "
            "that could drain all funds instantly — classic rugpull pattern."
        ),
        "patterns_db": []
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# CORE SCANNER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_contract_source(address):
    """Fetches verified contract source code from Etherscan"""
    print(f"  Fetching contract source code...")
    result = fetch_etherscan(
        module  ="contract",
        action  ="getsourcecode",
        address =address
    )
    if result and len(result) > 0:
        source = result[0].get("SourceCode", "")
        name   = result[0].get("ContractName", "Unknown")
        if source:
            print(f"  ✅ Source code found — Contract: {name}")
            return source, name
    print(f"  ⚠️  No verified source code found")
    return None, "Unverified Contract"


def scan_vulnerabilities(source_code):
    """Scans source code for known vulnerability patterns"""
    print(f"  Scanning for vulnerabilities...")
    found = []
    for vuln in VULNERABILITY_PATTERNS:
        if re.search(vuln["pattern"], source_code, re.IGNORECASE):
            found.append({
                "name"       : vuln["name"],
                "severity"   : vuln["severity"],
                "description": vuln["description"],
                "type"       : "vulnerability",
                "patterns_db": vuln["patterns_db"]
            })
    print(f"  ✅ Vulnerability scan complete — {len(found)} found")
    return found


def scan_backdoors(source_code):
    """Scans source code for backdoor patterns"""
    print(f"  Scanning for backdoors...")
    found = []
    for backdoor in BACKDOOR_PATTERNS:
        if re.search(backdoor["pattern"], source_code, re.IGNORECASE):
            found.append({
                "name"       : backdoor["name"],
                "severity"   : backdoor["severity"],
                "description": backdoor["description"],
                "type"       : "backdoor",
                "patterns_db": backdoor["patterns_db"]
            })
    print(f"  ✅ Backdoor scan complete — {len(found)} found")
    return found


def compare_to_exploits(vulnerabilities, backdoors):
    """Compares detected patterns to historical exploit database"""
    print(f"  Comparing to historical exploits...")
    all_exploits  = get_all_exploits()
    all_findings  = vulnerabilities + backdoors
    matched       = []

    for finding in all_findings:
        for pattern in finding.get("patterns_db", []):
            for exploit in all_exploits:
                if pattern in exploit["patterns"]:
                    match = {
                        "exploit_name"  : exploit["name"],
                        "year"          : exploit["year"],
                        "loss_usd"      : exploit["loss_usd"],
                        "attack_type"   : exploit["attack_type"],
                        "matched_via"   : finding["name"],
                        "description"   : exploit["description"],
                    }
                    if match not in matched:
                        matched.append(match)

    print(f"  ✅ Historical comparison complete — {len(matched)} matches")
    return matched


def calculate_verdict(vulnerabilities, backdoors, exploit_matches, has_source):
    """
    Generates final verdict based on all scan results.
    Returns verdict, confidence score and reasoning.
    """
    critical = [f for f in vulnerabilities + backdoors
                if f["severity"] == "CRITICAL"]
    high     = [f for f in vulnerabilities + backdoors
                if f["severity"] == "HIGH"]
    medium   = [f for f in vulnerabilities + backdoors
                if f["severity"] == "MEDIUM"]

    # Score calculation
    score = 0
    score += len(critical) * 40
    score += len(high)     * 20
    score += len(medium)   * 10
    score += len(exploit_matches) * 15
    if not has_source:
        score += 30  # Unverified contracts are more suspicious

    score = min(score, 100)

    # Verdict
    if not has_source:
        verdict    = "UNVERIFIED"
        reasoning  = ("Source code not verified on Etherscan. "
                      "Cannot perform full analysis. "
                      "Exercise extreme caution.")
    elif score >= 70:
        verdict    = "LIKELY MALICIOUS"
        reasoning  = (f"Found {len(critical)} critical and {len(high)} high "
                      f"severity issues with {len(exploit_matches)} historical "
                      f"exploit matches.")
    elif score >= 40:
        verdict    = "SUSPICIOUS"
        reasoning  = (f"Found {len(high)} high severity issues. "
                      f"Requires manual review before interaction.")
    elif score >= 15:
        verdict    = "LOW RISK"
        reasoning  = (f"Minor issues detected. "
                      f"Likely false positives but review recommended.")
    else:
        verdict    = "APPEARS SAFE"
        reasoning  = "No significant vulnerabilities or backdoors detected."

    return verdict, score, reasoning


def scan_contract(address):
    """
    Master function — runs full contract security scan.
    Returns complete audit report.
    """
    print(f"\nScanning contract: {address}")
    print("="*55)

    # Step 1 — Fetch source code
    source_code, contract_name = fetch_contract_source(address)
    has_source = source_code is not None

    if not has_source:
        source_code = ""

    # Step 2 — Scan for vulnerabilities
    vulnerabilities = scan_vulnerabilities(source_code) if has_source else []

    # Step 3 — Scan for backdoors
    backdoors = scan_backdoors(source_code) if has_source else []

    # Step 4 — Compare to exploit database
    exploit_matches = compare_to_exploits(vulnerabilities, backdoors)

    # Step 5 — Generate verdict
    verdict, confidence, reasoning = calculate_verdict(
        vulnerabilities, backdoors, exploit_matches, has_source
    )

    # Step 6 — Build full report
    report = {
        "address"        : address,
        "contract_name"  : contract_name,
        "has_source"     : has_source,
        "vulnerabilities": vulnerabilities,
        "backdoors"      : backdoors,
        "exploit_matches": exploit_matches,
        "verdict"        : verdict,
        "confidence"     : confidence,
        "reasoning"      : reasoning,
        "total_issues"   : len(vulnerabilities) + len(backdoors),
    }

    # Print summary
    verdict_icons = {
        "LIKELY MALICIOUS": "🚨",
        "SUSPICIOUS"      : "🔴",
        "LOW RISK"        : "🟡",
        "APPEARS SAFE"    : "🟢",
        "UNVERIFIED"      : "⚪"
    }
    icon = verdict_icons.get(verdict, "⚪")

    print(f"\n  Contract      : {contract_name}")
    print(f"  Vulnerabilities: {len(vulnerabilities)}")
    print(f"  Backdoors     : {len(backdoors)}")
    print(f"  Exploit Matches: {len(exploit_matches)}")
    print(f"  Confidence    : {confidence}/100")
    print(f"  Verdict       : {icon} {verdict}")
    print(f"  Reasoning     : {reasoning}")
    print("="*55)

    return report


if __name__ == "__main__":
    # Test with a real verified contract — Uniswap V2 Router
    test_contract = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    report = scan_contract(test_contract)
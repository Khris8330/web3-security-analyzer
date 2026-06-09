# src/wallet_lookup.py
# Wallet address lookup + risk scoring engine

import sys
import os
sys.path.append(os.path.dirname(__file__))

from utils import (
    fetch_etherscan,
    get_eth_balance,
    get_transaction_count,
    wei_to_eth
)

# ── Known malicious address lists ─────────────────────────────────────────────
# These are real documented hacker/scammer addresses
BLACKLISTED_ADDRESSES = {
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": "Ronin Bridge Attacker",
    "0xa0c7bd318d69424603cbf91e9969870f21b8ab4c": "Ronin Bridge Attacker 2",
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": "Binance Hot Wallet (flagged)",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "Tornado Cash Sanctioned",
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": "Darkside Ransomware",
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": "Conti Ransomware",
    "0x7db418b5d567a4e0e8c59ad71be1fce48f3e6107": "Conti Ransomware 2",
    "0x72a5843cc08275c8171e582972aa4fda8c397b2a": "Conti Ransomware 3",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "OFAC Sanctioned",
}

# ── Risk scoring weights ───────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "blacklisted"           : 100,
    "high_value_transfers"  : 30,
    "many_contract_calls"   : 15,
    "low_transaction_count" : 10,
    "new_wallet"            : 20,
    "high_tx_frequency"     : 25,
}


def check_blacklist(address):
    """Checks if address appears in known malicious address list"""
    normalized = address.lower()
    if normalized in BLACKLISTED_ADDRESSES:
        return True, BLACKLISTED_ADDRESSES[normalized]
    return False, None


def get_wallet_transactions(address, limit=100):
    """Fetches recent transactions for a wallet via Etherscan"""
    txs = fetch_etherscan(
        module="account",
        action="txlist",
        address=address,
        startblock=0,
        endblock=99999999,
        page=1,
        offset=limit,
        sort="desc"
    )
    return txs or []


def analyze_wallet_behavior(address, transactions):
    """
    Analyzes transaction behavior and returns risk indicators.
    Returns a dict of flags and a numeric risk score.
    """
    flags      = []
    risk_score = 0

    if not transactions:
        flags.append("No transaction history found")
        return flags, risk_score, {
            "total_txs"      : 0,
            "total_value_eth": 0,
            "avg_value_eth"  : 0,
            "contract_calls" : 0,
            "failed_txs"     : 0,
            "contract_ratio" : 0,
        }

    # Calculate basic stats
    total_txs    = len(transactions)
    eth_values   = [float(tx.get("value", 0)) / 1e18 for tx in transactions]
    total_value  = sum(eth_values)
    avg_value    = total_value / total_txs if total_txs > 0 else 0
    contract_calls = [tx for tx in transactions if tx.get("input", "0x") != "0x"]
    failed_txs   = [tx for tx in transactions if tx.get("isError", "0") == "1"]

    # Flag: High value transfers
    if avg_value > 10:
        flags.append(f"High average transaction value ({avg_value:.2f} ETH)")
        risk_score += RISK_WEIGHTS["high_value_transfers"]

    # Flag: Heavy contract interaction
    contract_ratio = len(contract_calls) / total_txs if total_txs > 0 else 0
    if contract_ratio > 0.7:
        flags.append(f"Heavy contract interaction ({contract_ratio*100:.0f}% of txs)")
        risk_score += RISK_WEIGHTS["many_contract_calls"]

    # Flag: Many failed transactions (probing behavior)
    if len(failed_txs) > 5:
        flags.append(f"Many failed transactions ({len(failed_txs)}) — possible probing")
        risk_score += 20

    # Flag: Very new wallet
    if total_txs < 5:
        flags.append("Very new or inactive wallet")
        risk_score += RISK_WEIGHTS["new_wallet"]

    return flags, risk_score, {
        "total_txs"      : total_txs,
        "total_value_eth": round(total_value, 4),
        "avg_value_eth"  : round(avg_value, 4),
        "contract_calls" : len(contract_calls),
        "failed_txs"     : len(failed_txs),
        "contract_ratio" : round(contract_ratio * 100, 1),
    }


def calculate_risk_level(risk_score, is_blacklisted):
    """Converts numeric risk score to human readable risk level"""
    if is_blacklisted:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 30:
        return "MEDIUM"
    return "LOW"


def lookup_wallet(address):
    """
    Master function — runs full wallet analysis.
    Returns complete risk profile for the address.
    """
    print(f"\nAnalyzing wallet: {address}")
    print("="*55)

    # Step 1 — Blacklist check
    is_blacklisted, blacklist_reason = check_blacklist(address)
    if is_blacklisted:
        print(f"🚨 BLACKLISTED: {blacklist_reason}")

    # Step 2 — Fetch on-chain data
    eth_balance = get_eth_balance(address)
    tx_count    = get_transaction_count(address)
    transactions = get_wallet_transactions(address)

    # Step 3 — Behavioral analysis
    result = analyze_wallet_behavior(address, transactions)
    flags, risk_score, stats = result

    # Step 4 — Blacklist adds maximum risk
    if is_blacklisted:
        risk_score += RISK_WEIGHTS["blacklisted"]

    # Step 5 — Final risk level
    risk_level = calculate_risk_level(risk_score, is_blacklisted)

    # Step 6 — Build full profile
    profile = {
        "address"          : address,
        "eth_balance"      : eth_balance,
        "tx_count"         : tx_count,
        "is_blacklisted"   : is_blacklisted,
        "blacklist_reason" : blacklist_reason,
        "risk_score"       : min(risk_score, 100),
        "risk_level"       : risk_level,
        "flags"            : flags,
        "stats"            : stats,
        "transactions"     : transactions[:10],  # Return last 10 for display
    }

    # Print summary
    risk_icons = {
        "CRITICAL": "🚨",
        "HIGH"    : "🔴",
        "MEDIUM"  : "🟡",
        "LOW"     : "🟢"
    }
    icon = risk_icons.get(risk_level, "⚪")

    print(f"  ETH Balance  : {eth_balance:.4f} ETH")
    print(f"  TX Count     : {tx_count}")
    print(f"  Risk Score   : {profile['risk_score']}/100")
    print(f"  Risk Level   : {icon} {risk_level}")
    print(f"\n  Flags:")
    for flag in flags:
        print(f"    ⚠️  {flag}")
    print("="*55)

    return profile


if __name__ == "__main__":
    # Test with Vitalik's wallet — should be LOW risk
    test_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    profile = lookup_wallet(test_address)
    print(f"\nRisk Level: {profile['risk_level']}")
# src/dashboard.py
# Web3 Security Analyzer — Main Dashboard

import sys
import os
sys.path.append(os.path.dirname(__file__))

import streamlit as st
import pandas as pd
from wallet_lookup import lookup_wallet
from contract_scanner import scan_contract

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Web3 Security Analyzer",
    page_icon="🔍",
    layout="wide"
)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔍 Web3 Security Analyzer")
st.markdown(
    "**Smart contract vulnerability scanner + wallet risk profiler "
    "powered by pattern analysis and historical exploit matching**"
)
st.divider()

# ── Navigation Tabs ───────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["👛  Wallet Lookup", "📄  Contract Scanner"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — WALLET LOOKUP
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.header("👛 Wallet Risk Profiler")
    st.markdown("Paste any Ethereum wallet address to get a full risk profile.")

    wallet_address = st.text_input(
        "Wallet Address",
        placeholder="0x...",
        key="wallet_input"
    )

    if st.button("🔍 Analyze Wallet", type="primary", key="wallet_btn"):
        if not wallet_address or not wallet_address.startswith("0x"):
            st.error("Please enter a valid Ethereum address starting with 0x")
        else:
            with st.spinner("Analyzing wallet..."):
                profile = lookup_wallet(wallet_address)

            # ── Risk level banner ─────────────────────────────────────────────
            risk_colors = {
                "CRITICAL": "🚨",
                "HIGH"    : "🔴",
                "MEDIUM"  : "🟡",
                "LOW"     : "🟢"
            }
            risk_level = profile["risk_level"]
            icon       = risk_colors.get(risk_level, "⚪")

            if risk_level == "CRITICAL":
                st.error(f"{icon} CRITICAL RISK — This wallet is blacklisted!")
            elif risk_level == "HIGH":
                st.error(f"{icon} HIGH RISK — Suspicious activity detected")
            elif risk_level == "MEDIUM":
                st.warning(f"{icon} MEDIUM RISK — Some suspicious patterns found")
            else:
                st.success(f"{icon} LOW RISK — No major threats detected")

            st.divider()

            # ── Metrics row ───────────────────────────────────────────────────
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Risk Score",    f"{profile['risk_score']}/100")
            col2.metric("ETH Balance",   f"{profile['eth_balance']:.4f} ETH")
            col3.metric("Total TXs",     profile["tx_count"])
            col4.metric("Blacklisted",
                        "YES ⚠️" if profile["is_blacklisted"] else "NO ✅")

            st.divider()

            # ── Behavioral stats ──────────────────────────────────────────────
            stats = profile.get("stats", {})
            if stats and stats.get("total_txs", 0) > 0:
                st.subheader("📊 Behavioral Analysis")
                s1, s2, s3 = st.columns(3)
                s1.metric("Avg TX Value",
                          f"{stats.get('avg_value_eth', 0):.4f} ETH")
                s2.metric("Contract Calls",
                          f"{stats.get('contract_ratio', 0)}%")
                s3.metric("Failed TXs",
                          stats.get("failed_txs", 0))
                st.divider()

            # ── Blacklist info ────────────────────────────────────────────────
            if profile["is_blacklisted"]:
                st.error(
                    f"⚠️ Blacklist Match: **{profile['blacklist_reason']}**"
                )
                st.divider()

            # ── Risk flags ────────────────────────────────────────────────────
            if profile["flags"]:
                st.subheader("🚩 Risk Flags")
                for flag in profile["flags"]:
                    st.warning(f"⚠️ {flag}")
                st.divider()

            # ── Recent transactions ───────────────────────────────────────────
            txs = profile.get("transactions", [])
            if txs:
                st.subheader("📋 Recent Transactions")
                tx_data = []
                for tx in txs[:10]:
                    tx_data.append({
                        "Hash"    : tx.get("hash", "")[:20] + "...",
                        "From"    : tx.get("from", "")[:15] + "...",
                        "To"      : tx.get("to",   "")[:15] + "...",
                        "Value"   : f"{float(tx.get('value', 0)) / 1e18:.4f} ETH",
                        "Status"  : "✅" if tx.get("isError") == "0" else "❌"
                    })
                st.dataframe(pd.DataFrame(tx_data), use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — CONTRACT SCANNER
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.header("📄 Smart Contract Security Scanner")
    st.markdown(
        "Paste any verified contract address to scan for vulnerabilities, "
        "backdoors, and historical exploit matches."
    )

    # Chain selector
    chain = st.selectbox(
        "Select Chain",
        ["Ethereum", "Polygon", "BNB Chain", "Arbitrum", "Base"],
        key="chain_select"
    )

    contract_address = st.text_input(
        "Contract Address",
        placeholder="0x...",
        key="contract_input"
    )

    if st.button("🔍 Scan Contract", type="primary", key="contract_btn"):
        if not contract_address or not contract_address.startswith("0x"):
            st.error("Please enter a valid contract address starting with 0x")
        else:
            # Scanning progress
            progress = st.empty()
            with progress.container():
                st.info("🔄 Fetching contract source code...")

            with st.spinner("Running full security scan..."):
                report = scan_contract(contract_address)

            progress.empty()

            # ── Verdict banner ────────────────────────────────────────────────
            verdict = report["verdict"]
            verdict_config = {
                "LIKELY MALICIOUS": ("error",   "🚨"),
                "SUSPICIOUS"      : ("error",   "🔴"),
                "LOW RISK"        : ("warning", "🟡"),
                "APPEARS SAFE"    : ("success", "🟢"),
                "UNVERIFIED"      : ("warning", "⚪"),
            }
            style, icon = verdict_config.get(verdict, ("warning", "⚪"))

            if style == "error":
                st.error(
                    f"{icon} **{verdict}** — "
                    f"Confidence: {report['confidence']}/100"
                )
            elif style == "success":
                st.success(
                    f"{icon} **{verdict}** — "
                    f"Confidence: {report['confidence']}/100"
                )
            else:
                st.warning(
                    f"{icon} **{verdict}** — "
                    f"Confidence: {report['confidence']}/100"
                )

            st.caption(f"📝 {report['reasoning']}")
            st.divider()

            # ── Metrics row ───────────────────────────────────────────────────
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Contract",       report["contract_name"])
            col2.metric("Vulnerabilities", len(report["vulnerabilities"]))
            col3.metric("Backdoors",       len(report["backdoors"]))
            col4.metric("Exploit Matches", len(report["exploit_matches"]))

            st.divider()

            # ── Vulnerabilities ───────────────────────────────────────────────
            if report["vulnerabilities"]:
                st.subheader("🔓 Vulnerabilities Detected")
                for vuln in report["vulnerabilities"]:
                    severity_fn = {
                        "CRITICAL": st.error,
                        "HIGH"    : st.error,
                        "MEDIUM"  : st.warning,
                        "LOW"     : st.info
                    }.get(vuln["severity"], st.info)

                    icons = {
                        "CRITICAL": "🚨",
                        "HIGH"    : "🔴",
                        "MEDIUM"  : "🟡",
                        "LOW"     : "🟢"
                    }
                    severity_fn(
                        f"{icons[vuln['severity']]} **[{vuln['severity']}] "
                        f"{vuln['name']}** — {vuln['description']}"
                    )
                st.divider()

            # ── Backdoors ─────────────────────────────────────────────────────
            if report["backdoors"]:
                st.subheader("🚪 Backdoors Detected")
                for bd in report["backdoors"]:
                    severity_fn = {
                        "CRITICAL": st.error,
                        "HIGH"    : st.error,
                        "MEDIUM"  : st.warning,
                        "LOW"     : st.info
                    }.get(bd["severity"], st.info)

                    icons = {
                        "CRITICAL": "🚨",
                        "HIGH"    : "🔴",
                        "MEDIUM"  : "🟡",
                        "LOW"     : "🟢"
                    }
                    severity_fn(
                        f"{icons[bd['severity']]} **[{bd['severity']}] "
                        f"{bd['name']}** — {bd['description']}"
                    )
                st.divider()

            # ── Historical exploit matches ────────────────────────────────────
            if report["exploit_matches"]:
                st.subheader("📚 Historical Exploit Matches")
                st.caption(
                    "These past exploits share similar patterns "
                    "with this contract."
                )
                for match in report["exploit_matches"]:
                    with st.expander(
                        f"⚠️ Similar to: {match['exploit_name']} "
                        f"({match['year']}) — "
                        f"${match['loss_usd']:,.0f} lost"
                    ):
                        st.write(f"**Attack Type:** {match['attack_type']}")
                        st.write(f"**Matched Via:** {match['matched_via']}")
                        st.write(f"**What Happened:** {match['description']}")

            # ── No issues found ───────────────────────────────────────────────
            if (not report["vulnerabilities"] and
                    not report["backdoors"] and
                    report["has_source"]):
                st.success(
                    "✅ No vulnerabilities or backdoors detected. "
                    "Contract appears clean."
                )
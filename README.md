# 🔍 Web3 Security Analyzer

> Smart contract vulnerability scanner and wallet risk profiler powered by 
pattern analysis, backdoor detection, and historical exploit matching.

## 🚨 The Problem
The Web3 ecosystem loses billions annually to smart contract exploits, 
rugpulls, and malicious wallet activity. Most investors and developers 
lack the tools to assess risk before interacting with unknown contracts 
or wallets.

## 🛡️ What This Tool Does
- Scans smart contract source code for vulnerabilities and backdoors
- Profiles wallet addresses with behavioral risk scoring
- Matches detected patterns against 15 documented historical exploits
- Delivers a clear verdict — Likely Malicious / Suspicious / Low Risk / Appears Safe
- Supports Ethereum, Polygon, BNB Chain, Arbitrum and Base

## ⚡ Detection Coverage

### Vulnerability Detection
| Vulnerability | Severity |
|---|---|
| Reentrancy Attack | 🚨 Critical |
| Integer Overflow/Underflow | 🔴 High |
| Unchecked Return Values | 🔴 High |
| tx.origin Authentication | 🔴 High |
| Selfdestruct Vulnerability | 🚨 Critical |
| Delegatecall Injection | 🚨 Critical |
| Timestamp Dependence | 🟡 Medium |
| Unprotected Initialization | 🚨 Critical |

### Backdoor Detection
| Backdoor | Severity |
|---|---|
| Hidden Mint Function | 🚨 Critical |
| Ownership Not Renounced | 🟡 Medium |
| Pausable Without Timelock | 🔴 High |
| Blacklist Function | 🔴 High |
| Fee Manipulation | 🔴 High |
| Proxy Upgrade Backdoor | 🚨 Critical |
| Hidden Drain Function | 🚨 Critical |

### Wallet Risk Flags
| Flag | Description |
|---|---|
| Blacklist Match | Address found on known malicious address lists |
| High Value Transfers | Unusually large ETH movements |
| Heavy Contract Interaction | Possible bot or exploit behavior |
| Many Failed Transactions | Possible probing or attack attempts |
| New Wallet | Minimal transaction history |

## 📚 Historical Exploit Database
The scanner compares detected patterns against 15 real documented exploits
covering $3.4 billion in total losses:

| Exploit | Year | Loss | Attack Type |
|---|---|---|---|
| Ronin Bridge | 2022 | $625M | Compromised Validator Keys |
| Poly Network | 2021 | $611M | Smart Contract Logic Flaw |
| Binance Bridge | 2022 | $570M | Proof Verification Bypass |
| Wormhole Bridge | 2022 | $320M | Signature Verification Bypass |
| Euler Finance | 2023 | $197M | Flash Loan + Donation Attack |
| Nomad Bridge | 2022 | $190M | Improper Message Validation |
| Wintermute | 2022 | $160M | Weak Private Key Generation |
| Beanstalk Farms | 2022 | $182M | Flash Loan Governance Attack |
| Cream Finance | 2021 | $130M | Flash Loan Reentrancy |
| BadgerDAO | 2021 | $120M | Frontend Phishing |
| Mango Markets | 2022 | $117M | Price Oracle Manipulation |
| Fei Protocol | 2022 | $80M | Reentrancy Attack |
| Harvest Finance | 2020 | $34M | Flash Loan Price Manipulation |
| Parity Multisig | 2017 | $30M | Access Control Bug |
| The DAO | 2016 | $60M | Reentrancy Attack |

## 🏗️ Architecture
User Input (wallet or contract address)
↓
Alchemy API          Etherscan API V2
(on-chain data)      (source code fetch)
↓                    ↓
wallet_lookup.py    contract_scanner.py
├── Blacklist check  ├── Vulnerability scan
├── Behavior analysis├── Backdoor scan
└── Risk scoring     └── Exploit matching
↓                    ↓
verdict_engine — Final verdict + confidence score
↓
Streamlit Dashboard
├── 👛 Wallet Lookup Tab
└── 📄 Contract Scanner Tab

## 🛠️ Tech Stack
| Tool | Purpose |
|---|---|
| **Python 3.14** | Core language |
| **Web3** | Ethereum RPC via Alchemy |
| **Requests** | Etherscan API calls |
| **Scikit-learn** | ML pattern analysis |
| **Pandas** | Transaction data processing |
| **Streamlit** | Interactive dashboard |
| **python-dotenv** | Secure API key management |

## 🚀 Setup & Installation

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/web3-security-analyzer.git
cd web3-security-analyzer
```

### 2. Create virtual environment
```bash
python -m venv venv
source venv/Scripts/activate  # Windows
source venv/bin/activate       # Linux/Mac
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API keys
Create a `.env` file in the root directory:
ALCHEMY_URL=https://eth-mainnet.g.alchemy.com/v2/my_api_key
ETHERSCAN_API_KEY=my_etherscan_api_key

### 5. Run the dashboard
```bash
streamlit run src/dashboard.py
```

## 📊 Sample Results

### Wallet Analysis
- Address: Vitalik Buterin's public wallet
- Risk Score: 0/100
- Risk Level: 🟢 LOW
- ETH Balance: 5.69 ETH
- Total Transactions: 5,896
- Blacklisted: NO

### Contract Scan (Uniswap V2 Router)
- Vulnerabilities found: 4
- Backdoors found: 1
- Historical exploit matches: 6
- Verdict: Requires manual review

## ⚠️ Limitations & Future Work
- Contract scanner requires verified source code on Etherscan
- Pattern matching may produce false positives on legitimate protocols
- Future: Multi-chain support with automatic chain detection
- Future: GPT-powered natural language audit report generation
- Future: Telegram and email alerting for high risk detections
- Future: On-chain transaction behavior integrated into contract verdict

## 🔗 Related Project
This tool is part of a two-part Web3 security suite:
- **Tool 1:** [Onchain Threat Detector](https://github.com/Khris8330/Onchain-Threat-detector) 
  — Real-time Ethereum transaction monitoring and ML anomaly detection

## 📄 License
MIT License
# src/utils.py
# Shared helper functions for the Web3 Security Analyzer

import os
import requests
from dotenv import load_dotenv

load_dotenv()

ALCHEMY_URL    = os.getenv("ALCHEMY_URL")
ETHERSCAN_KEY  = os.getenv("ETHERSCAN_API_KEY")


def hex_to_int(hex_value):
    """Converts hex string to integer"""
    if not hex_value or hex_value == "0x":
        return 0
    return int(hex_value, 16)


def wei_to_eth(wei_value):
    """Converts Wei to ETH"""
    return hex_to_int(wei_value) / 1e18


def fetch_alchemy(method, params):
    """Makes a JSON-RPC call to Alchemy"""
    payload = {
        "jsonrpc": "2.0",
        "method" : method,
        "params" : params,
        "id"     : 1
    }
    response = requests.post(ALCHEMY_URL, json=payload)
    data     = response.json()
    return data.get("result")


def fetch_etherscan(module, action, **kwargs):
    """Makes a call to the Etherscan API V2"""
    params = {
        "chainid" : "1",
        "module"  : module,
        "action"  : action,
        "apikey"  : ETHERSCAN_KEY,
        **kwargs
    }
    response = requests.get(
        "https://api.etherscan.io/v2/api",
        params=params
    )
    data = response.json()
    if data.get("status") == "1":
        return data.get("result")
    return None


def get_eth_balance(address):
    """Gets ETH balance of any address"""
    result = fetch_alchemy("eth_getBalance", [address, "latest"])
    return wei_to_eth(result) if result else 0


def get_transaction_count(address):
    """Gets total number of transactions for an address"""
    result = fetch_alchemy("eth_getTransactionCount", [address, "latest"])
    return hex_to_int(result) if result else 0


if __name__ == "__main__":
    # Quick connection test
    test_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # Vitalik's wallet
    balance = get_eth_balance(test_address)
    tx_count = get_transaction_count(test_address)
    print(f"Test address  : {test_address}")
    print(f"ETH Balance   : {balance:.4f} ETH")
    print(f"TX Count      : {tx_count}")
    print("Utils working correctly!")
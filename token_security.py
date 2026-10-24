#!/usr/bin/env python3
"""Token Security Analyzer — x402 paid API (0.003 USDC/call)

Detects honeypots, rug pulls, and suspicious patterns in ERC-20 tokens
using public on-chain data (Base RPC + DexScreener + GoPlus).
"""
import json, os, urllib.request, urllib.parse, http.server, socketserver, base64
from datetime import datetime, timezone

PORT = int(os.environ.get("PORT", 8840))
PRICE_USDC = 0.003
PAY_TO = "0x65aa59025C4AcD8CD7ba2051ecb9152abaE4fcC6"
NETWORK = "base"
USDC_ADDR = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_RPC = "https://mainnet.base.org"

# ── Helpers ──────────────────────────────────────────────
def rpc_call(method, params):
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(BASE_RPC, data=data, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def fetch_json(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Belkzaz/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def get_code(address):
    r = rpc_call("eth_getCode", [address, "latest"])
    return r.get("result", "0x") if "result" in r else "0x"

def get_balance(address):
    r = rpc_call("eth_getBalance", [address, "latest"])
    val = r.get("result", "0x0")
    try:
        return int(val, 16) / 1e18
    except:
        return 0.0

def get_token_info(address):
    # ERC-20 standard calls: name, symbol, decimals, totalSupply
    selectors = {
        "name": "0x06fdde03",
        "symbol": "0x95d89b41",
        "decimals": "0x313ce567",
        "totalSupply": "0x18160ddd",
    }
    info = {}
    for key, sel in selectors.items():
        r = rpc_call("eth_call", [{"to": address, "data": sel}, "latest"])
        raw = r.get("result", "0x")
        if raw and raw != "0x":
            try:
                if key in ("name", "symbol"):
                    # decode string
                    if len(raw) > 66:
                        info[key] = bytes.fromhex(raw[2:]).split(b'\x00')[0].decode('utf-8', errors='replace').strip()
                    else:
                        info[key] = raw
                elif key == "decimals":
                    info[key] = int(raw, 16)
                elif key == "totalSupply":
                    info[key] = int(raw, 16)
            except:
                info[key] = raw
    return info

def check_dexscreener(address):
    url = f"https://api.dexscreener.com/latest/dex/tokens/{address}"
    data = fetch_json(url)
    if "error" in data:
        return {"error": data["error"]}
    pairs = data.get("pairs", [])
    if not pairs:
        return {"listed": False, "pairs": 0}
    pair = pairs[0]
    return {
        "listed": True,
        "pairs": len(pairs),
        "dex": pair.get("dexId", "unknown"),
        "price_usd": pair.get("priceUsd"),
        "liquidity_usd": pair.get("liquidity", {}).get("usd", 0),
        "volume_24h": pair.get("volume", {}).get("h24", 0),
        "price_change_24h": pair.get("priceChange", {}).get("h24", 0),
        "fdv": pair.get("fdv"),
        "pair_created": pair.get("pairCreatedAt"),
    }

def check_goplus(address):
    url = f"https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses={address}"
    data = fetch_json(url)
    if "error" in data:
        return {"error": data["error"]}
    result = data.get("result", {}).get(address.lower(), {})
    if not result:
        return {"available": False}
    return {
        "available": True,
        "is_honeypot": result.get("is_honeypot", "0") == "1",
        "buy_tax": result.get("buy_tax", "0"),
        "sell_tax": result.get("sell_tax", "0"),
        "can_take_back_ownership": result.get("can_take_back_ownership", "0") == "1",
        "owner_change_balance": result.get("owner_change_balance", "0") == "1",
        "hidden_owner": result.get("hidden_owner", "0") == "1",
        "selfdestruct": result.get("selfdestruct", "0") == "1",
        "external_call": result.get("external_call", "0") == "1",
        "is_proxy": result.get("is_proxy", "0") == "1",
        "is_mintable": result.get("is_mintable", "0") == "1",
        "can_pause": result.get("can_pause", "0") == "1",
        "trading_cooldown": result.get("trading_cooldown", "0") == "1",
        "is_blacklisted": result.get("is_blacklisted", "0") == "1",
        "is_whitelisted": result.get("is_whitelisted", "0") == "1",
        "anti_whale": result.get("anti_whale", "0") == "1",
        "slippage_modifiable": result.get("slippage_modifiable", "0") == "1",
        "personal_slippage_modifiable": result.get("personal_slippage_modifiable", "0") == "1",
    }

def analyze_token(address):
    address = address.strip().lower()
    if not address.startswith("0x") or len(address) != 42:
        return {"error": "Invalid address format. Expected 0x + 40 hex chars."}

    code = get_code(address)
    is_contract = code != "0x" and len(code) > 2
    token_info = get_token_info(address) if is_contract else {}
    dex_data = check_dexscreener(address)
    goplus_data = check_goplus(address)

    # Risk scoring
    risk_score = 0
    risk_factors = []

    if not is_contract:
        risk_factors.append("Not a contract — may be an EOA")
        risk_score += 10

    if goplus_data.get("available"):
        gp = goplus_data
        if gp.get("is_honeypot"):
            risk_score += 50
            risk_factors.append("HONEYPOT DETECTED — cannot sell tokens")
        try:
            buy_tax = float(gp.get("buy_tax", "0"))
            sell_tax = float(gp.get("sell_tax", "0"))
            if buy_tax > 10:
                risk_score += 15
                risk_factors.append(f"High buy tax: {buy_tax}%")
            if sell_tax > 10:
                risk_score += 20
                risk_factors.append(f"High sell tax: {sell_tax}%")
            if sell_tax > buy_tax + 5:
                risk_score += 15
                risk_factors.append("Sell tax significantly higher than buy tax")
        except:
            pass
        if gp.get("can_take_back_ownership"):
            risk_score += 20
            risk_factors.append("Owner can take back ownership")
        if gp.get("owner_change_balance"):
            risk_score += 25
            risk_factors.append("Owner can change balances")
        if gp.get("hidden_owner"):
            risk_score += 15
            risk_factors.append("Hidden owner detected")
        if gp.get("selfdestruct"):
            risk_score += 30
            risk_factors.append("Contract can self-destruct")
        if gp.get("is_mintable"):
            risk_score += 15
            risk_factors.append("Token is mintable (unlimited supply risk)")
        if gp.get("can_pause"):
            risk_score += 10
            risk_factors.append("Trading can be paused by owner")
        if gp.get("is_blacklisted"):
            risk_score += 10
            risk_factors.append("Blacklist functionality present")
        if gp.get("slippage_modifiable"):
            risk_score += 15
            risk_factors.append("Slippage can be modified by owner")
        if gp.get("is_proxy"):
            risk_score += 5
            risk_factors.append("Proxy contract — implementation can change")

    if dex_data.get("listed"):
        liq = dex_data.get("liquidity_usd", 0) or 0
        if liq < 1000:
            risk_score += 15
            risk_factors.append(f"Low liquidity: ${liq:,.0f}")
        vol = dex_data.get("volume_24h", 0) or 0
        if vol < 100:
            risk_score += 5
            risk_factors.append(f"Low 24h volume: ${vol:,.0f}")
        pc = dex_data.get("price_change_24h", 0) or 0
        if abs(pc) > 50:
            risk_score += 10
            risk_factors.append(f"Extreme price change 24h: {pc}%")
    else:
        risk_score += 10
        risk_factors.append("Not listed on any DEX")

    risk_score = min(risk_score, 100)
    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 40:
        verdict = "MEDIUM RISK"
    elif risk_score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "SAFE"

    return {
        "address": address,
        "is_contract": is_contract,
        "token_info": token_info,
        "dex_data": dex_data,
        "security": goplus_data,
        "risk_score": risk_score,
        "verdict": verdict,
        "risk_factors": risk_factors,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "chain": "base",
    }

# ── HTTP Server ──────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self.respond(200, {"status":"ok","service":"token-security","price_usdc":PRICE_USDC,"chain":"base"})
            return
        if parsed.path == "/analyze":
            params = urllib.parse.parse_qs(parsed.query)
            addr = params.get("address", [""])[0]
            chain = params.get("chain", ["base"])[0]
            # Check payment header
            payment = self.headers.get("X-PAYMENT", "")
            if not payment:
                self.respond(402, {
                    "error": "Payment required",
                    "price_usdc": PRICE_USDC,
                    "pay_to": PAY_TO,
                    "network": NETWORK,
                    "asset": "USDC",
                    "asset_address": USDC_ADDR,
                })
                return
            # Payment provided — analyze
            result = analyze_token(addr)
            self.respond(200, result)
            return
        self.respond(404, {"error": "Not found", "endpoints": ["/health", "/analyze?address=0x...&chain=base"]})

    def respond(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Token Security Analyzer running on port {PORT}")
        httpd.serve_forever()

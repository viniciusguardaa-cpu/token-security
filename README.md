# Token Security Analyzer — x402 Paid API

Analyze ERC-20 tokens for honeypots, rug pulls, and suspicious patterns via x402 (USDC on Base).

## Endpoints

| Method | Path | Price | Description |
|--------|------|-------|-------------|
| GET | /health | Free | Health check |
| GET | /analyze?address=0x...&chain=base | 0.003 USDC | Token security analysis |

## What It Detects
- **Honeypot** — cannot sell tokens after buying
- **High buy/sell tax** — excessive transaction fees
- **Sell tax >> buy tax** — asymmetric taxation (classic rug pull)
- **Owner can take back ownership** — re-centralization risk
- **Owner can change balances** — arbitrary mint/burn
- **Hidden owner** — disguised admin control
- **Self-destruct** — contract can destroy itself
- **Mintable** — unlimited supply risk
- **Pausable** — trading can be frozen
- **Blacklist/whitelist** — selective blocking
- **Slippage modifiable** — owner can change slippage
- **Proxy contract** — implementation can change
- **Low liquidity** — insufficient DEX liquidity
- **Extreme price changes** — abnormal volatility

## Risk Scoring
Each factor adds to a 0-100 risk score:
- **0-14**: SAFE
- **15-39**: LOW RISK
- **40-69**: MEDIUM RISK
- **70-100**: HIGH RISK

## Payment
- Network: Base Mainnet (eip155:8453)
- Asset: USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
- PayTo: 0x65aa59025C4AcD8CD7ba2051ecb9152abaE4fcC6
- Price: 0.003 USDC per call

## Usage

curl https://attempting-equation-get-besides.trycloudflare.com/health

curl "https://attempting-equation-get-besides.trycloudflare.com/analyze?address=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913&chain=base" \
  -H "X-PAYMENT: <base64-encoded-payment-proof>"

## Tech Stack
- Python 3 (stdlib only — no external dependencies)
- GoPlus Security API (free, no API key required)
- DexScreener API (free)
- Base RPC (public)
- x402 payment protocol

## License
MIT
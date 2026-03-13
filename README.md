# SolAudit — Secure Transaction Core

> Open-source security module powering [solaudit.app](https://solaudit.app)

This repository contains the security-hardened transaction builder used in production at SolAudit — a Solana wallet security scanner for revoking token approvals, recovering SOL rent, burning unwanted tokens, and batch-selling via Jupiter Ultra.

This is a sanitized version of our production code. It demonstrates our security practices transparently — any engineer can verify in minutes that funds always go to the user's wallet.

---

## Why This Exists

Most Solana dApps build transactions without verifying what they contain at the instruction level. This leaves users exposed to:

- **Supply chain attacks** on npm packages (real incident: CVE-2024-54134, $190K stolen)
- **Malicious RPC responses** that inflate balances or redirect destinations
- **Prototype pollution** that silently replaces critical wallet addresses
- **XSS injection** into token/NFT metadata that hijacks transfers

This module addresses all of the above with layered, zero-trust defenses.

---

## Wallet Signing Methods

SolAudit uses different signing methods depending on the operation, all compatible with Blowfish Lighthouse simulation:

### Signing Method Matrix

| Operation | Method | Blowfish Compatible | Why |
|---|---|---|---|
| Revoke, Close, Burn (single tx) | `wallet.sendTransaction()` | Yes | Maps to provider `signAndSendTransaction` — Blowfish intercepts and simulates |
| Batch burns, Rent recovery | `wallet.sendTransaction()` per tx | Yes | One popup per batch transaction |
| Panic Sell — batch (primary) | `wallet.signAllTransactions()` | Yes | 1 popup for all swaps — Blowfish simulates each tx individually in batch popup |
| Panic Sell — sequential (fallback) | `wallet.signTransaction()` | Yes | 1 popup per swap — signed tx sent to Jupiter Ultra execute |
| Panic Sell — last resort | `wallet.sendTransaction()` | Yes | For wallets without `signTransaction` support |

### How Blowfish Works With Each Method

**`sendTransaction`** — Blowfish intercepts at the wallet provider level. The wallet adapter's `sendTransaction()` maps to the provider's `signAndSendTransaction`, which Blowfish hooks into to simulate before the user approves.

**`signAllTransactions`** — Blowfish simulates each transaction individually within the batch approval popup. The user sees a summary of all transactions before approving. Used by DZap, Raydium, Orca, and other major dApps for batch operations.

**`signTransaction`** — Blowfish intercepts during the sign step. The transaction is simulated before the user approves signing. After signing, the transaction cannot be modified (ed25519 signature covers every byte).

### Architecture

```
Server (Edge/Worker)                    Client (Browser)
┌──────────────────┐                    ┌──────────────────────┐
│ Build unsigned tx │ ──── base64 ────> │ Deserialize          │
│ (VersionedTx)    │                    │ Blowfish simulates   │
│ No private keys  │                    │ User approves popup  │
│ No signing       │                    │ Wallet signs         │
└──────────────────┘                    │ Send to network      │
                                        └──────────────────────┘
```

For Panic Sell (Jupiter Ultra), the signed transaction is sent back to our server which forwards it to Jupiter's `/ultra/v1/execute` endpoint for optimal landing. The signed transaction is never modified — any modification would invalidate the ed25519 signature.

### Supported Wallets

- Phantom (with Blowfish Lighthouse)
- Solflare
- Backpack
- Ledger (via adapter)
- Any wallet supporting `@solana/wallet-adapter-react`

---

## Security Architecture

### Transaction-Level Defenses

#### [CRITICAL-1] Supply Chain Attack — CVE-2024-54134 (CVSS 8.3)
**Real incident:** `@solana/web3.js` v1.95.7 was backdoored on Dec 2, 2024. The backdoor exfiltrated private keys via fake CloudFlare headers.

**Fix:** After `createCloseAccountInstruction()` is called, we deserialize and verify byte-by-byte that:
- `keys[0]` (account to close) matches the expected token account
- `keys[1]` (destination) matches the user's wallet — **the most critical check**
- `keys[2]` (authority) matches the user's wallet

If any check fails, the entire operation aborts before signing.

```typescript
function verifyCloseInstruction(
  ix: TransactionInstruction,
  expectedAccount: PublicKey,
  expectedDestination: PublicKey,
  expectedAuthority: PublicKey
): boolean {
  if (ix.keys.length < 3) return false;
  if (!ix.keys[1].pubkey.equals(expectedDestination)) return false;
  // ...full verification of all 3 keys
}
```

#### [CRITICAL-2] Malicious RPC / MITM
A Service Worker or browser extension can replace the RPC endpoint silently.

**Fix:** The Connection object's endpoint is validated against a trusted whitelist using URL parsing with suffix-based subdomain matching.

#### [CRITICAL-3] Prototype Pollution
`Object.prototype.toPubkey = attackerWallet` can corrupt address resolution.

**Fix:** `Object.freeze()` on all constant arrays and PublicKey objects. `instanceof PublicKey` for type checks.

#### [CRITICAL-4] XSS to Wallet Drain
XSS in token metadata can replace fee wallet addresses at runtime.

**Fix:** All critical constants are frozen. Fee wallet resolved from backend environment variable, never embedded in client code.

#### [HIGH-5] Account Spoofing
Malicious RPC can inject accounts with inflated lamport values.

**Fix:** On-chain verification before every transaction:
1. Account must exist on-chain
2. Owner must be `TOKEN_PROGRAM_ID` or `TOKEN_2022_PROGRAM_ID`
3. Authority must match `userPubkey`
4. Lamports must not deviate more than 2% from reported value
5. Lamports capped at 5,000,000 — higher triggers rejection

#### [HIGH-6] Integer Overflow / Precision
JavaScript `Number.MAX_SAFE_INTEGER = 2^53-1`. Lamport totals can exceed this.

**Fix:** Exclusive use of `BigInt` for all financial calculations:
```typescript
const PROTOCOL_FEE_BPS = 400n;    // 4%
const BPS_DIVISOR      = 10_000n;
const feeLamports = (batchRent * PROTOCOL_FEE_BPS) / BPS_DIVISOR;
```

#### [MEDIUM-7] Dynamic Compute Unit Calibration
Hardcoded CU limits waste fees or cause failures.

**Fix:** Simulate a representative transaction to measure actual CUs, apply 1.25x safety buffer. Batch sizes auto-shrink if serialized tx exceeds 1,180 bytes.

### API-Level Defenses

| Defense | Description |
|---|---|
| **ed25519 Curve Validation** | All wallet addresses validated with `PublicKey.isOnCurve()` at every entry point |
| **Content-Type Enforcement** | Strict `application/json` validation, `415` on mismatch |
| **Rate Limiting** | Per-IP fixed-window rate limiting per endpoint |
| **CSRF / Origin Validation** | `Origin` header validated against whitelist, `403` on unknown origins |
| **Account Cap** | Maximum 200 token accounts per request (DoS prevention) |
| **Structured Logging** | JSON-logged security events without stack traces (prevents API key leakage) |
| **Blockhash Freshness** | Auto-refresh if batch build exceeds 2 seconds |
| **Pre-flight Simulation** | Every transaction simulated with `sigVerify: false` before returning to client |

---

## Transaction Integrity Guarantee

Once a user signs a transaction, **nobody can modify it** — not SolAudit, not Jupiter, not anyone. This is guaranteed by ed25519 cryptography:

1. The wallet signs the transaction bytes with the user's private key
2. The signature covers **every byte** of the transaction (instructions, accounts, amounts)
3. Any modification (even 1 bit) invalidates the signature
4. Validators reject transactions with invalid signatures

**What this means in practice:**
- The server builds an unsigned transaction and sends it to the client
- Blowfish/Phantom shows the user exactly what will happen (simulation)
- The user approves and signs
- After signing, the transaction is immutable — it will do exactly what was simulated

---

## Error Codes

| Code | Meaning |
|---|---|
| `WALLET_MISMATCH` | Connected wallet does not match userPubkey |
| `RPC_UNTRUSTED` | RPC endpoint not in trusted whitelist |
| `NO_ACCOUNTS` | No valid accounts after sanitization |
| `ACCOUNT_VALIDATION_FAILED` | All accounts failed on-chain verification |
| `SUPPLY_CHAIN_ALERT` | **Critical:** Instruction had tampered destination. Nothing was signed. |
| `TX_TOO_LARGE` | Transaction exceeds 1,180B safe limit |
| `BLOCKHASH_EXPIRED` | Blockhash expired before signing |

---

## Trusted RPC Whitelist

```typescript
const ALLOWED_RPC_HOSTS = Object.freeze([
  "api.mainnet-beta.solana.com",
  "helius-rpc.com",
  "helius.xyz",
  "rpc.ankr.com",
  "g.alchemy.com",
  "mainnet.rpc.jito.wtf",
  "api.devnet.solana.com",
  "127.0.0.1", "localhost",
]);
```

---

## Design Principles

- **Zero-trust inputs** — every parameter validated independently
- **Zero-trust libraries** — instruction output verified at byte level, not API level
- **Fail-closed** — any validation failure returns typed error and aborts
- **Immutability by default** — all constants frozen at module load
- **BigInt everywhere** — no floating point in financial calculations
- **Structured logging** — JSON events without stack traces in production
- **Blowfish compatible** — all signing paths allow wallet-level simulation before user approval

---

## Links

- **Production:** [solaudit.app](https://solaudit.app)
- **Twitter:** [@solaboratorio](https://twitter.com/solaboratorio)
- **Developer:** Jose ([@Blitz99Win](https://github.com/Blitz99Win))

---

## License

MIT

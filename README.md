# SolAudit — Secure Transaction Core 🛡️
> Open-source security module powering [solaudit.app](https://solaudit.app)

This module is the core transaction engine used in production at solaudit.app — a Solana wallet security tool for revoking token approvals, recovering SOL rent, and burning unwanted tokens.

This repository contains an open-source, heavily security-hardened transaction builder for Solana dApps. It is a sanitizer and transaction-packing engine designed for handling batch token account operations safely.

---

## Why this exists

Most Solana dApps build and sign transactions without verifying what they're actually signing at the instruction level. This leaves users exposed to:

- **Supply chain attacks** on npm packages (verified real incident: CVE-2024-54134, $190K stolen)
- **Malicious RPC responses** that inflate balances or redirect destinations
- **Prototype pollution** that silently replaces critical wallet addresses
- **XSS injection** into token/NFT metadata that hijacks transfers

This module addresses all of the above with layered, zero-trust defenses.

---

## Security Architecture

### [CRITICAL-1] Supply Chain Attack — CVE-2024-54134 (CVSS 8.3)
**Real incident:** `@solana/web3.js` v1.95.7 was backdoored on Dec 2, 2024 via spear-phishing of a developer with npm publish access. The backdoor added the `addToQueue` function that exfiltrated private keys via fake CloudFlare headers to `sol-rpc[.]xyz`.

**Fix:** After `createCloseAccountInstruction()` is called, we deserialize the resulting instruction and verify byte-by-byte that:
- `keys[0]` (account to close) matches the expected token account
- `keys[1]` (destination) matches the user's wallet — **the most critical check**
- `keys[2]` (authority) matches the user's wallet

If any check fails, the entire operation aborts immediately before signing.

```typescript
function verifyCloseInstruction(
  ix: TransactionInstruction,
  expectedAccount: PublicKey,
  expectedDestination: PublicKey,
  expectedAuthority: PublicKey
): boolean {
  if (ix.keys.length < 3) return false;
  const destination = ix.keys[1].pubkey;
  if (!destination.equals(expectedDestination)) return false; // abort if tampered
  // ...
}
```

### [CRITICAL-2] Malicious RPC / MITM
A Service Worker, malicious browser extension, or compromised network can substitute the RPC endpoint silently. A fake RPC can return inflated balances, redirect destinations, or provide expired blockhashes.

**Fix:** The Connection object's endpoint is validated against a trusted whitelist using `URL` parsing with suffix-based subdomain matching before any RPC call is made.

### [CRITICAL-3] Prototype Pollution
Attackers that compromise Node.js/npm can set `Object.prototype.toPubkey = attackerWallet`, corrupting address resolution across the entire application.

**Fix:** 
- `Object.freeze()` on all constant arrays and PublicKey objects
- `instanceof PublicKey` for all type checks (duck typing bypasses this protection)

### [CRITICAL-4] XSS → Wallet Drain
If an NFT metadata field or token name contains `<script>` tags and XSS is present, an attacker can replace in-memory fee wallet addresses at runtime.

**Fix:** All critical constants are frozen with `Object.freeze()`. Fee wallet address is resolved from a backend environment variable, not embedded in client-side code.

### [HIGH-5] Account Spoofing
A malicious RPC can inject accounts with inflated lamport values or inject pubkeys belonging to other users.

**Fix:** Every account undergoes on-chain verification before being added to any transaction:
1. Account must exist on-chain
2. Owner must be `TOKEN_PROGRAM_ID` or `TOKEN_2022_PROGRAM_ID`
3. Authority (token account owner) must be `===` `userPubkey`
4. On-chain lamports must not deviate more than 2% from reported value
5. Lamports capped at `5_000_000` — any higher triggers rejection as suspicious

### [HIGH-6] Integer Overflow / Precision Loss
JavaScript's `Number.MAX_SAFE_INTEGER = 2^53 - 1`. Lamport values for wallets with many accounts can exceed this, causing fee calculation errors.

**Fix:** Exclusive use of `BigInt` for all financial calculations. The protocol fee is calculated as:

```typescript
const PROTOCOL_FEE_BPS = 400n;    // 4%
const BPS_DIVISOR      = 10_000n;

const feeLamports = (batchRent * PROTOCOL_FEE_BPS) / BPS_DIVISOR; // pure BigInt
```

### [MEDIUM-7] Dynamic Compute Unit Calibration
Using hardcoded CU limits wastes fees or causes transaction failures.

**Fix:** We simulate a representative transaction on-chain (`calibrateCuPerClose`) to measure actual CUs consumed, then apply a `1.25x` safety buffer. Batch sizes auto-shrink if the serialized transaction exceeds 1,180 bytes.

---

## Integration Guide

### 1. Install dependencies

```bash
npm install @solana/web3.js @solana/spl-token
```

### 2. Pass feeWallet from your backend

```typescript
// In your Edge Route / Worker (server-side)
const feeWallet = new PublicKey(process.env.FEE_WALLET!);
```

Never embed your fee wallet address in client-side code.

### 3. Build the transactions

```typescript
import { buildSecureTransaction } from "./buildSecureTransaction";

const result = await buildSecureTransaction(connection, userPubkey, accounts, {
  feeWallet,           // from backend
  connectedWallet,     // from useWallet()
  useJito: true,
  jitoTipLamports: 10_000n,
});

if (!result.ok) {
  console.error(result.code, result.message);
  return;
}

// result.transactions → VersionedTransaction[] ready to sign & send
```

### 4. Send via wallet adapter (Blowfish/Lighthouse compatible)

```typescript
const { sendTransaction } = useWallet();

for (const tx of result.transactions) {
  const sig = await sendTransaction(tx, connection, {
    skipPreflight: false,
    maxRetries: 3,
  });
  await connection.confirmTransaction(sig, "confirmed");
}
```

> **Why `sendTransaction` over `signTransaction` + `sendRawTransaction`?**  
> Using the wallet adapter's `sendTransaction` allows Blowfish Lighthouse and Phantom's native simulation engine to inspect the transaction before the user signs. Our security checks happen during *construction* (before this call), not during signing — so you get both layers of protection.

---

## Error Codes

| Code | Meaning |
|---|---|
| `WALLET_MISMATCH` | Connected wallet ≠ userPubkey. Possible parameter tampering. |
| `RPC_UNTRUSTED` | RPC endpoint not in the trusted whitelist. |
| `NO_ACCOUNTS` | No valid accounts after input sanitization. |
| `ACCOUNT_VALIDATION_FAILED` | All accounts failed on-chain anti-spoofing validation. |
| `SUPPLY_CHAIN_ALERT` | **Critical:** A generated instruction had a tampered destination. Nothing was signed. |
| `TX_TOO_LARGE` | Transaction exceeds 1,180B safe limit even at batch size 1. |
| `BLOCKHASH_EXPIRED` | Detected via `lastValidBlockHeight` comparison at signing time. |

---

## Trusted RPC Whitelist

```typescript
const ALLOWED_RPC_HOSTS = [
  "api.mainnet-beta.solana.com",
  "helius-rpc.com",        // covers mainnet.helius-rpc.com, staked.helius-rpc.com
  "helius.xyz",            // covers rpc.helius.xyz
  "rpc.ankr.com",
  "g.alchemy.com",         // covers solana-mainnet.g.alchemy.com
  "mainnet.rpc.jito.wtf",
  "api.devnet.solana.com",
  "127.0.0.1", "localhost",
];
```

To add a custom RPC, extend this array. Any endpoint not in the list is rejected before execution.

---

## Design Principles

- **Zero-trust inputs**: Every parameter is validated independently, regardless of origin.
- **Zero-trust libraries**: We verify the output of `createCloseAccountInstruction()` at the instruction level, not at the library API level.
- **Fail-closed**: Any validation failure returns a typed error and aborts — nothing is signed.
- **Immutability by default**: Every critical constant is frozen at module load time.
- **BigInt everywhere**: All financial calculations use BigInt to avoid precision loss.

> *True security does not come from obscurity. It comes from verifiable, auditable code that can withstand public scrutiny.*

---

## License

MIT — use freely, attribution appreciated.

Built with ❤️ by the [SolAudit](https://solaudit.app) team.

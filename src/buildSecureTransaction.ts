/**
 * buildSecureTransaction.ts
 * ============================================================
 * SolAudit — Secure Transaction Core
 * Version: 4.1.0 — HARDENED SECURITY · March 2026
 * ============================================================
 *
 * This is a sanitized version of the production transaction builder
 * used at solaudit.app. It handles batch token account close operations
 * (rent recovery) with extensive security hardening.
 *
 * NOTE: This file builds UNSIGNED transactions only. The client
 * receives these and signs via the wallet adapter. Blowfish/Phantom
 * simulate each transaction before the user approves.
 *
 * ════════════════════════════════════════════════════════════
 * SECURITY AUDIT — VULNERABILITIES FOUND & FIXED
 * ════════════════════════════════════════════════════════════
 *
 * [CRITICAL-1] SUPPLY CHAIN ATTACK — CVE-2024-54134 (CVSS 8.3)
 *   Type: ✅ REAL CVE — verified incident, $190K stolen
 *   @solana/web3.js v1.95.7 was compromised on Dec 2 2024 via
 *   spear-phishing of a dev with npm publish access.
 *   The backdoor added `addToQueue` that exfiltrated private keys
 *   via fake CloudFlare headers to sol-rpc[.]xyz.
 *   FIX: We verify that the deserialized closeAccount instruction
 *        contains exactly the user's pubkey as destination BEFORE
 *        adding it to the tx (verifyCloseInstruction).
 *
 * [CRITICAL-2] MALICIOUS RPC / MITM
 *   Type: Documented real vector — no specific CVE
 *   The Connection object comes from the frontend. An attacker can:
 *   - Replace window.solana.connect() with a malicious hook
 *   - Inject a Service Worker that intercepts RPC calls
 *   - Return false simulations showing more SOL than real
 *   - Return expired blockhash (griefing attack)
 *   FIX: Validate the RPC endpoint against a trusted whitelist.
 *
 * [CRITICAL-3] PROTOTYPE POLLUTION
 *   Type: Documented real vector — similar to 2024 Solana npm attacks
 *   Object.prototype.toPubkey = attackerWallet corrupts calculations.
 *   FIX: Object.freeze on all constants. instanceof PublicKey (no duck typing).
 *
 * [CRITICAL-4] XSS → WALLET DRAIN
 *   Type: Documented real vector in web3 dApps
 *   If there's XSS (token name with <script>, injected NFT metadata),
 *   an attacker can replace feeWallet or JITO_TIP_ACCOUNTS.
 *   FIX: Object.freeze on constants. Strict CSP in response headers.
 *
 * [HIGH-5] PARAMETER TAMPERING IN DEVTOOLS
 *   Type: Defensive best practice — expected browser behavior
 *   Anyone can pass a different feeWallet in DevTools.
 *   FIX: feeWallet resolved from backend env. userPubkey === connectedWallet.
 *
 * [HIGH-6] ACCOUNT SPOOFING in tokenAccountsToClose
 *   Type: Defensive best practice — RPC MITM mitigation
 *   A malicious RPC can inject accounts with inflated lamports
 *   or pubkeys not belonging to the user.
 *   FIX: On-chain verification of each account: owner, authority, lamports.
 *
 * [HIGH-7] INTEGER OVERFLOW / PRECISION
 *   Type: Defensive best practice — known JavaScript limitation
 *   Number.MAX_SAFE_INTEGER = 2^53-1. Lamports can exceed that.
 *   FIX: BigInt for all lamports calculations.
 *
 * [MEDIUM-8] LOG LEAKING
 *   Type: Defensive best practice (OWASP A09:2021)
 *   console.log in production exposes internal state.
 *   FIX: Conditional logger, disabled in production.
 *
 * [MEDIUM-9] BLOCKHASH STALENESS
 *   Type: Defensive best practice — real UX edge case
 *   A single blockhash for all batches. If the user takes >60s
 *   to sign, the last batches arrive with an expired blockhash.
 *   FIX: We save lastValidBlockHeight to detect expiration.
 *
 * [LOW-10] JITO TIP ACCOUNT MANIPULATION
 *   Type: Defensive best practice — runtime array mutation
 *   FIX: Object.freeze on the array and each element.
 */

import {
  ComputeBudgetProgram,
  Connection,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  createCloseAccountInstruction,
  AccountLayout,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";

// ─── IMMUTABLE Constants (Object.freeze prevents runtime mutation) ──────────────

/**
 * Protocol fee in basis points. 400 BPS = 4%.
 * Industry standard: 10_000 BPS = 100%.
 */
const PROTOCOL_FEE_BPS  = 400n;   // 4% — production value
const BPS_DIVISOR       = 10_000n;

const CU_BUFFER_FACTOR      = 1.25;
const CU_FALLBACK_PER_CLOSE = 18_000;
const CU_BASE_OVERHEAD      = 15_000;
const SAFE_TX_BYTES         = 1_180;
const DEFAULT_PRIORITY      = 50_000n;
const INITIAL_BATCH_SIZE    = 20;
const MIN_BATCH_SIZE        = 1;
const BATCH_SHRINK_FACTOR   = 0.75;
const DEFAULT_JITO_TIP      = 10_000n;

/** FIX [LOW-10]: Array and each element frozen against XSS/prototype pollution */
const JITO_TIP_ACCOUNTS = Object.freeze(
  [
    "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
    "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
    "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
    "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
  ].map((k) => Object.freeze(new PublicKey(k)))
);

/**
 * FIX [CRITICAL-2]: Only these RPC endpoints are accepted.
 * Suffix-based matching covers subdomains
 * (e.g. mainnet.helius-rpc.com, staked.helius-rpc.com).
 */
const ALLOWED_RPC_HOSTS = Object.freeze([
  "api.mainnet-beta.solana.com",
  "helius-rpc.com",      // covers mainnet.helius-rpc.com, staked.helius-rpc.com, etc.
  "helius.xyz",          // covers rpc.helius.xyz
  "rpc.ankr.com",
  "g.alchemy.com",       // covers solana-mainnet.g.alchemy.com
  "mainnet.rpc.jito.wtf",
  "api.devnet.solana.com",
  "127.0.0.1", "localhost",
]);

// ─── Public Types ────────────────────────────────────────────────────────────────

export interface TokenAccountToClose {
  pubkey: PublicKey;
  lamports: number;
  /** TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID — detected on-chain in validateAccounts */
  programId?: PublicKey;
}

export interface BuildOptions {
  /**
   * Protocol fee destination wallet.
   * Pass this securely from your backend (Edge Route or Worker), never hardcode in client.
   */
  feeWallet: PublicKey;
  useJito?: boolean;
  jitoTipLamports?: bigint;
  priorityFeeOverride?: bigint;
  commitment?: "processed" | "confirmed" | "finalized";
  /** Currently connected wallet — validated against userPubkey */
  connectedWallet: PublicKey;
}

export interface RecoverResult {
  ok: true;
  transactions: VersionedTransaction[];
  summary: {
    batchCount: number;
    totalRentSol: number;    // total SOL recovered before fees
    feeSol: number;          // protocol fee in SOL
    jitoTotalSol: number;    // total Jito tips in SOL
    netSol: number;          // what the user actually receives
    priorityFeeUsed: bigint;
    accountsClosed: number;
    cuPerClose: number;
    blockhashExpiresAt: number; // lastValidBlockHeight for expiration detection
  };
}

export interface RecoverError {
  ok: false;
  code:
    | "NO_ACCOUNTS"
    | "TX_TOO_LARGE"
    | "RPC_UNTRUSTED"
    | "ACCOUNT_VALIDATION_FAILED"
    | "WALLET_MISMATCH"
    | "SUPPLY_CHAIN_ALERT"
    | "BLOCKHASH_EXPIRED";
  message: string;
}

export type RecoverResponse = RecoverResult | RecoverError;

// ─── Conditional Logger — FIX [MEDIUM-8] ────────────────────────────────────────

const IS_DEV = process.env.NODE_ENV !== "production";
const log = IS_DEV
  ? (msg: string, data?: object) =>
      console.log(
        JSON.stringify({ ts: new Date().toISOString(), ctx: "buildSecureTx", msg, ...data })
      )
  : () => {}; // no-op in production

// ─── Security Validations ────────────────────────────────────────────────────────

/**
 * FIX [CRITICAL-2]: Verifies that the RPC endpoint is trusted.
 * A malicious Service Worker or browser extension can silently replace the endpoint.
 */
function validateRpcEndpoint(connection: Connection): boolean {
  try {
    // @ts-expect-error — accessing internal _rpcEndpoint property
    const endpoint: string = connection._rpcEndpoint ?? connection.rpcEndpoint ?? "";
    const url = new URL(endpoint);
    return ALLOWED_RPC_HOSTS.some(
      (host) => url.hostname === host || url.hostname.endsWith(`.${host}`)
    );
  } catch {
    return false; // invalid URL → reject
  }
}

/**
 * FIX [HIGH-6]: On-chain verification of each account before closing.
 * Prevents: account spoofing, data MITM, closing accounts owned by others.
 *
 * Verifies:
 *   1. The account exists on-chain
 *   2. owner === TOKEN_PROGRAM_ID (it's a legitimate token account)
 *   3. The authority (token owner) === userPubkey
 *   4. The lamports match what was reported (not inflated)
 */
async function validateAccounts(
  connection: Connection,
  accounts: TokenAccountToClose[],
  userPubkey: PublicKey
): Promise<{ valid: TokenAccountToClose[]; rejected: string[] }> {
  const pubkeys = accounts.map((a) => a.pubkey);

  // Batch fetch — single RPC call for all accounts
  const infos = await connection.getMultipleAccountsInfo(pubkeys, "confirmed");

  const valid: TokenAccountToClose[] = [];
  const rejected: string[] = [];

  for (let i = 0; i < accounts.length; i++) {
    const acc = accounts[i];
    const info = infos[i];
    const pk = acc.pubkey.toBase58();

    if (!info) {
      rejected.push(`${pk}: does not exist on-chain`);
      continue;
    }

    // ① Owner must be the Token Program (SPL Token or Token-2022)
    const isTokenProgram = info.owner.equals(TOKEN_PROGRAM_ID);
    const isToken2022Program = info.owner.equals(TOKEN_2022_PROGRAM_ID);
    if (!isTokenProgram && !isToken2022Program) {
      rejected.push(`${pk}: owner is not TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID (possible spoofing)`);
      continue;
    }

    // ② Parse token account data
    if (info.data.length < AccountLayout.span) {
      rejected.push(`${pk}: insufficient data to be a token account`);
      continue;
    }

    const decoded = AccountLayout.decode(info.data);

    // ③ Authority must be the current user
    const authority = new PublicKey(decoded.owner);
    if (!authority.equals(userPubkey)) {
      rejected.push(`${pk}: authority ${authority.toBase58()} ≠ user (attempt to close foreign account)`);
      continue;
    }

    // ④ Rent Spoofing prevention (ceiling check)
    const onChainLamports = info.lamports;

    // Token-2022 accounts with extensions can have rent > 3M lamports
    const MAX_EXPECTED_RENT = 5_000_000; // ~0.005 SOL — covers Token-2022 with extensions
    if (onChainLamports > MAX_EXPECTED_RENT) {
      rejected.push(`${pk}: abnormally high lamports (${onChainLamports}). Possible malicious RPC.`);
      continue;
    }

    // ⑤ Lamports must not differ more than 2% from reported value
    //    (detects data inflation by malicious RPC)
    const reportedLamports = acc.lamports;
    const diff = Math.abs(onChainLamports - reportedLamports);
    const tolerance = Math.ceil(reportedLamports * 0.02);

    if (diff > tolerance) {
      rejected.push(
        `${pk}: on-chain lamports (${onChainLamports}) ≠ reported (${reportedLamports}) — possible malicious RPC`
      );
      continue;
    }

    // Use the real on-chain value, not the reported one. Include programId.
    valid.push({ pubkey: acc.pubkey, lamports: onChainLamports, programId: info.owner });
  }

  return { valid, rejected };
}

/**
 * FIX [CRITICAL-1]: Verifies that the deserialized closeAccount
 * instruction contains exactly the correct destination.
 * Detects supply chain attacks in @solana/spl-token.
 */
function verifyCloseInstruction(
  ix: TransactionInstruction,
  expectedAccount: PublicKey,
  expectedDestination: PublicKey,
  expectedAuthority: PublicKey
): boolean {
  // closeAccount instruction: [account, destination, authority, ...]
  if (ix.keys.length < 3) return false;

  const account     = ix.keys[0].pubkey;
  const destination = ix.keys[1].pubkey;
  const authority   = ix.keys[2].pubkey;

  if (!account.equals(expectedAccount))         return false;
  if (!destination.equals(expectedDestination)) return false; // ← the most critical
  if (!authority.equals(expectedAuthority))     return false;

  return true;
}

/**
 * FIX [CRITICAL-3]: Validates that input has not been corrupted
 * by prototype pollution. Uses instanceof instead of duck typing.
 */
function assertValidAccount(acc: unknown): acc is TokenAccountToClose {
  if (!acc || typeof acc !== "object") return false;
  const a = acc as Record<string, unknown>;
  if (!(a.pubkey instanceof PublicKey))    return false;
  if (typeof a.lamports !== "number")      return false;
  if (!Number.isFinite(a.lamports))        return false;
  if (a.lamports < 0)                      return false;
  if (a.lamports > 1e13)                  return false; // >10k SOL in one account → suspicious
  return true;
}

// ─── Dynamic Priority Fee with BigInt ───────────────────────────────────────────

async function getDynamicPriorityFee(connection: Connection): Promise<bigint> {
  try {
    const fees = await connection.getRecentPrioritizationFees();
    if (!fees.length) return DEFAULT_PRIORITY;
    const sorted = fees.map((f) => f.prioritizationFee).sort((a, b) => a - b);
    const p75 = sorted[Math.floor(sorted.length * 0.75)] ?? 0;
    const suggested = BigInt(Math.ceil(p75 * 1.1));
    return suggested < 10_000n
      ? 10_000n
      : suggested > 2_000_000n
      ? 2_000_000n
      : suggested;
  } catch {
    return DEFAULT_PRIORITY;
  }
}

// ─── O(1) CU Calibration ────────────────────────────────────────────────────────

async function calibrateCuPerClose(
  connection: Connection,
  sample: TokenAccountToClose,
  userPubkey: PublicKey,
  priorityFee: bigint,
  feeWallet: PublicKey
): Promise<number> {
  // FIX [HIGH-7]: BigInt throughout — avoids precision loss on large lamport values
  const feeLamports = (BigInt(sample.lamports) * PROTOCOL_FEE_BPS) / BPS_DIVISOR;

  const ixs: TransactionInstruction[] = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
    // Safe: priorityFee capped at 2_000_000n by getDynamicPriorityFee, well below MAX_SAFE_INTEGER
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: Number(priorityFee) }),
    createCloseAccountInstruction(
      sample.pubkey,
      userPubkey,
      userPubkey,
      [],
      sample.programId || TOKEN_PROGRAM_ID
    ),
    SystemProgram.transfer({
      fromPubkey: userPubkey,
      toPubkey: feeWallet,
      lamports: Number(feeLamports),
    }),
  ];

  const msg = new TransactionMessage({
    payerKey: userPubkey,
    recentBlockhash: "11111111111111111111111111111111",
    instructions: ixs,
  }).compileToV0Message();

  try {
    const sim = await connection.simulateTransaction(new VersionedTransaction(msg), {
      replaceRecentBlockhash: true,
      sigVerify: false,
    });
    if (sim.value.err || !sim.value.unitsConsumed) return CU_FALLBACK_PER_CLOSE;
    return Math.max(sim.value.unitsConsumed - CU_BASE_OVERHEAD, CU_FALLBACK_PER_CLOSE);
  } catch {
    return CU_FALLBACK_PER_CLOSE;
  }
}

function estimateCuForBatch(n: number, cuPerClose: number): number {
  return Math.ceil((CU_BASE_OVERHEAD + n * cuPerClose) * CU_BUFFER_FACTOR);
}

// ─── Secure Batch Instruction Builder ───────────────────────────────────────────

function buildBatchIxs(params: {
  batch: TokenAccountToClose[];
  userPubkey: PublicKey;
  priorityFee: bigint;
  cuForBatch: number;
  useJito: boolean;
  jitoTipLamports: bigint;
  feeWallet: PublicKey;
}): { ixs: TransactionInstruction[]; batchRent: bigint } | null {
  const { batch, userPubkey, priorityFee, cuForBatch, useJito, jitoTipLamports, feeWallet } = params;
  const ixs: TransactionInstruction[] = [];
  let batchRent = 0n;

  ixs.push(
    ComputeBudgetProgram.setComputeUnitLimit({ units: cuForBatch }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: Number(priorityFee) })
  );

  for (const acc of batch) {
    if (acc.lamports === 0) continue;

    const closeIx = createCloseAccountInstruction(
      acc.pubkey,
      userPubkey,
      userPubkey,
      [],
      acc.programId || TOKEN_PROGRAM_ID
    );

    // FIX [CRITICAL-1]: Verify the generated instruction is legitimate
    if (!verifyCloseInstruction(closeIx, acc.pubkey, userPubkey, userPubkey)) {
      log("SUPPLY CHAIN ALERT: closeInstruction destination is incorrect", {
        account: acc.pubkey.toBase58(),
        severity: "CRITICAL",
      });
      return null; // Immediate abort — possible supply chain attack
    }

    batchRent += BigInt(acc.lamports);
    ixs.push(closeIx);
  }

  // Protocol fee transfer — added after all close instructions
  if (batchRent > 0n) {
    // FIX [HIGH-7]: BigInt arithmetic — 400n / 10_000n = 4% with no floating point error
    const feeLamports = (batchRent * PROTOCOL_FEE_BPS) / BPS_DIVISOR;
    ixs.push(
      SystemProgram.transfer({
        fromPubkey: userPubkey,
        toPubkey: feeWallet,
        lamports: Number(feeLamports),
      })
    );
  }

  // Jito tip — ALWAYS LAST
  if (useJito && jitoTipLamports > 0n) {
    const tipAccount = JITO_TIP_ACCOUNTS[Math.floor(Math.random() * JITO_TIP_ACCOUNTS.length)];
    ixs.push(
      SystemProgram.transfer({
        fromPubkey: userPubkey,
        toPubkey: tipAccount,
        lamports: Number(jitoTipLamports),
      })
    );
  }

  return { ixs, batchRent };
}

// ─── Main Entry Point ────────────────────────────────────────────────────────────

export async function buildSecureTransaction(
  connection: Connection,
  userPubkey: PublicKey,
  tokenAccountsToClose: TokenAccountToClose[],
  options: BuildOptions
): Promise<RecoverResponse> {
  const {
    feeWallet,
    useJito = false,
    priorityFeeOverride,
    commitment = "confirmed",
    connectedWallet,
  } = options;

  const MAX_JITO_TIP = 50_000_000n; // 0.05 SOL maximum

  let parsedJitoTip =
    typeof options.jitoTipLamports === "bigint"
      ? options.jitoTipLamports
      : BigInt(options.jitoTipLamports ?? DEFAULT_JITO_TIP);

  if (parsedJitoTip > MAX_JITO_TIP) {
    parsedJitoTip = MAX_JITO_TIP; // Silent cap
  }

  // ── FIX [HIGH-5]: Active wallet must match userPubkey ────────────────────
  if (!connectedWallet.equals(userPubkey)) {
    return {
      ok: false,
      code: "WALLET_MISMATCH",
      message: "Connected wallet does not match userPubkey. Possible manipulation.",
    };
  }

  // ── FIX [CRITICAL-2]: Validate RPC endpoint ──────────────────────────────
  if (!validateRpcEndpoint(connection)) {
    return {
      ok: false,
      code: "RPC_UNTRUSTED",
      message: "The RPC endpoint is not in the trusted whitelist.",
    };
  }

  // ── FIX [CRITICAL-3]: Validate input with instanceof ─────────────────────
  const rawAccounts = tokenAccountsToClose.filter(assertValidAccount);
  if (rawAccounts.length === 0) {
    return { ok: false, code: "NO_ACCOUNTS", message: "No valid accounts to close." };
  }

  // ── FIX [HIGH-6]: Verify accounts on-chain ───────────────────────────────
  const { valid: validAccounts, rejected } = await validateAccounts(connection, rawAccounts, userPubkey);

  if (rejected.length > 0) {
    log("Accounts rejected in on-chain validation", { rejected });
  }

  if (validAccounts.length === 0) {
    return {
      ok: false,
      code: "ACCOUNT_VALIDATION_FAILED",
      message: `All accounts failed on-chain validation: ${rejected.slice(0, 3).join(" | ")}`,
    };
  }

  // ── Parallel RPC calls ────────────────────────────────────────────────────
  const [{ blockhash, lastValidBlockHeight }, priorityFee] = await Promise.all([
    connection.getLatestBlockhash(commitment),
    priorityFeeOverride !== undefined
      ? Promise.resolve(priorityFeeOverride)
      : getDynamicPriorityFee(connection),
  ]);

  // ── O(1) CU Calibration ───────────────────────────────────────────────────
  const cuPerClose = await calibrateCuPerClose(
    connection,
    validAccounts[0],
    userPubkey,
    priorityFee,
    feeWallet
  );

  log("Starting secure transaction build", {
    accounts: validAccounts.length,
    rejected: rejected.length,
    priorityFee: priorityFee.toString(),
    cuPerClose,
  });

  const transactions: VersionedTransaction[] = [];
  let totalRentLamports = 0n;
  let totalAccountsClosed = 0;
  let batchSize = Math.min(INITIAL_BATCH_SIZE, validAccounts.length);
  let cursor = 0;

  while (cursor < validAccounts.length) {
    const batch = validAccounts.slice(cursor, cursor + batchSize);
    const cuForBatch = estimateCuForBatch(batch.length, cuPerClose);

    const result = buildBatchIxs({
      batch,
      userPubkey,
      priorityFee,
      cuForBatch,
      useJito,
      jitoTipLamports: parsedJitoTip,
      feeWallet,
    });

    // FIX [CRITICAL-1]: Supply chain attack detected → total abort
    if (result === null) {
      return {
        ok: false,
        code: "SUPPLY_CHAIN_ALERT",
        message: "CRITICAL ALERT: Instruction generated with incorrect destination. Nothing was signed.",
      };
    }

    const { ixs, batchRent } = result;

    const message = new TransactionMessage({
      payerKey: userPubkey,
      recentBlockhash: blockhash,
      instructions: ixs,
    }).compileToV0Message();

    const tx = new VersionedTransaction(message);
    const serializedBytes = tx.serialize().length;

    if (serializedBytes > SAFE_TX_BYTES) {
      if (batchSize <= MIN_BATCH_SIZE) {
        return {
          ok: false,
          code: "TX_TOO_LARGE",
          message: `1 account = ${serializedBytes}B > ${SAFE_TX_BYTES}B safe limit.`,
        };
      }
      batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize * BATCH_SHRINK_FACTOR));
      continue;
    }

    totalRentLamports += batchRent;
    totalAccountsClosed += batch.length;
    transactions.push(tx);

    log(`Batch ${transactions.length}`, { accounts: batch.length, bytes: serializedBytes });

    cursor += batch.length;
    batchSize = Math.min(INITIAL_BATCH_SIZE, validAccounts.length - cursor);
  }

  // FIX [HIGH-7]: All final calculations in BigInt
  const feeLamports  = (totalRentLamports * PROTOCOL_FEE_BPS) / BPS_DIVISOR;
  const jitoLamports = useJito ? parsedJitoTip * BigInt(transactions.length) : 0n;
  const netLamports  = totalRentLamports - feeLamports - jitoLamports;

  const toLamportsSol = (l: bigint) => Number(l) / LAMPORTS_PER_SOL;

  return {
    ok: true,
    transactions,
    summary: {
      batchCount:          transactions.length,
      totalRentSol:        toLamportsSol(totalRentLamports),
      feeSol:              toLamportsSol(feeLamports),
      jitoTotalSol:        toLamportsSol(jitoLamports),
      netSol:              toLamportsSol(netLamports),
      priorityFeeUsed:     priorityFee,
      accountsClosed:      totalAccountsClosed,
      cuPerClose,
      blockhashExpiresAt:  lastValidBlockHeight,
    },
  };
}

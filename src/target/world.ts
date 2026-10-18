import { DEBUG_MFA } from "../labs/auth";
import { PAN } from "../labs/crypto";
import { ALICE, BOB } from "../labs/idor";
import type { Progress } from "../progress";

/** Starting balance of the shared account. CSRF moves the amount taught in that lab. */
const BALANCE = 1_000_000;
const TRANSFER = 10_000;

const MASKED_CARD = `************${PAN.slice(-4)}`;

export interface WorldOrder {
  id: string;
  item: string;
  price: string;
  card: string;
}

export interface WorldMail {
  subject: string;
  body: string;
}

/** What the shared target app shows, from levels already cleared. */
export interface World {
  account: "alice" | "admin";
  balance: number;
  orders: WorldOrder[];
  mail: WorldMail | null;
  avatarReplaced: boolean;
}

function cleared(progress: Progress, id: string): boolean {
  return (progress[id] ?? []).some((level) => level >= 1 && level <= 4);
}

/**
 * Best confirmed results across labs. The screen being attacked does not
 * read this for its own door; callers hide the matching strip there.
 */
export function worldFromProgress(progress: Progress): World {
  const admin = cleared(progress, "sqli") || cleared(progress, "auth") || cleared(progress, "jwt");
  const card = cleared(progress, "crypto") ? PAN : MASKED_CARD;
  const orders: WorldOrder[] = [{ id: ALICE.id, item: ALICE.item, price: ALICE.price, card }];
  if (cleared(progress, "idor")) {
    orders.push({ id: BOB.id, item: BOB.item, price: BOB.price, card: "—" });
  }
  return {
    account: admin ? "admin" : "alice",
    balance: cleared(progress, "csrf") ? BALANCE - TRANSFER : BALANCE,
    orders,
    mail: (progress.auth ?? []).includes(4) ? { subject: "確認コード", body: DEBUG_MFA } : null,
    avatarReplaced: cleared(progress, "upload"),
  };
}

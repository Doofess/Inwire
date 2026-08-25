/**
 * Assertion tests for agentProtocol.ts's pairing token storage, against an
 * in-memory localStorage stand-in (this runs under plain Node via tsx, which
 * has no DOM/localStorage of its own).
 *
 *   npx tsx scripts/agent-protocol/token-storage.ts
 */
class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string) { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string) { this.store.set(key, value); }
  removeItem(key: string) { this.store.delete(key); }
}
(globalThis as any).localStorage = new MemoryStorage();

const { getStoredPairingToken, storePairingToken, clearStoredPairingToken } = await import('../../src/services/agentProtocol');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

check('no token stored initially', getStoredPairingToken(), null);
storePairingToken('ABCD-1234');
check('stored token is retrievable', getStoredPairingToken(), 'ABCD-1234');
storePairingToken('WXYZ-5678');
check('storing again overwrites', getStoredPairingToken(), 'WXYZ-5678');
clearStoredPairingToken();
check('cleared token is gone', getStoredPairingToken(), null);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');

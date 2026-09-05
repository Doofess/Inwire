/**
 * Learning which program a TLS fingerprint belongs to, from this machine.
 *
 * JA4 identifies the TLS *stack* a client used - its version, cipher list,
 * extension list and ALPN, hashed. Every analyzer can compute one; what none of
 * them can do from a capture alone is say whose it is. The usual answer is a
 * downloaded corpus of fingerprints somebody else labelled, which is a claim
 * about the world rather than about this network.
 *
 * This machine can do better, and only because of process attribution
 * (`services/flowAnnotations.ts`). A ClientHello sent from a socket the
 * operating system says belongs to `chrome.exe` is a labelled example -
 * ground truth, gathered here, about the software actually installed here.
 * Collect enough of them and the *unattributed* hellos become readable: another
 * machine on the segment, or a socket that lived and died inside one poll, can
 * be matched against fingerprints this machine has already accounted for.
 *
 * **It is a match, never an identification.** Two programs sharing a TLS
 * library share a fingerprint - every Electron app carries Chrome's, and
 * anything built on the system schannel or on curl's OpenSSL carries theirs. So
 * a fingerprint seen from two different programs is ambiguous FOREVER after,
 * and this reports nothing for it rather than picking the one it saw first.
 * That is the same rule the socket table follows for a reused port: where the
 * evidence does not decide, say nothing.
 */
import type { ProtocolLayer } from '../../types/packet';

/** What a fingerprint has been seen belonging to. */
interface Sighting {
  /** Distinct process names observed sending this fingerprint. */
  names: Set<string>;
  /** Frames counted, for the tree row to say how well attested a match is. */
  frames: number;
}

export class ClientFingerprintStore {
  private byJa4 = new Map<string, Sighting>();

  /** Bumped on every change, so a consumer can tell new from unchanged. */
  generation = 0;

  clear(): void {
    this.byJa4.clear();
    this.generation += 1;
  }

  /**
   * Records that this fingerprint was sent by this program.
   *
   * Called only for frames the OS actually attributed - a guess learned here
   * would be a guess repeated with growing confidence everywhere else.
   */
  learn(ja4: string, processName: string): void {
    if (!ja4 || !processName) return;
    let sighting = this.byJa4.get(ja4);
    if (!sighting) {
      sighting = { names: new Set(), frames: 0 };
      this.byJa4.set(ja4, sighting);
    }
    sighting.names.add(processName);
    sighting.frames += 1;
    this.generation += 1;
  }

  /**
   * The single program this fingerprint has been seen from, or null.
   *
   * Null when it has never been seen, and null when it has been seen from more
   * than one program - which are different facts to a reader but the same
   * instruction to a renderer: show nothing.
   */
  match(ja4: string): { name: string; frames: number } | null {
    const sighting = this.byJa4.get(ja4);
    if (!sighting || sighting.names.size !== 1) return null;
    const [name] = sighting.names;
    return { name, frames: sighting.frames };
  }

  /** Fingerprints seen from more than one program, for the tree to explain. */
  isAmbiguous(ja4: string): boolean {
    return (this.byJa4.get(ja4)?.names.size ?? 0) > 1;
  }

  /** How many fingerprints have been learned. For the UI, and for tests. */
  get size(): number {
    return this.byJa4.size;
  }
}

export const clientFingerprints = new ClientFingerprintStore();

/**
 * Learns from a frame, or labels it - never both.
 *
 * A frame the OS attributed teaches; a frame it could not attribute is what the
 * teaching is for. Doing both to one frame would let a match feed itself.
 *
 * The label is published as a field so a filter can ask "everything that looks
 * like this browser, wherever it came from" - which on a segment with other
 * machines on it is the question worth asking.
 */
export function learnOrLabelFingerprint(
  fields: Record<string, string | number> | undefined,
  store: ClientFingerprintStore,
  layers?: ProtocolLayer[],
): void {
  if (!fields) return;
  const ja4 = fields['tls.handshake.ja4'];
  if (typeof ja4 !== 'string' || !ja4) return;

  const process = fields['inwire.process.name'];
  if (typeof process === 'string' && process) {
    store.learn(ja4, process);
    return;
  }

  const match = store.match(ja4);
  if (!match) return;
  fields['inwire.process.ja4_match'] = match.name;
  if (layers) addFingerprintRow(layers, match.name, match.frames);
}

/**
 * The tree row for a matched fingerprint.
 *
 * Worded as what it is. "Process: chrome.exe" would be a lie on a frame this
 * machine never sent - the row says *matches*, and its child says how many
 * attributed frames that rests on, so a match resting on one hello reads
 * differently from one resting on four hundred.
 *
 * On the Frame layer rather than beside the JA4 in the TLS tree: the evidence
 * came from this machine's process table, not from the handshake, and putting
 * it under TLS would present it as something the bytes said.
 */
export function addFingerprintRow(layers: ProtocolLayer[], name: string, frames: number): void {
  const frame = layers.find((layer) => layer.name === 'Frame');
  if (!frame) return;
  frame.fields.push({
    name: 'Matches process',
    value: name,
    generated: true,
    abbrev: 'inwire.process.ja4_match',
    children: [{
      name: 'Basis',
      value: `this TLS fingerprint has only been seen from ${name} on this machine`
        + ` (${frames} attributed frame${frames === 1 ? '' : 's'})`,
      generated: true,
    }],
  });
}

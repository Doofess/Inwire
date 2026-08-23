import { CustomDissectorEngine } from './customDissectorEngine';

export class PacketGenerator {
  private packetIdCounter = 1;
  private dissectorEngine: CustomDissectorEngine;

  constructor(dissectorEngine?: CustomDissectorEngine) {
    this.dissectorEngine = dissectorEngine || new CustomDissectorEngine();
  }

  public reset(): void {
    this.packetIdCounter = 1;
  }

  public setDissectorEngine(engine: CustomDissectorEngine): void {
    this.dissectorEngine = engine;
  }

  public getNextId(): number {
    return this.packetIdCounter++;
  }
}

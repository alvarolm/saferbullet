import type { EventHookT } from "@alvarolm/saferbullet/type/manifest";
import type { Hook } from "./types.ts";

export interface EventHookI extends Hook<EventHookT> {
  dispatchEvent(eventName: string, ...args: unknown[]): Promise<unknown[]>;

  listEvents(): string[];
}

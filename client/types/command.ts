import type {
  CommandDef,
  SlashCommandDef,
} from "@alvarolm/saferbullet/type/manifest";

import type { SlashCompletions } from "@alvarolm/saferbullet/type/client";

export type Command = CommandDef & {
  run?: (args?: any[]) => Promise<any>;
  lastRun?: number;
};

export type SlashCommand = SlashCommandDef & {
  run: (...args: any[]) => Promise<SlashCompletions>;
};

export type CommandHookEvents = {
  commandsUpdated(commands: Map<string, Command>): void;
};

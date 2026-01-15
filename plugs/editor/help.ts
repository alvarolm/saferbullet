import { editor } from "@alvarolm/saferbullet/syscalls";
import { publicVersion } from "../../public_version.ts";

export async function versionCommand() {
  await editor.flashNotification(
    `You are currently running SilverBullet ${publicVersion}`,
  );
}

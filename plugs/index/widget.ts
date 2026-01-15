import { codeWidget } from "@alvarolm/saferbullet/syscalls";

export async function refreshWidgets() {
  await codeWidget.refreshAll();
}

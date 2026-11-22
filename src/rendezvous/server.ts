import type { RawData, WebSocket } from "ws";
import { createLogger } from "../logger.js";

const log = createLogger("Rendezvous");

export const RendezvousCloseCode = {
  NORMAL: 1000,
  PROTOCOL_ERROR: 4000,
  INIT_TIMEOUT_REACHED: 4003,
  OTHER_DEVICE_DISCONNECTED: 4004
} as const;

const MAX_EARLY_BUFFERED_FRAMES = 32;
const WS_HEARTBEAT_INTERVAL_MS = 30_000;

interface PendingChannel {
  peerA: WebSocket;
  peerB?: WebSocket;
  bufferedFromA: Array<{ data: RawData; isBinary: boolean }>;
  timer: NodeJS.Timeout;
}

export class RendezvousServer {
  private readonly channels = new Map<string, PendingChannel>();
  private readonly alive = new WeakMap<WebSocket, boolean>();
  private readonly initTimeoutMs = 120_000;
  private readonly heartbeatTimer: NodeJS.Timeout;

  constructor() {
    this.heartbeatTimer = setInterval(() => {
      for (const ch of this.channels.values()) {
        for (const ws of [ch.peerA, ch.peerB]) {
          if (!ws) continue;
          if (this.alive.get(ws) === false) {
            ws.terminate();
            continue;
          }
          this.alive.set(ws, false);
          if (ws.readyState === ws.OPEN) {
            ws.ping();
          }
        }
      }
    }, WS_HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref();
  }

  handleConnection(ws: WebSocket, pathname: string): void {
    const pathHex = pathname.replace(/^\/rendezvous\//, "").replace(/^\/+/, "");
    const shortChan = pathHex.slice(0, 12);
    if (!pathHex) {
      ws.close(RendezvousCloseCode.PROTOCOL_ERROR, "Missing rendezvous path");
      return;
    }

    this.alive.set(ws, true);
    ws.on("pong", () => {
      this.alive.set(ws, true);
    });

    ws.on("error", (err) => {
      log.error(`ws error channel=${shortChan}...: ${err.message}`);
    });

    const existing = this.channels.get(pathHex);
    if (!existing) {
      const timer = setTimeout(() => {
        const current = this.channels.get(pathHex);
        if (current && current.peerA === ws && !current.peerB) {
          this.channels.delete(pathHex);
          ws.close(RendezvousCloseCode.INIT_TIMEOUT_REACHED, "Timed out waiting for peer");
        }
      }, this.initTimeoutMs);
      timer.unref();

      const channel: PendingChannel = {
        peerA: ws,
        bufferedFromA: [],
        timer
      };
      this.channels.set(pathHex, channel);
      log.info(`peerA waiting channel=${shortChan}...`);

      ws.on("message", (data, isBinary) => {
        this.alive.set(ws, true);
        if (channel.peerB) {
          if (channel.peerB.readyState === channel.peerB.OPEN) {
            channel.peerB.send(data, { binary: isBinary });
          }
          return;
        }
        if (channel.bufferedFromA.length < MAX_EARLY_BUFFERED_FRAMES) {
          channel.bufferedFromA.push({ data, isBinary });
        }
      });

      ws.on("close", (code) => {
        log.info(`peerA closed channel=${shortChan}... code=${code}`);
        const current = this.channels.get(pathHex);
        if (!current) return;
        clearTimeout(current.timer);
        if (!current.peerB) {
          this.channels.delete(pathHex);
          return;
        }
        const other = current.peerA === ws ? current.peerB : current.peerA;
        this.channels.delete(pathHex);
        if (other.readyState === other.OPEN) {
          other.close(RendezvousCloseCode.OTHER_DEVICE_DISCONNECTED, "Other device disconnected");
        }
      });
      return;
    }

    if (existing.peerB) {
      ws.close(RendezvousCloseCode.PROTOCOL_ERROR, "Rendezvous channel full");
      return;
    }

    clearTimeout(existing.timer);
    existing.peerB = ws;
    const peerA = existing.peerA;
    const peerB = ws;

    log.info(
      `peerB paired channel=${shortChan}... (flushed ${existing.bufferedFromA.length} early frames)`
    );

    for (const frame of existing.bufferedFromA) {
      if (peerB.readyState === peerB.OPEN) {
        peerB.send(frame.data, { binary: frame.isBinary });
      }
    }
    existing.bufferedFromA.length = 0;

    peerB.on("message", (data, isBinary) => {
      this.alive.set(peerB, true);
      if (peerA.readyState === peerA.OPEN) {
        peerA.send(data, { binary: isBinary });
      }
    });

    peerB.on("close", (code) => {
      log.info(`peerB closed channel=${shortChan}... code=${code}`);
      if (this.channels.get(pathHex) === existing) {
        this.channels.delete(pathHex);
      }
      if (peerA.readyState === peerA.OPEN) {
        peerA.close(RendezvousCloseCode.OTHER_DEVICE_DISCONNECTED, "Other device disconnected");
      }
    });
  }

  getStats(): {
    totalChannels: number;
    waitingChannels: number;
    pairedChannels: number;
  } {
    let waitingChannels = 0;
    let pairedChannels = 0;
    for (const ch of this.channels.values()) {
      if (ch.peerB) pairedChannels++;
      else waitingChannels++;
    }
    return {
      totalChannels: this.channels.size,
      waitingChannels,
      pairedChannels
    };
  }

  closeAll(): void {
    clearInterval(this.heartbeatTimer);
    for (const ch of this.channels.values()) {
      clearTimeout(ch.timer);
      if (ch.peerA.readyState === ch.peerA.OPEN) {
        ch.peerA.close(RendezvousCloseCode.NORMAL, "Server shutting down");
      }
      if (ch.peerB && ch.peerB.readyState === ch.peerB.OPEN) {
        ch.peerB.close(RendezvousCloseCode.NORMAL, "Server shutting down");
      }
    }
    this.channels.clear();
  }
}

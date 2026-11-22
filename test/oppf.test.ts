import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { WebSocket } from "ws";
import { generateLocalTlsBundle } from "../src/crypto/tlsCert.js";
import {
  blake2bMac256,
  boxEncryptShared,
  concatBytes,
  deriveCurve25519PublicKey,
  deriveSharedSecret,
  ed25519Verify
} from "../src/crypto/primitives.js";
import {
  D2mCloseCode,
  D2mPayloadType,
  decodeServerHello,
  decodeServerInfo,
  encodeClientHello,
  encodeClientUrlInfo
} from "../src/d2m/proto.js";
import {
  ADMIN_KEY,
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  WsQueue,
  basicAuthHeader,
  httpsRequest,
  startTestServer
} from "./helpers.js";

describe("OPPF & TLS Provisioning", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("serves and Ed25519-signs OPPF & fallback OPPF with remoteSecret feature toggle", async () => {
    const unauth = await fetch(`${ctx.httpOrigin}/config.oppf`);
    assert.equal(unauth.status, 401);

    const res = await fetch(`${ctx.httpOrigin}/config.oppf`, {
      headers: { authorization: authDemo }
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    const rawOppf = await res.text();

    const lastNl = rawOppf.lastIndexOf("\n");
    assert.ok(lastNl > 0);
    const bodyStr = rawOppf.slice(0, lastNl);
    const sigB64 = rawOppf.slice(lastNl + 1);
    assert.equal(sigB64.length, 88);

    const sig = new Uint8Array(Buffer.from(sigB64, "base64"));
    const pub = ctx.server.keyManager.getOppfPublicKey();
    assert.equal(ed25519Verify(Buffer.from(bodyStr, "utf8"), sig, pub), true);

    const parsed = JSON.parse(bodyStr) as Record<string, any>;
    assert.ok(parsed.version.startsWith("1."));
    assert.equal(parsed.signatureKey, ctx.server.keyManager.getOppfPublicKeyBase64());
    assert.equal(parsed.chat.ports[0], ctx.cspPort);
    assert.equal(parsed.chat.publicKey, ctx.server.keyManager.getCspKeyPair().publicKeyBase64);
    assert.ok(parsed.directory.url.startsWith(ctx.httpOrigin));
    assert.ok(parsed.mediator.url.startsWith(ctx.wsOrigin));
    assert.equal(parsed.features, undefined);

    // Fallback OPPF works without Basic Auth
    const fb = await fetch(`${ctx.httpOrigin}/config.fallback.oppf`);
    assert.equal(fb.status, 200);
    assert.equal(await fb.text(), rawOppf);

    // Enabling remoteSecret via Admin MDM exposes features.remoteSecret in OPPF
    const mdmPut = await fetch(`${ctx.httpOrigin}/admin/mdm`, {
      method: "PUT",
      headers: { "content-type": "application/json", "x-admin-key": ADMIN_KEY },
      body: JSON.stringify({ remoteSecretEnabled: true })
    });
    assert.equal(mdmPut.status, 200);
    const res2 = await fetch(`${ctx.httpOrigin}/config.oppf`, {
      headers: { authorization: authDemo }
    });
    const raw2 = await res2.text();
    const parsed2 = JSON.parse(raw2.slice(0, raw2.lastIndexOf("\n"))) as Record<string, any>;
    assert.deepEqual(parsed2.features, { remoteSecret: {} });
  });

  it("serves verified HTTPS & WSS endpoints with local SAN cert, SPKI pin, and proxy derivation", async () => {
    const tmpCertDir = fs.mkdtempSync(path.join(os.tmpdir(), "threema-tls-"));
    const certPath = path.join(tmpCertDir, "server-fullchain.crt");
    const keyPath = path.join(tmpCertDir, "server.key");
    const bundle = generateLocalTlsBundle({
      dnsNames: ["localhost"],
      ipAddresses: ["127.0.0.1", "::1"]
    });
    fs.writeFileSync(certPath, bundle.fullchainPem, "utf8");
    fs.writeFileSync(keyPath, bundle.serverKeyPem, "utf8");

    const tlsCtx = await startTestServer({
      host: "0.0.0.0",
      cspHost: "localhost",
      tlsEnabled: true,
      tlsCertPath: certPath,
      tlsKeyPath: keyPath,
      tlsPinSpki: true
    });

    try {
      assert.ok(tlsCtx.httpOrigin.startsWith("https://"));
      assert.ok(tlsCtx.wsOrigin.startsWith("wss://"));

      const healthRes = await httpsRequest(bundle.caCertPem, "GET", `${tlsCtx.httpOrigin}/health`);
      assert.equal(healthRes.statusCode, 200);
      assert.deepEqual(JSON.parse(healthRes.body), { ok: true });

      const headOppf = await httpsRequest(bundle.caCertPem, "HEAD", `${tlsCtx.httpOrigin}/config.oppf`, {
        authorization: authDemo
      });
      assert.equal(headOppf.statusCode, 200);

      const headFallback = await httpsRequest(
        bundle.caCertPem,
        "HEAD",
        `${tlsCtx.httpOrigin}/config.fallback.oppf`
      );
      assert.equal(headFallback.statusCode, 200);

      const getOppf = await httpsRequest(bundle.caCertPem, "GET", `${tlsCtx.httpOrigin}/config.oppf`, {
        authorization: authDemo
      });
      assert.equal(getOppf.statusCode, 200);
      const lastNl = getOppf.body.lastIndexOf("\n");
      const bodyStr = getOppf.body.slice(0, lastNl);
      const sigB64 = getOppf.body.slice(lastNl + 1);
      assert.equal(
        ed25519Verify(
          Buffer.from(bodyStr, "utf8"),
          new Uint8Array(Buffer.from(sigB64, "base64")),
          tlsCtx.server.keyManager.getOppfPublicKey()
        ),
        true
      );
      const parsed = JSON.parse(bodyStr) as Record<string, any>;
      assert.equal(parsed.domains.rules.length, 1);
      assert.equal(parsed.domains.rules[0].fqdn, "127.0.0.1");
      assert.equal(parsed.domains.rules[0].matchMode, "exact");
      assert.equal(parsed.domains.rules[0].spkis[0].value, bundle.spkiSha256Base64);

      // Verify wss:// D2M handshake over TLS using trusted CA
      const dgk = new Uint8Array(crypto.randomBytes(32));
      const dgpk = blake2bMac256(dgk, new Uint8Array(0), { personal: "3ma-mdev", salt: "p" });
      const dgid = deriveCurve25519PublicKey(dgpk);
      const urlInfoHex = Buffer.from(
        encodeClientUrlInfo({ deviceGroupId: dgid, serverGroup: "0" })
      ).toString("hex");

      const ws = new WebSocket(`${tlsCtx.wsOrigin}/mediator/${urlInfoHex}`, {
        ca: bundle.caCertPem,
        rejectUnauthorized: true
      });
      const q = new WsQueue(ws);
      await new Promise<void>((resolve, reject) => {
        ws.once("open", resolve);
        ws.once("error", reject);
      });

      const helloMsg = await q.next();
      assert.equal(helloMsg.payloadType, D2mPayloadType.SERVER_HELLO);
      const serverHello = decodeServerHello(helloMsg.payload);
      const nonce = new Uint8Array(crypto.randomBytes(24));
      const shared = deriveSharedSecret(serverHello.esk, dgpk);
      q.send(
        D2mPayloadType.CLIENT_HELLO,
        encodeClientHello({
          version: 0,
          response: concatBytes(nonce, boxEncryptShared(serverHello.challenge, nonce, shared)),
          deviceId: 0x0102030405060708n,
          deviceSlotsExhaustedPolicy: 0,
          deviceSlotExpirationPolicy: 1,
          encryptedDeviceInfo: Buffer.from("tls-dev"),
          expectedDeviceSlotState: 0
        })
      );
      const infoMsg = await q.next();
      assert.equal(infoMsg.payloadType, D2mPayloadType.SERVER_INFO);
      assert.equal(decodeServerInfo(infoMsg.payload).maxDeviceSlots, 8);
      if (ws.readyState === WebSocket.OPEN) ws.close(D2mCloseCode.NORMAL);

      // Verify proxy-aware OPPF derivation with X-Forwarded-* & Host without 304
      const proxyOppfRes = await httpsRequest(
        bundle.caCertPem,
        "GET",
        `${tlsCtx.httpOrigin}/config.oppf`,
        {
          authorization: authDemo,
          "x-forwarded-proto": "https",
          "x-forwarded-host": "onprem.example.test"
        }
      );
      assert.equal(proxyOppfRes.statusCode, 200);
      const proxyNl = proxyOppfRes.body.lastIndexOf("\n");
      const proxyParsed = JSON.parse(proxyOppfRes.body.slice(0, proxyNl)) as Record<string, any>;
      assert.equal(proxyParsed.directory.url, "https://onprem.example.test/directory/");
      assert.equal(proxyParsed.rendezvous.url, "wss://onprem.example.test/rendezvous/");

      const headProvRes = await httpsRequest(
        bundle.caCertPem,
        "HEAD",
        `${tlsCtx.httpOrigin}/prov/config.oppf`,
        {
          authorization: authDemo,
          host: "thr.2sx.me",
          "if-none-match": '"stale-etag"'
        }
      );
      assert.equal(headProvRes.statusCode, 200);
      assert.equal(headProvRes.headers["cache-control"], "no-store");

      const getProvRes = await httpsRequest(
        bundle.caCertPem,
        "GET",
        `${tlsCtx.httpOrigin}/prov/config.oppf`,
        {
          authorization: authDemo,
          host: "thr.2sx.me",
          "if-none-match": "*"
        }
      );
      assert.equal(getProvRes.statusCode, 200);
      assert.equal(getProvRes.headers["cache-control"], "no-store");
      const provNl = getProvRes.body.lastIndexOf("\n");
      const thrParsed = JSON.parse(getProvRes.body.slice(0, provNl)) as Record<string, any>;
      assert.equal(thrParsed.chat.hostname, "thr.2sx.me");
      assert.equal(thrParsed.directory.url, "https://thr.2sx.me/directory/");
      assert.equal(thrParsed.mediator.url, "wss://thr.2sx.me/mediator/");
      assert.equal(thrParsed.rendezvous.url, "wss://thr.2sx.me/rendezvous/");

      // Verify wss://localhost:<port>/rendezvous/... dual-stack TLS WebSocket relay
      const tlsPort = new URL(tlsCtx.wsOrigin).port;
      const rChanHex = crypto.randomBytes(32).toString("hex");
      const rWsA = new WebSocket(`wss://localhost:${tlsPort}/rendezvous/${rChanHex}`, {
        ca: bundle.caCertPem,
        rejectUnauthorized: true
      });
      const rWsB = new WebSocket(`wss://localhost:${tlsPort}/rendezvous/${rChanHex}`, {
        ca: bundle.caCertPem,
        rejectUnauthorized: true
      });
      await Promise.all([
        new Promise<void>((resolve, reject) => {
          rWsA.once("open", resolve);
          rWsA.once("error", reject);
        }),
        new Promise<void>((resolve, reject) => {
          rWsB.once("open", resolve);
          rWsB.once("error", reject);
        })
      ]);
      const rGotB = new Promise<Buffer>((resolve) => {
        rWsB.once("message", (d) => resolve(Buffer.from(d as Buffer)));
      });
      const rPing = Buffer.from([9, 8, 7, 6]);
      rWsA.send(rPing);
      assert.deepEqual(await rGotB, rPing);
      const rClosedB = new Promise<number>((resolve) => {
        rWsB.once("close", (code) => resolve(code));
      });
      rWsA.close(1000);
      assert.equal(await rClosedB, 4004);
    } finally {
      await tlsCtx.stopAndCleanup();
      fs.rmSync(tmpCertDir, { recursive: true, force: true });
    }
  });
});

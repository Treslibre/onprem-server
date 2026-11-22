import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
  computeDirectoryChallengeResponse,
  deriveSharedSecret
} from "../src/crypto/primitives.js";
import {
  DEMO_PASS,
  DEMO_USER,
  type TestServerContext,
  basicAuthHeader,
  createIdentityViaDirectory,
  startTestServer
} from "./helpers.js";

describe("Disk-Backed Blobs, Safe Backups & Avatars", () => {
  let ctx: TestServerContext;
  const authDemo = basicAuthHeader(DEMO_USER, DEMO_PASS);

  before(async () => {
    ctx = await startTestServer();
  });

  after(async () => {
    await ctx.stopAndCleanup();
  });

  it("stores new blobs on disk, preserves legacy DB fallback, and respects usual vs mirror done semantics", async () => {
    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    // Unauthenticated blob_cred challenge-response (Android BlobUploadRequestInterceptor)
    const step1 = await fetch(`${ctx.httpOrigin}/directory/identity/blob_cred`, {
      method: "POST",
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: JSON.stringify({ identity: alice.identity })
    });
    assert.equal(step1.status, 200);
    const ch = (await step1.json()) as { token: string; tokenRespKeyPub: string };
    const resp = computeDirectoryChallengeResponse(
      deriveSharedSecret(new Uint8Array(Buffer.from(ch.tokenRespKeyPub, "base64")), alice.keys.secretKey),
      new Uint8Array(Buffer.from(ch.token, "base64"))
    );
    const step2 = await fetch(`${ctx.httpOrigin}/directory/identity/blob_cred`, {
      method: "POST",
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: JSON.stringify({
        identity: alice.identity,
        token: ch.token,
        response: Buffer.from(resp).toString("base64")
      })
    });
    assert.equal(step2.status, 200);
    const cred = (await step2.json()) as {
      success: boolean;
      token: string;
      expiration: number;
      authToken: string;
      expiresIn: number;
    };
    assert.equal(cred.success, true);
    assert.equal(cred.token, cred.authToken);

    const rawBytes = crypto.randomBytes(2048);
    const form = new FormData();
    form.append("blob", new Blob([rawBytes]), "blob.bin");
    const up = await fetch(`${ctx.httpOrigin}/blob/upload?persist=0`, {
      method: "POST",
      headers: { authorization: `ThreemaBlobToken ${cred.token}` },
      body: form
    });
    assert.equal(up.status, 200);
    const blobId = (await up.text()).trim();
    assert.match(blobId, /^[0-9a-f]{32}$/);

    // Verify stored physically on disk rather than SQLite BlobItem.data
    const diskPath = path.join(ctx.blobDir, blobId.slice(0, 2), blobId);
    assert.equal(fs.existsSync(diskPath), true);
    const row = await ctx.server.prisma.blobItem.findUnique({ where: { id: blobId } });
    assert.equal(row?.size, 2048);
    assert.equal(row?.data.byteLength, 0);

    const dl = await fetch(`${ctx.httpOrigin}/blob/${blobId}`);
    assert.equal(dl.status, 200);
    assert.deepEqual(Buffer.from(await dl.arrayBuffer()), rawBytes);

    // /mediator-blob/:id/done must NOT delete usual blob
    const mediatorDone = await fetch(`${ctx.httpOrigin}/mediator-blob/${blobId}/done`, {
      method: "POST"
    });
    assert.equal(mediatorDone.status, 204);
    assert.equal((await fetch(`${ctx.httpOrigin}/mediator-blob/${blobId}`)).status, 200);

    // /blob/:id/done deletes both DB row and disk file
    const done = await fetch(`${ctx.httpOrigin}/blob/${blobId}/done`, { method: "POST" });
    assert.equal(done.status, 204);
    assert.equal((await fetch(`${ctx.httpOrigin}/blob/${blobId}`)).status, 404);
    assert.equal(fs.existsSync(diskPath), false);

    // Mirror blob with legacy auth_token
    const tokRes = await fetch(`${ctx.httpOrigin}/directory/auth_token`, {
      headers: { authorization: authDemo }
    });
    const { authToken: legacyToken } = (await tokRes.json()) as { authToken: string };
    const form2 = new FormData();
    form2.append("blob", new Blob([rawBytes]), "blob.bin");
    const upMirror = await fetch(
      `${ctx.httpOrigin}/mediator-blob/upload?deviceId=0102030405060708&deviceGroupId=${"aa".repeat(32)}&scope=local&persist=1`,
      {
        method: "POST",
        headers: { authorization: `Token ${legacyToken}` },
        body: form2
      }
    );
    assert.equal(upMirror.status, 200);
    const mirrorId = (await upMirror.text()).trim();
    assert.equal((await fetch(`${ctx.httpOrigin}/mediator-blob/${mirrorId}/done`, { method: "POST" })).status, 204);
    assert.equal((await fetch(`${ctx.httpOrigin}/mediator-blob/${mirrorId}`)).status, 200);

    // Legacy inline SQLite blob fallback (storagePath = null)
    const legacyId = crypto.randomBytes(16).toString("hex");
    const legacyBytes = crypto.randomBytes(512);
    await ctx.server.prisma.blobItem.create({
      data: {
        id: legacyId,
        scope: "usual",
        persist: false,
        storagePath: null,
        size: legacyBytes.byteLength,
        data: new Uint8Array(legacyBytes)
      }
    });
    const legacyDl = await fetch(`${ctx.httpOrigin}/blob/${legacyId}`);
    assert.equal(legacyDl.status, 200);
    assert.deepEqual(Buffer.from(await legacyDl.arrayBuffer()), legacyBytes);
  });

  it("handles Safe backups (with HEAD & Last-Modified) and Avatar PUT/GET/304/DELETE", async () => {
    const alice = await createIdentityViaDirectory(ctx.httpOrigin, authDemo);

    // Avatar PUT, GET, 304, DELETE
    const avatarPng = crypto.randomBytes(256);
    const putAv = await fetch(`${ctx.httpOrigin}/avatar/${alice.identity}`, {
      method: "PUT",
      headers: { authorization: authDemo, "content-type": "image/png" },
      body: avatarPng
    });
    assert.equal(putAv.status, 204);

    const getAv = await fetch(`${ctx.httpOrigin}/avatar/${alice.identity}`);
    assert.equal(getAv.status, 200);
    assert.ok(getAv.headers.get("etag"));
    assert.ok(getAv.headers.get("last-modified"));
    assert.deepEqual(Buffer.from(await getAv.arrayBuffer()), avatarPng);

    const av304 = await fetch(`${ctx.httpOrigin}/avatar/${alice.identity}`, {
      headers: { "if-none-match": getAv.headers.get("etag")! }
    });
    assert.equal(av304.status, 304);

    const delAv = await fetch(`${ctx.httpOrigin}/avatar/${alice.identity}`, {
      method: "DELETE",
      headers: { authorization: authDemo }
    });
    assert.equal(delAv.status, 204);
    assert.equal((await fetch(`${ctx.httpOrigin}/avatar/${alice.identity}`)).status, 404);

    // Safe backups + HEAD + Last-Modified
    const safeCfg = await fetch(`${ctx.httpOrigin}/safe/config`, {
      headers: { authorization: authDemo }
    });
    assert.equal(safeCfg.status, 200);
    assert.ok(((await safeCfg.json()) as any).maxBackupBytes > 0);

    const backupId = crypto.randomBytes(32).toString("hex");
    const backupData = crypto.randomBytes(512);
    const putSafe = await fetch(`${ctx.httpOrigin}/safe/backups/${backupId}`, {
      method: "PUT",
      headers: { authorization: authDemo, "content-type": "application/octet-stream" },
      body: backupData
    });
    assert.equal(putSafe.status, 200);

    const headSafe = await fetch(`${ctx.httpOrigin}/safe/backups/${backupId}`, {
      method: "HEAD",
      headers: { authorization: authDemo }
    });
    assert.equal(headSafe.status, 200);
    assert.ok(headSafe.headers.get("last-modified"));
    assert.ok(headSafe.headers.get("etag"));
    assert.equal(headSafe.headers.get("content-length"), "512");

    const getSafe = await fetch(`${ctx.httpOrigin}/safe/backups/${backupId}`, {
      headers: { authorization: authDemo }
    });
    assert.equal(getSafe.status, 200);
    assert.deepEqual(Buffer.from(await getSafe.arrayBuffer()), backupData);

    const delSafe = await fetch(`${ctx.httpOrigin}/safe/backups/${backupId}`, {
      method: "DELETE",
      headers: { authorization: authDemo }
    });
    assert.equal(delSafe.status, 200);
    assert.equal(
      (await fetch(`${ctx.httpOrigin}/safe/backups/${backupId}`, { headers: { authorization: authDemo } }))
        .status,
      404
    );
  });
});

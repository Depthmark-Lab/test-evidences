import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { createApp, greeting } from "../src/app.js";

describe("greeting", () => {
  test("greets the world by default", () => {
    assert.equal(greeting(undefined), "Hello, world!");
    assert.equal(greeting("  "), "Hello, world!");
  });
});

describe("web service", () => {
  let server;
  let base;
  before(async () => {
    server = createApp().listen(0);
    await new Promise((resolve) => server.once("listening", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  test("hello answers with json", async () => {
    const response = await fetch(`${base}/hello?name=Talos`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { message: "Hello, Talos!" });
  });

  test("health says ok", async () => {
    assert.deepEqual(await (await fetch(`${base}/health`)).json(), { status: "ok" });
  });
});

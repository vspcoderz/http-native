import { resolve } from "node:path";

const nativeExt =
  process.platform === "darwin"
    ? "dylib"
    : process.platform === "win32"
      ? "dll"
      : "so";
process.env.HTTP_NATIVE_NATIVE_PATH ??= resolve(
  process.cwd(),
  `http-native.release.${nativeExt}`,
);

const { createApp } = await import("../src/index.js");

const db = {
  async getUser(id) {
    return {
      id,
      name: "Ada Lovelace",
      role: "admin",
    };
  },
};

const app = createApp();

app.get("/", (req, res) => {
  res.json({
    ok: true,
    engine: "http-native",
    mode: "static",
  });
});

app.get("/users/:id", async (req, res) => {
  const user = await db.getUser(req.params.id);
  res.json(user);
});

const server = await app.listen({
  port: 3001,
});

console.log(`Server running at ${server.url}`);

// Keep the process alive while benchmarking
setInterval(() => {}, 1 << 30);

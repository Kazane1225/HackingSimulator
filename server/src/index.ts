import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 3000);
const server = createApp();

server.listen(port, "0.0.0.0", () => {
  console.log(`hacklab-server listening on :${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

const payload = JSON.stringify({ payload: "x".repeat(1024 * 1024) });
process.stdout.write(payload);
process.exit(0);

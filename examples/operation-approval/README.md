# Synthetic operation-approval rehearsal

From the repository root, serve the files only on loopback and open the demo in a modern browser:

```sh
python3 -m http.server --bind 127.0.0.1 8000
```

Then visit `http://127.0.0.1:8000/examples/operation-approval/demo.html` to inspect a proposed target/effect, enable the rehearsal, simulate one-time approval and claim, and observe that an uncertain outcome cannot be retried.

This is a static demonstration with hard-coded fake identifiers and browser-memory state. It does not authenticate a user, persist an approval, call New Relic, or perform any operation. The page and module are served over local loopback; the rehearsal logic makes no outbound API/provider requests. The nonce and state are not secure against browser developer tools or page reloads. Do not host this as an approval service or treat its output as authorization. Production writes and destructive operations remain unavailable.

After `npm run build`, run the mock invariants from the repository root with:

```sh
node scripts/test-operation-approval.mjs
node scripts/test-operation-approval-ui.mjs
```

The tests also verify that the production catalog and raw transport continue to reject write policies before any network request.

import {
  MockApprovalStore,
  approveSyntheticProposal,
  cancelSyntheticProposal,
  claimSyntheticProposal,
  createSyntheticProposal,
  markSyntheticOutcomeUnknown,
  readSyntheticProposal,
} from "./rehearsal.mjs";

const store = new MockApprovalStore();
const context = Object.freeze({
  ownerId: "synthetic-owner",
  sessionBinding: "synthetic-browser-session",
  accountId: "demo-account-01",
  region: "us",
  connectionGeneration: 1,
});

const enable = document.querySelector("#enable-rehearsal");
const threshold = document.querySelector("#threshold");
const createButton = document.querySelector("#create");
const approveButton = document.querySelector("#approve");
const claimButton = document.querySelector("#claim");
const unknownButton = document.querySelector("#unknown");
const cancelButton = document.querySelector("#cancel");
const status = document.querySelector("#status");
const summary = document.querySelector("#proposal-summary");

let proposalId = null;
let browserOnlyNonce = null;
let currentState = "empty";
let busy = false;
let enableEpoch = 0;

function syncButtons() {
  const blocked = !enable.checked || busy;
  createButton.disabled = blocked || ["pending", "approved", "claimed"].includes(currentState);
  approveButton.disabled = blocked || currentState !== "pending";
  claimButton.disabled = blocked || currentState !== "approved";
  unknownButton.disabled = blocked || currentState !== "claimed";
  cancelButton.disabled = blocked || !["pending", "approved"].includes(currentState);
}

async function refreshProposal() {
  if (!proposalId) return;
  const visible = await readSyntheticProposal({ store, proposalId, context });
  if (!visible) {
    currentState = "unavailable";
    summary.textContent = "This synthetic proposal is unavailable to the current demo identity.";
    return;
  }
  currentState = visible.state;
  if (["stale", "expired", "cancelled", "claimed", "outcome_unknown", "unavailable"].includes(currentState)) {
    browserOnlyNonce = null;
  }
  summary.textContent = visible.summary + " State: " + visible.state + ". " + visible.effect;
  if (currentState === "claimed") status.textContent = "Simulation claim recorded in page memory. No New Relic or other provider was contacted.";
  if (currentState === "outcome_unknown") status.textContent = "Simulated uncertain outcome. The claim cannot be retried; no provider was contacted.";
  syncButtons();
}

async function reportFailure(prefix, error) {
  const message = prefix + String(error?.code || "invalid state");
  try { await refreshProposal(); } catch { /* keep the safe error message visible */ }
  status.textContent = message;
  syncButtons();
}

enable.addEventListener("change", async () => {
  enableEpoch += 1;
  if (!enable.checked && proposalId && ["pending", "approved"].includes(currentState)) {
    try {
      await cancelSyntheticProposal({ store, proposalId, context });
      browserOnlyNonce = null;
      await refreshProposal();
      status.textContent = "Rehearsal disabled. The pending synthetic approval was invalidated.";
    } catch {
      status.textContent = "Rehearsal disabled. The proposal cannot be changed from this state.";
    }
  } else {
    status.textContent = enable.checked
      ? "Only the local synthetic rehearsal is enabled. Real writes remain unavailable."
      : "Rehearsal controls are off.";
  }
  syncButtons();
});

createButton.addEventListener("click", async () => {
  const requestEpoch = enableEpoch;
  busy = true;
  syncButtons();
  try {
    const numericThreshold = Number(threshold.value);
    const created = await createSyntheticProposal({
      store,
      context,
      enabled: enable.checked,
      args: {
        accountId: "demo-account-01",
        conditionGuid: "demo-condition-01",
        threshold: numericThreshold,
      },
    });
    if (requestEpoch !== enableEpoch || !enable.checked) {
      await cancelSyntheticProposal({ store, proposalId: created.proposalId, context });
      status.textContent = "Rehearsal was disabled before creation completed. The late synthetic proposal was discarded.";
      return;
    }
    proposalId = created.proposalId;
    browserOnlyNonce = created.approvalNonce;
    currentState = "pending";
    status.textContent = "Synthetic proposal created. Review the exact target and effect before the one-time approval simulation.";
    await refreshProposal();
  } catch (error) {
    await reportFailure("Rehearsal stopped safely: ", error);
  } finally {
    busy = false;
    syncButtons();
  }
});

approveButton.addEventListener("click", async () => {
  const requestEpoch = enableEpoch;
  busy = true;
  syncButtons();
  try {
    await approveSyntheticProposal({
      store,
      proposalId,
      context,
      approvalNonce: browserOnlyNonce,
      enabled: enable.checked,
      method: "POST",
      sameOrigin: true,
      csrfValid: true,
      action: "approve_once",
    });
    if (requestEpoch !== enableEpoch || !enable.checked) {
      await cancelSyntheticProposal({ store, proposalId, context });
      browserOnlyNonce = null;
      await refreshProposal();
      status.textContent = "Rehearsal was disabled during approval. The pending synthetic operation was invalidated.";
      return;
    }
    browserOnlyNonce = null;
    status.textContent = "One-time synthetic approval recorded in browser memory only.";
    await refreshProposal();
  } catch (error) {
    await reportFailure("Approval was not recorded: ", error);
  } finally {
    busy = false;
    syncButtons();
  }
});

claimButton.addEventListener("click", async () => {
  const requestEpoch = enableEpoch;
  busy = true;
  syncButtons();
  try {
    const result = await claimSyntheticProposal({
      store,
      proposalId,
      context,
      enabled: enable.checked,
      args: {
        accountId: "demo-account-01",
        conditionGuid: "demo-condition-01",
        threshold: Number(threshold.value),
      },
    });
    if (requestEpoch !== enableEpoch || !enable.checked) {
      await refreshProposal();
      status.textContent = "Rehearsal was disabled during the simulated claim. No provider operation was sent.";
      return;
    }
    status.textContent = result.dispatch === "disabled"
      ? "Single-use claim recorded. Dispatch is not implemented and New Relic was not contacted."
      : "Unexpected rehearsal state.";
    await refreshProposal();
  } catch (error) {
    await reportFailure("Claim stopped safely: ", error);
  } finally {
    busy = false;
    syncButtons();
  }
});

unknownButton.addEventListener("click", async () => {
  busy = true;
  syncButtons();
  try {
    await markSyntheticOutcomeUnknown({ store, proposalId, context });
    status.textContent = "Simulated an unknown result. The claim cannot be retried; no provider was contacted.";
    await refreshProposal();
  } catch (error) {
    await reportFailure("Rehearsal stopped safely: ", error);
  } finally {
    busy = false;
    syncButtons();
  }
});

cancelButton.addEventListener("click", async () => {
  busy = true;
  syncButtons();
  try {
    await cancelSyntheticProposal({ store, proposalId, context });
    browserOnlyNonce = null;
    status.textContent = "Synthetic proposal cancelled. It cannot be approved or claimed.";
    await refreshProposal();
  } catch (error) {
    await reportFailure("Cancellation was not recorded: ", error);
  } finally {
    busy = false;
    syncButtons();
  }
});

syncButtons();

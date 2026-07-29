import { api } from "./api.js";
import {
  $,
  element,
  formatDate,
  formatDuration,
  formatNumber,
  selectedAdapterId,
  setText,
} from "./utils.js";

let status = window.netguardStatus || null;
let adapters = [];

function selectedAdapter() {
  const device = $("#capture-adapter").value || selectedAdapterId(status);
  return adapters.find((adapter) => adapter.device === device);
}

function renderAdapter() {
  const adapter = selectedAdapter();
  setText("#capture-adapter-name", adapter?.friendly_name || adapter?.label);
  setText("#capture-adapter-description", adapter?.description || "No description supplied.");
  setText("#capture-adapter-ipv4", (adapter?.ipv4_addresses || []).join(", ") || "None");
  const ipv6Addresses = adapter?.ipv6_addresses || [];
  setText("#capture-adapter-ipv6-count", `${formatNumber(ipv6Addresses.length)} ${ipv6Addresses.length === 1 ? "address" : "addresses"}`);
  setText("#capture-adapter-ipv6", ipv6Addresses.join(", ") || "None");
  setText("#capture-adapter-availability", adapter ? (adapter.is_up === false ? "Unavailable" : "Available") : "Select an adapter");
  setText("#capture-page-interface", adapter?.device || selectedAdapterId(status));
  setText("#capture-page-adapter", adapter?.friendly_name || adapter?.label);
  const ready = adapter && adapter.is_up !== false && ((adapter.ipv4_addresses || []).length || (adapter.ipv6_addresses || []).length);
  if (status?.state === "running") {
    setText("#capture-readiness", "Capture is active.");
  } else {
    setText("#capture-readiness", ready ? "Ready to start capture." : "Select an available adapter with an IPv4 or IPv6 address.");
  }
}

function applyStatus(nextStatus) {
  status = nextStatus;
  const state = status?.state || "unknown";
  const stateLabel = state.replaceAll("_", " ").replace(/^\w/, (letter) => letter.toUpperCase());
  setText("#capture-page-state", stateLabel);
  setText("#capture-page-error", status?.last_error || "", "");
  setText("#capture-page-started", status?.started_at ? formatDate(status.started_at) : "Not started");
  setText("#capture-page-duration", status?.started_at ? formatDuration(status.started_at) : "—");
  setText("#capture-page-packets", formatNumber(status?.packet_count));
  setText("#capture-page-alerts", formatNumber(status?.alert_count));
  setText("#capture-page-dropped", formatNumber(status?.dropped_packets));
  setText("#capture-page-mode", status?.development_mode ? "Development" : "Normal");
  const changingState = ["starting", "stopping", "shutting_down"].includes(state);
  const locked = changingState || state === "running";
  $("#capture-start").disabled = locked;
  $("#capture-stop").disabled = state !== "running";
  $("#capture-adapter").disabled = locked;
  $("#capture-development-mode").disabled = locked;
  const lockedTooltip = locked ? "Stop capture before changing this setting." : "";
  $("#capture-adapter").title = lockedTooltip;
  $("#capture-development-mode").title = lockedTooltip;
  $("#capture-adapter").closest(".field").title = lockedTooltip;
  $("#capture-development-mode").closest(".switch-row").title = lockedTooltip;
  if (locked) $("#capture-development-mode").checked = Boolean(status.development_mode);
  $("#capture-quality-warning").hidden = !(Number(status?.dropped_packets) > 0);
  $("#capture-orb").className = `capture-orb ${state === "running" ? "capture-orb--running" : state === "error" ? "capture-orb--error" : "capture-orb--unknown"}`;
  renderAdapter();
}

async function loadAdapters() {
  try {
    adapters = await api.interfaces();
    window.netguardInterfaceNames = Object.fromEntries(
      adapters.map((adapter) => [adapter.device, adapter.friendly_name || adapter.label || "Network adapter"]),
    );
    const select = $("#capture-adapter");
    const nodes = [element("option", "", "Select an adapter")];
    nodes[0].value = "";
    adapters.forEach((adapter) => {
      const option = element("option", "", adapter.friendly_name || adapter.label);
      option.value = adapter.device;
      option.disabled = adapter.is_up === false;
      nodes.push(option);
    });
    select.replaceChildren(...nodes);
    select.value = selectedAdapterId(status);
    if (!adapters.length) {
      setText("#capture-page-error", "No usable adapters were found. Verify Npcap and network connectivity.");
    }
    renderAdapter();
  } catch (error) {
    setText("#capture-page-error", error.message);
  }
}

async function start() {
  const interfaceId = $("#capture-adapter").value;
  const development = $("#capture-development-mode").checked;
  if (!interfaceId) {
    setText("#capture-page-error", "Select an available adapter before starting capture.");
    return;
  }
  if (development && !window.confirm("Development Mode lowers detection thresholds and may create additional alerts. Continue?")) return;
  localStorage.setItem("netguard.selectedAdapter", interfaceId);
  $("#capture-start").disabled = true;
  try {
    const result = await api.startCapture(interfaceId, development);
    applyStatus(result.status);
  } catch (error) {
    setText("#capture-page-error", error.message);
  }
}

async function stop() {
  $("#capture-stop").disabled = true;
  try {
    const result = await api.stopCapture();
    applyStatus(result.status);
  } catch (error) {
    setText("#capture-page-error", error.message);
  }
}

document.addEventListener("netguard:status", (event) => applyStatus(event.detail));
$("#capture-adapter").addEventListener("change", renderAdapter);
$("#capture-start").addEventListener("click", start);
$("#capture-stop").addEventListener("click", stop);
$("#capture-copy-interface").addEventListener("click", async () => {
  const value = $("#capture-page-interface").textContent;
  if (value && value !== "—") await navigator.clipboard.writeText(value);
});
$("#capture-development-mode").checked = localStorage.getItem("netguard.developmentModeDefault") === "true";
loadAdapters();

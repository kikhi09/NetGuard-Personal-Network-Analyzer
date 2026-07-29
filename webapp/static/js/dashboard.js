import { api } from "./api.js";
import { renderDonut } from "./charts.js";
import {
  $,
  badge,
  createPoller,
  element,
  endpoint,
  formatBytes,
  formatDuration,
  formatNumber,
  formatTime,
  relativeTime,
  replaceChildren,
  safetyClassification,
  safetyScoreFromRisk,
  selectedAdapterId,
  setPanelState,
  setText,
  showAlertDetails,
  tcpFlagsLabel,
} from "./utils.js";

let currentStatus = window.netguardStatus || null;
let interfaces = [];

function cell(value, className = "") {
  return element("td", className, value ?? "—");
}

function toneForState(state) {
  if (state === "running") return "success";
  if (state === "error") return "danger";
  if (["starting", "stopping", "shutting_down"].includes(state)) return "warning";
  return "unknown";
}

function stateLabel(state) {
  return String(state || "unknown")
    .replaceAll("_", " ")
    .replace(/^\w/, (letter) => letter.toUpperCase());
}

function selectedInterface(status = currentStatus) {
  const device = selectedAdapterId(status);
  return interfaces.find((item) => item.device === device);
}

function applyStatus(status) {
  if (!status) return;
  currentStatus = status;
  const state = status.state || "unknown";
  setText("#summary-state", stateLabel(state));
  setText("#summary-duration", status.started_at ? formatDuration(status.started_at) : "0s");
  setText("#summary-session", status.active_session_id || status.last_session_id
    ? "Current Session"
    : "No current session");
  const adapter = selectedInterface(status);
  setText("#summary-adapter", adapter?.friendly_name || adapter?.label || "No adapter selected");
  setText("#stat-total-packets", formatNumber(status.packet_count));
  setText("#stat-alerts", formatNumber(status.alert_count));
  setText("#stat-dropped", formatNumber(status.dropped_packets));
  const dot = $("#summary-state-dot");
  if (dot) dot.className = `status-dot status-dot--${toneForState(state)}`;
  updateAdapter();
}

async function refreshStatistics() {
  const statistics = await api.statistics();
  setText("#summary-pps", formatNumber(statistics.packet_rate, 2));
  setText("#stat-pps", formatNumber(statistics.packet_rate, 2));
  const bytes = statistics.direction_byte_counts || {};
  setText("#stat-inbound-bytes", formatBytes(bytes.inbound || 0));
  setText("#stat-outbound-bytes", formatBytes(bytes.outbound || 0));
  renderDonut(
    $("#direction-chart"),
    $("#direction-legend"),
    statistics.direction_counts || {},
    "#direction-chart-total",
  );
  renderDonut(
    $("#protocol-chart"),
    $("#protocol-legend"),
    statistics.protocol_counts || {},
    "#protocol-chart-total",
  );
}

async function refreshRisk() {
  const result = await api.risk();
  const risk = Math.max(0, Math.min(100, Number(result.percentage) || 0));
  const safetyScore = safetyScoreFromRisk(risk);
  const classification = safetyClassification(risk);
  setText("#safety-percentage", `${formatNumber(safetyScore)}%`);
  setText("#safety-status", classification.label);
  setText("#risk-updated", formatTime(result.updated_at));
  const severity = result.severity_counts || {};
  setText("#risk-high", formatNumber(severity.HIGH || 0));
  setText("#risk-medium", formatNumber(severity.MEDIUM || 0));
  setText("#risk-low", formatNumber(severity.LOW || 0));
  setText("#risk-info", formatNumber(severity.INFO || 0));
  setText("#summary-alerts", formatNumber(result.alert_rows || 0));
  const statuses = result.status_counts || {};
  setText("#summary-unacknowledged", formatNumber(statuses.new || 0));
  setText("#risk-new", formatNumber(statuses.new || 0));
  setText("#risk-acknowledged", formatNumber(statuses.acknowledged || 0));
  setText("#risk-resolved", formatNumber(statuses.resolved || 0));
  setText("#risk-ignored", formatNumber(statuses.ignored || 0));
  const ring = $("#safety-ring");
  if (ring) {
    ring.style.setProperty("--risk-value", `${safetyScore * 3.6}deg`);
    ring.dataset.tone = classification.tone;
    ring.setAttribute("aria-valuenow", String(safetyScore));
    ring.setAttribute("aria-valuetext", `${safetyScore}% — ${classification.label}`);
  }
}

function updateAdapter() {
  const adapter = selectedInterface();
  if (!adapter) {
    setPanelState("dashboard-adapter", "empty", "No adapter is selected.");
    $("#dashboard-adapter-content").hidden = true;
    return;
  }
  setPanelState("dashboard-adapter", "ready");
  $("#dashboard-adapter-content").hidden = false;
  setText("#adapter-name", adapter.friendly_name || adapter.label);
  setText("#adapter-description", adapter.description || "No description supplied.");
  setText("#adapter-ipv4", (adapter.ipv4_addresses || []).join(", ") || "None");
  const ipv6Count = (adapter.ipv6_addresses || []).length;
  setText("#adapter-ipv6", `${formatNumber(ipv6Count)} ${ipv6Count === 1 ? "address" : "addresses"}`);
  setText("#adapter-device", adapter.device);
  $("#adapter-device").title = adapter.device;
  const status = $("#adapter-status");
  status.textContent = adapter.is_up === false ? "Unavailable" : "Available";
  status.className = `status-badge status-badge--${adapter.is_up === false ? "danger" : "success"}`;
}

async function refreshInterfaces() {
  try {
    interfaces = await api.interfaces();
    window.netguardInterfaceNames = Object.fromEntries(
      interfaces.map((item) => [item.device, item.friendly_name || item.label || "Network adapter"]),
    );
    updateAdapter();
    if (currentStatus) applyStatus(currentStatus);
  } catch (error) {
    setPanelState("dashboard-adapter", "error", error.message);
  }
}

function renderAlerts(alerts) {
  const visible = alerts.slice(0, 5);
  if (!visible.length) {
    setPanelState("dashboard-alerts", "empty", "No active alerts.");
    $("#dashboard-alert-list").hidden = true;
    return;
  }
  setPanelState("dashboard-alerts", "ready");
  const list = $("#dashboard-alert-list");
  list.hidden = false;
  const nodes = visible.map((alert) => {
    const item = element("article", "alert-item");
    const main = element("div", "alert-item__main");
    const location = alert.rule_id === "NG-TRAFFIC-SPIKE"
      ? "Entire network adapter · Combined inbound and outbound"
      : `${endpoint(alert.source_ip, alert.source_port)} → ${endpoint(alert.target_ip || alert.destination_ip, alert.destination_port)}`;
    main.append(
      element("h3", "", alert.display_title || "Unusual Network Activity"),
      element("p", "", location),
      element("small", "", `${relativeTime(alert.last_seen || alert.timestamp)} · ${formatNumber(alert.occurrence_count || 1)} occurrence(s) · ${alert.status || "new"}`),
    );
    const actions = element("div", "alert-actions");
    const details = element("button", "button button--secondary button--small", "Details");
    details.type = "button";
    details.addEventListener("click", () => showAlertDetails(alert));
    actions.append(details);
    if ((alert.status || "new") === "new" && alert.id) {
      const acknowledge = element("button", "button button--secondary button--small", "Acknowledge");
      acknowledge.type = "button";
      acknowledge.addEventListener("click", async () => {
        acknowledge.disabled = true;
        try {
          await api.setAlertStatus(alert.id, "acknowledged");
          await Promise.all([refreshAlerts(), refreshRisk()]);
          document.dispatchEvent(new CustomEvent("netguard:risk-refresh"));
        } catch (error) {
          setPanelState("dashboard-alerts", "error", error.message);
        }
      });
      actions.append(acknowledge);
    }
    item.append(badge(alert.severity, "severity"), main, actions);
    return item;
  });
  replaceChildren(list, nodes);
}

async function refreshAlerts() {
  try {
    const result = await api.alerts({ limit: 500 });
    renderAlerts(result.items || []);
  } catch (error) {
    setPanelState("dashboard-alerts", "error", error.message);
  }
}

function renderPackets(packets) {
  if (!packets.length) {
    setPanelState("dashboard-packets", "empty", "No packet records match the current session.");
    $("#dashboard-packets-content").hidden = true;
    return;
  }
  setPanelState("dashboard-packets", "ready");
  $("#dashboard-packets-content").hidden = false;
  const rows = packets.map((packet) => {
    const row = element("tr");
    const direction = element("td");
    direction.append(badge(packet.direction, "direction"));
    const flags = element("td");
    flags.append(tcpFlagsLabel(packet.tcp_flags));
    row.append(
      cell(formatTime(packet.timestamp)),
      cell(packet.src_ip, "mono"),
      cell(packet.src_port),
      cell(packet.dst_ip, "mono"),
      cell(packet.dst_port),
      cell(packet.protocol),
      cell(formatBytes(packet.length)),
      direction,
      cell(packet.ip_version ? `IPv${packet.ip_version}` : "—"),
      flags,
    );
    return row;
  });
  replaceChildren($("#dashboard-packets-body"), rows);
}

async function refreshPackets() {
  try {
    const result = await api.packets({ limit: 15 });
    renderPackets(result.items || []);
  } catch (error) {
    setPanelState("dashboard-packets", "error", error.message);
  }
}

document.addEventListener("netguard:status", (event) => applyStatus(event.detail));
$("#copy-adapter")?.addEventListener("click", async () => {
  const device = $("#adapter-device")?.textContent;
  if (device && device !== "—") await navigator.clipboard.writeText(device);
});

refreshInterfaces();
createPoller(async () => {
  await Promise.all([refreshStatistics(), refreshRisk(), refreshPackets()]);
}, 2000);
createPoller(refreshAlerts, 3000);

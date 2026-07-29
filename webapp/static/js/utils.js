export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

export function element(tagName, className = "", text = null) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

export function replaceChildren(node, children = []) {
  node?.replaceChildren(...children.filter(Boolean));
}

export function setText(selectorOrNode, value, fallback = "—") {
  const node = typeof selectorOrNode === "string" ? $(selectorOrNode) : selectorOrNode;
  if (node) node.textContent = value === null || value === undefined || value === "" ? fallback : String(value);
}

export function formatNumber(value, maximumFractionDigits = 0) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits }).format(number);
}

export function formatBytes(value, perSecond = false) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = Math.max(0, number);
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const precision = amount >= 100 || unit === 0 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(precision)} ${units[unit]}${perSecond ? "/s" : ""}`;
}

export function formatBitsPerSecond(bytesPerSecond) {
  const bytes = Number(bytesPerSecond);
  if (!Number.isFinite(bytes)) return "—";
  const bits = bytes * 8;
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(2)} Gbps`;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(2)} Mbps`;
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bits)} bps`;
}

export function formatDate(value, includeSeconds = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: includeSeconds ? "medium" : "short",
  }).format(date);
}

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(date);
}

export function formatDateOnly(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

export function formatShortTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { timeStyle: "short" }).format(date);
}

export function relativeTime(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  if (!Number.isFinite(seconds)) return "Unknown time";
  const absolute = Math.abs(seconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absolute < 60) return formatter.format(seconds, "second");
  if (absolute < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (absolute < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}

export function formatDuration(start, end = null) {
  if (!start) return "—";
  const startTime = new Date(start).getTime();
  const endTime = end ? new Date(end).getTime() : Date.now();
  if (!Number.isFinite(startTime) || !Number.isFinite(endTime)) return "—";
  let seconds = Math.max(0, Math.floor((endTime - startTime) / 1000));
  const hours = Math.floor(seconds / 3600);
  seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  seconds %= 60;
  return [hours && `${hours}h`, minutes && `${minutes}m`, `${seconds}s`].filter(Boolean).join(" ");
}

export function endpoint(ip, port) {
  if (!ip) return "—";
  return port === null || port === undefined ? ip : `${ip}:${port}`;
}

export function tcpFlagsDisplay(value) {
  const technical = String(value || "").toUpperCase();
  const compact = technical.replaceAll(",", "").replaceAll(" ", "");
  const labels = {
    S: "Start",
    SA: "Accepted",
    A: "Acknowledged",
    PA: "Data transfer",
    FA: "Closing",
    R: "Reset",
    RA: "Reset",
  };
  const expanded = {
    S: "SYN",
    SA: "SYN, ACK",
    A: "ACK",
    PA: "PSH, ACK",
    FA: "FIN, ACK",
    R: "RST",
    RA: "RST, ACK",
  };
  return {
    label: labels[compact] || (technical ? `Other (${technical})` : "Not applicable"),
    tooltip: technical
      ? `TCP flags: ${expanded[compact] || technical} (technical value: ${technical})`
      : "No TCP flags",
  };
}

export function tcpFlagsLabel(value) {
  const display = tcpFlagsDisplay(value);
  const node = element("span", "tcp-flags-label", display.label);
  node.title = display.tooltip;
  node.setAttribute("aria-label", `${display.label}. ${display.tooltip}`);
  return node;
}

export function badge(text, kind = "status") {
  const normalized = String(text || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const node = element("span", `${kind}-badge ${kind}-badge--${normalized}`, text || "Unknown");
  return node;
}

export function setPanelState(prefix, state, message = null) {
  const container = $(`#${prefix}-state`);
  if (!container) return;
  $$("[data-state]", container).forEach((node) => {
    node.hidden = node.dataset.state !== state;
  });
  if (message) {
    const active = $(`[data-state="${state}"]`, container);
    if (active) active.textContent = message;
  }
  container.hidden = state === "ready";
}

export function scoreClassification(score) {
  const number = Number(score);
  if (!Number.isFinite(number)) return { label: "Unknown", tone: "unknown" };
  if (number >= 85) return { label: "Good", tone: "success" };
  if (number >= 70) return { label: "Fair", tone: "info" };
  if (number >= 50) return { label: "Warning", tone: "warning" };
  return { label: "Critical", tone: "danger" };
}

export function riskClassification(risk) {
  const number = Number(risk);
  if (!Number.isFinite(number)) return { label: "Unknown", tone: "unknown" };
  if (number < 20) return { label: "Safe", tone: "success" };
  if (number < 40) return { label: "Normal", tone: "info" };
  if (number < 60) return { label: "Moderate", tone: "warning" };
  if (number < 80) return { label: "High Risk", tone: "orange" };
  return { label: "Critical", tone: "danger" };
}

export function safetyScoreFromRisk(risk) {
  const number = Number(risk);
  if (!Number.isFinite(number)) return null;
  return 100 - Math.max(0, Math.min(100, number));
}

export function safetyClassification(risk) {
  const number = Number(risk);
  if (!Number.isFinite(number)) return { label: "Unknown", tone: "unknown" };
  if (number <= 0) return { label: "No active risk detected", tone: "success" };
  if (number < 40) return { label: "Low concern", tone: "info" };
  if (number < 60) return { label: "Moderate concern", tone: "warning" };
  if (number < 80) return { label: "High concern", tone: "orange" };
  return { label: "Critical concern", tone: "danger" };
}

export function createPoller(callback, interval = 2000) {
  let timer = null;
  let running = false;
  let stopped = false;
  const run = async () => {
    if (stopped || running || document.hidden) return;
    running = true;
    try {
      await callback();
    } catch (error) {
      if (error.name !== "AbortError") console.warn("NetGuard refresh failed:", error.message);
    } finally {
      running = false;
    }
  };
  const visibility = () => {
    if (!document.hidden) run();
  };
  document.addEventListener("visibilitychange", visibility);
  run();
  timer = window.setInterval(run, interval);
  return {
    refresh: run,
    stop() {
      stopped = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", visibility);
    },
  };
}

export function configurePagination(container, state, onChange) {
  if (!container) return;
  const previous = $('[data-page-action="previous"]', container);
  const next = $('[data-page-action="next"]', container);
  const label = $("[data-page-label]", container);
  const update = (itemCount = 0) => {
    const page = Math.floor(state.offset / state.limit) + 1;
    label.textContent = `Page ${page}`;
    previous.disabled = state.offset === 0;
    next.disabled = itemCount < state.limit;
  };
  previous.addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    onChange();
  });
  next.addEventListener("click", () => {
    state.offset += state.limit;
    onChange();
  });
  return update;
}

function appendDetail(list, label, value) {
  const wrapper = element("div");
  wrapper.append(element("dt", "", label), element("dd", "", value ?? "—"));
  list.append(wrapper);
}

function disclosure(title, children, open = false) {
  const details = element("details", "alert-detail-section");
  details.open = open;
  details.append(element("summary", "", title));
  const content = element("div", "alert-detail-section__content");
  content.append(...children);
  details.append(content);
  return details;
}

function friendlyInterfaceName(interfaceId) {
  return window.netguardInterfaceNames?.[interfaceId] || "Network adapter";
}

function trafficSpikeEvidence(alert) {
  const evidence = alert.evidence || {};
  const list = element("dl", "detail-grid");
  appendDetail(list, "Normal rate", Number.isFinite(Number(evidence.baseline_packets_per_second))
    ? `about ${formatNumber(Math.round(Number(evidence.baseline_packets_per_second)))} packets/second`
    : "Unavailable");
  appendDetail(list, "Observed rate", Number.isFinite(Number(evidence.observed_packets_per_second))
    ? `about ${formatNumber(Math.round(Number(evidence.observed_packets_per_second)))} packets/second`
    : "Unavailable");
  appendDetail(list, "Increase", Number.isFinite(Number(evidence.observed_multiplier))
    ? `about ${formatNumber(Number(evidence.observed_multiplier), 1)}× normal`
    : "Unavailable");
  appendDetail(list, "Baseline samples", formatNumber(evidence.baseline_observations));
  return list;
}

export function showAlertDetails(alert, options = { focus: true }) {
  const modal = $("#details-modal");
  const body = $("#modal-body");
  if (options.focus !== false) window.netguardModalReturnFocus = document.activeElement;
  setText("#modal-title", alert.display_title || "Unusual Network Activity");
  const isTrafficSpike = alert.rule_id === "NG-TRAFFIC-SPIKE"
    || alert.alert_type === "TRAFFIC_SPIKE";
  const heading = element("div", "modal-summary");
  heading.append(badge(alert.severity, "severity"));
  const summary = element("dl", "detail-grid");
  if (isTrafficSpike) {
    appendDetail(summary, "Scope", "Entire network adapter");
    appendDetail(summary, "Traffic", "Combined inbound and outbound");
    appendDetail(summary, "Adapter", friendlyInterfaceName(alert.interface_id));
  } else {
    appendDetail(summary, "Source", endpoint(alert.source_ip, alert.source_port));
    appendDetail(summary, "Destination", endpoint(alert.target_ip || alert.destination_ip, alert.destination_port));
    appendDetail(summary, "Direction", alert.direction);
    appendDetail(summary, "Adapter", friendlyInterfaceName(alert.interface_id));
  }
  appendDetail(summary, "First seen", formatDate(alert.timestamp));
  appendDetail(summary, "Last seen", formatDate(alert.last_seen || alert.timestamp));
  appendDetail(summary, "Occurrences", formatNumber(alert.occurrence_count || 1));

  const why = element("p", "", alert.description || "No explanation is available.");
  const normal = element("div");
  const normalList = element("ul", "feature-list");
  (alert.possible_normal_causes || ["No specific normal causes are available."]).forEach((cause) => {
    normalList.append(element("li", "", cause));
  });
  normal.append(normalList);
  const recommendation = element("p", "", alert.recommendation || "Review the event in context before taking action.");
  const timeline = element("ol", "incident-timeline");
  (alert.timeline || []).forEach((event) => {
    const item = element("li");
    item.append(
      element("time", "", formatDate(event.timestamp)),
      element("strong", "", (event.details || event.event_type || "Activity").replaceAll("_", " ")),
    );
    if (event.occurrence_count) item.append(element("small", "", `Occurrence ${event.occurrence_count}`));
    timeline.append(item);
  });
  if (!(alert.timeline || []).length) timeline.append(element("li", "", "No detailed timeline is available for this older incident."));

  const advanced = element("dl", "detail-grid detail-grid--stacked");
  appendDetail(advanced, "Technical rule", alert.rule_id || alert.alert_type || "Unknown");
  appendDetail(advanced, "Npcap capture ID", alert.interface_id);
  appendDetail(advanced, "Protocol", alert.protocol);
  appendDetail(advanced, "Lifecycle status", alert.status || (alert.acknowledged ? "acknowledged" : "new"));
  appendDetail(advanced, "Application / process", alert.process_name || "Unknown");
  appendDetail(advanced, "Process ID", alert.process_id);
  appendDetail(advanced, "Mapping confidence", alert.process_mapping_confidence);
  appendDetail(advanced, "Cooldown", alert.cooldown_seconds === null || alert.cooldown_seconds === undefined ? "—" : `${alert.cooldown_seconds} seconds`);
  if (alert.evidence && typeof alert.evidence === "object" && !Array.isArray(alert.evidence)) {
    Object.entries(alert.evidence).forEach(([key, value]) => {
      if (isTrafficSpike && [
        "baseline_packets_per_second",
        "observed_packets_per_second",
        "observed_multiplier",
        "baseline_observations",
      ].includes(key)) return;
      appendDetail(advanced, key.replaceAll("_", " "), typeof value === "object" ? JSON.stringify(value) : value);
    });
  }

  replaceChildren(body, [
    heading,
    disclosure("Summary", [summary, ...(isTrafficSpike ? [trafficSpikeEvidence(alert)] : [])], true),
    disclosure("Why this alert appeared", [why], true),
    disclosure("Possible normal causes", [normal], true),
    disclosure("Recommendation", [recommendation]),
    disclosure("Activity timeline", [timeline]),
    disclosure("Advanced technical details", [advanced]),
  ]);
  modal.hidden = false;
  window.netguardOpenAlertId = alert.id || null;
  if (options.focus !== false) $("#modal-close")?.focus();
}

export function selectedAdapterId(status = null) {
  return status?.selected_interface || localStorage.getItem("netguard.selectedAdapter") || "";
}

export function preference(key, fallback) {
  const value = localStorage.getItem(`netguard.${key}`);
  return value === null ? fallback : value;
}

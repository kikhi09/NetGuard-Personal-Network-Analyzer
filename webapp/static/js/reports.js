import { api } from "./api.js";
import {
  $,
  createPoller,
  element,
  formatDateOnly,
  formatDuration,
  formatNumber,
  formatShortTime,
  replaceChildren,
  safetyClassification,
  safetyScoreFromRisk,
  setText,
} from "./utils.js";

let currentSession = null;
let downloading = false;

function downloadButtons() {
  return [...document.querySelectorAll(".download-card")];
}

function renderSession() {
  const container = $("#report-session-preview");
  const finalized = Boolean(currentSession?.ended_at);
  downloadButtons().forEach((button) => {
    button.disabled = downloading || !finalized;
  });

  if (!currentSession) {
    replaceChildren(container, [
      element("p", "state-message", "No current session data is available. Start a capture to create a report."),
    ]);
    setText("#report-progress", "No current session data is available. Start a capture to create a report.");
    return;
  }

  const list = element("dl", "detail-grid detail-grid--stacked");
  [
    ["Capture record", "Current Session"],
    ["Date", formatDateOnly(currentSession.started_at)],
    ["Start", formatShortTime(currentSession.started_at)],
    ["End", finalized ? formatShortTime(currentSession.ended_at) : "Running"],
    ["Duration", formatDuration(currentSession.started_at, currentSession.ended_at)],
    ["Network adapter", currentSession.interface_name || "Network adapter"],
    ["Packets", formatNumber(currentSession.total_packets)],
    ["Grouped alerts", formatNumber(currentSession.total_alerts)],
    ["Occurrences", formatNumber(currentSession.alert_occurrences)],
    ["Safety Score", currentSession.final_risk_percentage === null
      ? "Not available yet"
      : `${safetyClassification(currentSession.final_risk_percentage).label} — ${formatNumber(safetyScoreFromRisk(currentSession.final_risk_percentage))}%`],
    ["Mode", currentSession.capture_mode === "development" ? "Development" : "Normal"],
  ].forEach(([label, value]) => {
    const wrapper = element("div");
    wrapper.append(
      element("dt", "", label),
      element("dd", "", value ?? "—"),
    );
    list.append(wrapper);
  });
  replaceChildren(container, [list]);
  setText(
    "#report-progress",
    finalized
      ? "Current Session report and CSV exports are ready."
      : "Capture is running. Stop capture to generate the final report.",
  );
}

async function refreshSession() {
  if (downloading) return;
  try {
    currentSession = await api.currentSession();
    renderSession();
  } catch (error) {
    currentSession = null;
    renderSession();
    setText("#report-progress", error.message);
  }
}

async function download(kind) {
  if (!currentSession?.ended_at) {
    setText(
      "#report-progress",
      currentSession
        ? "Stop capture before generating the final report."
        : "No current session data is available. Start a capture to create a report.",
    );
    return;
  }
  downloading = true;
  renderSession();
  setText("#report-progress", "Generating the requested file…");
  try {
    const filename = kind === "pdf"
      ? await api.downloadPdf()
      : await api.downloadCsv(kind);
    setText("#report-progress", `${filename} was generated and downloaded.`);
  } catch (error) {
    setText("#report-progress", error.message);
  } finally {
    downloading = false;
    renderSession();
  }
}

$("#download-packets-csv").addEventListener("click", () => download("packets"));
$("#download-alerts-csv").addEventListener("click", () => download("alerts"));
$("#download-report-pdf").addEventListener("click", () => download("pdf"));
createPoller(refreshSession, 2500);

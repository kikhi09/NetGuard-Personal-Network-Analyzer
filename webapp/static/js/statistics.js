import { api } from "./api.js";
import { renderDonut } from "./charts.js";
import {
  $,
  createPoller,
  element,
  formatBytes,
  formatNumber,
  replaceChildren,
  setText,
} from "./utils.js";

function statRows(values, formatter = formatNumber) {
  const entries = Object.entries(values || {}).sort((left, right) => Number(right[1]) - Number(left[1]));
  if (!entries.length) return [element("p", "state-message", "No data is available.")];
  return entries.map(([label, value]) => {
    const row = element("div", "stat-list__row");
    row.append(element("span", "", label.replaceAll("_", " ")), element("strong", "", formatter(value)));
    return row;
  });
}

async function refreshStatistics() {
  const [status, statistics] = await Promise.all([
    api.status(),
    api.statistics(),
  ]);
  setText("#statistics-packets", formatNumber(status.packet_count));
  setText("#statistics-pps", formatNumber(statistics.packet_rate, 2));
  setText("#statistics-dropped", formatNumber(status.dropped_packets));
  renderDonut($("#statistics-protocol-chart"), $("#statistics-protocol-legend"), statistics.protocol_counts || {}, "#statistics-protocol-total");
  renderDonut($("#statistics-direction-chart"), $("#statistics-direction-legend"), statistics.direction_counts || {}, "#statistics-direction-total");
  replaceChildren($("#statistics-direction-bytes"), statRows(statistics.direction_byte_counts, formatBytes));
}

createPoller(refreshStatistics, 2500);

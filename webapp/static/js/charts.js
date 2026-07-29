import { element, formatNumber, replaceChildren, setText } from "./utils.js";

const palette = [
  "var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)",
  "var(--chart-5)", "var(--chart-6)", "var(--chart-7)", "var(--chart-8)",
];

export function renderDonut(chart, legend, values, totalTarget = null) {
  if (!chart || !legend) return;
  const entries = Object.entries(values || {})
    .map(([label, value]) => [label, Number(value) || 0])
    .filter(([, value]) => value > 0)
    .sort((left, right) => right[1] - left[1]);
  const total = entries.reduce((sum, [, value]) => sum + value, 0);
  if (totalTarget) setText(totalTarget, formatNumber(total));
  if (!total) {
    chart.classList.add("chart-empty");
    chart.style.background = "";
    chart.setAttribute("aria-label", "No chart data is available");
    replaceChildren(legend, [element("p", "muted", "No data is available for this period.")]);
    return;
  }

  let position = 0;
  const segments = entries.map(([, value], index) => {
    const start = position;
    position += (value / total) * 100;
    return `${palette[index % palette.length]} ${start.toFixed(2)}% ${position.toFixed(2)}%`;
  });
  chart.classList.remove("chart-empty");
  chart.style.background = `conic-gradient(${segments.join(",")})`;
  chart.setAttribute("aria-label", entries.map(([label, value]) => `${label}: ${value}`).join(", "));

  const rows = entries.map(([label, value], index) => {
    const row = element("div", "legend-row");
    const swatch = element("span", "legend-swatch");
    swatch.style.background = palette[index % palette.length];
    row.append(swatch, element("span", "", label), element("strong", "", `${formatNumber(value)} · ${Math.round((value / total) * 100)}%`));
    return row;
  });
  replaceChildren(legend, rows);
}

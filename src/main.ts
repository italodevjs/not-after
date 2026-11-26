import {
  createReport,
  csvReport,
  evaluateWindow,
  inspectBytes,
  inspectText,
  MAX_INPUT_BYTES,
  mergeCertificates,
  type CertificateRecord,
} from "./model";
import { persistCertificates, restoreCertificates } from "./storage";
import { studyCoverage } from "./coverage";

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Required element missing: ${id}`);
  return found as T;
}
const pem = element<HTMLTextAreaElement>("pem"),
  at = element<HTMLInputElement>("at");
const persist = element<HTMLInputElement>("persist"),
  file = element<HTMLInputElement>("file");
const filter = element<HTMLSelectElement>("filter"),
  entries = element("entries"),
  detail = element("detail");
const message = element("message"),
  saveNote = element("storage-note");
let records: CertificateRecord[] = [],
  selected = "",
  busy = true;
const statusLabel = {
  expired: "Expired",
  "not-yet-valid": "Not yet valid",
  expiring: "Expires within 30 days",
  "in-window": "Inside time window",
};
at.value = new Date().toISOString().slice(0, 19);
function evaluationTime() {
  const value = new Date(at.value + "Z");
  if (!at.value || !Number.isFinite(value.getTime()))
    throw new Error("Choose a complete evaluation time in UTC.");
  return value;
}
function announce(text: string, error = false) {
  message.textContent = text;
  message.className = error ? "error" : "";
}
function updateBusyControls() {
  for (const id of ["inspect", "examples", "file", "persist", "forget"])
    element<HTMLButtonElement | HTMLInputElement>(id).disabled = busy;
  for (const id of ["json", "csv", "clear"])
    element<HTMLButtonElement>(id).disabled = !records.length || busy;
  document
    .querySelectorAll<HTMLButtonElement>(".detail-actions button,.cert-row")
    .forEach((button) => {
      button.disabled = busy;
    });
}
function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  className?: string,
) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = text;
  if (className) result.className = className;
  return result;
}
function remember() {
  try {
    persistCertificates(localStorage, records, persist.checked);
    saveNote.textContent = persist.checked
      ? "Saved in this browser, including certificate subjects and names. Clear the register or turn this off to remove this saved copy."
      : "Off. Imported certificates remain in memory until this page closes.";
  } catch {
    saveNote.textContent =
      "Browser storage is unavailable or full. Changes are in memory only; an earlier saved copy may remain. Export your report before closing.";
    announce("Could not update local storage. See the storage note.", true);
  }
}
function formatUTC(value: string) {
  return value.replace("T", " ").replace(".000Z", " UTC");
}
function render() {
  let time: Date;
  try {
    time = evaluationTime();
  } catch (error) {
    announce((error as Error).message, true);
    return;
  }
  const shown = records.filter((cert) => {
    const status = evaluateWindow(cert, time).status;
    return (
      filter.value === "all" ||
      (filter.value === "attention" && status !== "in-window") ||
      (filter.value === "expired" && status === "expired") ||
      (filter.value === "future" && status === "not-yet-valid")
    );
  });
  element("count").textContent =
    `${records.length} certificate${records.length === 1 ? "" : "s"} · ordered by expiry${shown.length !== records.length ? ` · ${shown.length} shown` : ""}`;
  entries.replaceChildren();
  if (!shown.length) {
    const empty = node("div", undefined, "empty");
    empty.append(
      node(
        "h3",
        records.length
          ? "No matching certificates."
          : "An empty register, ready for your files.",
      ),
      node(
        "p",
        records.length
          ? "Choose another filter to see the rest of the register."
          : "Open a public certificate, paste a bundle, or load the clearly labelled examples.",
      ),
    );
    entries.append(empty);
  }
  for (const cert of shown) {
    const window = evaluateWindow(cert, time),
      row = node("button", undefined, "cert-row");
    row.type = "button";
    row.setAttribute("aria-pressed", String(selected === cert.fingerprint));
    row.append(
      node("span", cert.subject || "(Empty subject)", "subject"),
      node("span", formatUTC(cert.notAfter), "expiry mono"),
      node(
        "span",
        statusLabel[window.status],
        `window-status ${window.status}`,
      ),
    );
    row.addEventListener("click", () => {
      selected = cert.fingerprint;
      render();
    });
    entries.append(row);
  }
  detail.replaceChildren();
  const cert = records.find((c) => c.fingerprint === selected);
  if (cert && shown.some((c) => c.fingerprint === cert.fingerprint)) {
    const heading = node("div", undefined, "detail-heading");
    heading.append(
      node("h3", "Inspection record"),
      node("span", cert.source, "small"),
    );
    detail.append(heading);
    const list = node("dl");
    for (const [label, value] of [
      ["Subject", cert.subject || "(Empty subject)"],
      ["Issuer", cert.issuer],
      ["Not before", formatUTC(cert.notBefore)],
      ["Not after", formatUTC(cert.notAfter)],
      ["Serial number", cert.serial],
      ["Public key", cert.publicKeyAlgorithm],
      ["Signature", cert.signatureAlgorithm],
      [
        "DNS names",
        cert.dnsNames.join(", ") || "No DNS names in SAN extension",
      ],
      [
        "CA constraint",
        cert.certificateAuthority
          ? "CA: true (declared)"
          : "CA: false or absent",
      ],
      ["SHA-256", cert.fingerprint],
    ]) {
      list.append(
        node("dt", label),
        node("dd", value, label === "SHA-256" ? "fingerprint mono" : undefined),
      );
    }
    detail.append(list);
    const controls = node("div", undefined, "detail-actions");
    const copy = node("button", "Copy fingerprint");
    copy.addEventListener("click", () => {
      void navigator.clipboard
        ?.writeText(cert.fingerprint)
        .then(() => announce("SHA-256 fingerprint copied."))
        .catch(() =>
          announce(
            "Clipboard unavailable. Select the fingerprint above and copy it.",
            true,
          ),
        );
      if (!navigator.clipboard)
        announce(
          "Clipboard unavailable. Select the fingerprint above and copy it.",
          true,
        );
    });
    const remove = node("button", "Remove certificate", "danger-text");
    remove.addEventListener("click", () => {
      if (busy) return;
      records = records.filter((c) => c.fingerprint !== cert.fingerprint);
      selected = records[0]?.fingerprint ?? "";
      remember();
      render();
      announce("Certificate removed from the register.");
    });
    controls.append(copy, remove);
    detail.append(controls);
    if (cert.dnsNames[0]) {
      const until = new Date(time.getTime() + 365 * 86_400_000);
      const study = studyCoverage(records, cert.dnsNames[0], time, until);
      const coverage = node("section", undefined, "coverage");
      coverage.append(
        node("h3", "A year of declared coverage"),
        node(
          "p",
          `${study.name} · ${study.certificateCount} matching certificate${study.certificateCount === 1 ? "" : "s"} in this register. Exact DNS entries only; wildcards are not expanded.`,
          "small",
        ),
      );
      const ns = "http://www.w3.org/2000/svg",
        graphic = document.createElementNS(ns, "svg");
      graphic.setAttribute("viewBox", "0 0 600 38");
      graphic.setAttribute("role", "img");
      graphic.setAttribute(
        "aria-label",
        `Declared certificate windows over the next 365 days. ${study.gaps.length} uncovered interval${study.gaps.length === 1 ? "" : "s"}.`,
      );
      const background = document.createElementNS(ns, "rect");
      background.setAttribute("x", "0");
      background.setAttribute("y", "8");
      background.setAttribute("width", "600");
      background.setAttribute("height", "22");
      background.setAttribute("fill", "#f3dddd");
      graphic.append(background);
      for (const interval of study.covered) {
        const rectangle = document.createElementNS(ns, "rect");
        rectangle.setAttribute(
          "x",
          String(
            ((interval.start - time.getTime()) /
              (until.getTime() - time.getTime())) *
              600,
          ),
        );
        rectangle.setAttribute("y", "8");
        rectangle.setAttribute(
          "width",
          String(
            ((interval.end - interval.start) /
              (until.getTime() - time.getTime())) *
              600,
          ),
        );
        rectangle.setAttribute("height", "22");
        rectangle.setAttribute("fill", "#315b48");
        graphic.append(rectangle);
      }
      coverage.append(
        graphic,
        node(
          "p",
          `${time.toISOString().slice(0, 10)} to ${until.toISOString().slice(0, 10)} UTC. Green: declared coverage. Pale red: no declared coverage in this register.`,
          "small",
        ),
      );
      if (study.gaps.length) {
        const gaps = node("ul", undefined, "small");
        for (const gap of study.gaps)
          gaps.append(
            node(
              "li",
              `${new Date(gap.start).toISOString()} to ${new Date(gap.end).toISOString()}`,
            ),
          );
        coverage.append(
          node(
            "p",
            "Uncovered intervals (interior only; certificate boundary instants remain inclusive):",
            "small",
          ),
          gaps,
        );
      } else
        coverage.append(
          node(
            "p",
            "No gaps in the declared windows during this study. This does not establish trusted TLS coverage.",
            "small",
          ),
        );
      detail.append(coverage);
    }
    detail.append(
      node(
        "p",
        "Issuer and subject are untrusted certificate data. No chain, signature, hostname or revocation check is performed.",
        "small",
      ),
    );
  }
  updateBusyControls();
}
async function importAction(action: () => Promise<CertificateRecord[]>) {
  if (busy) return;
  busy = true;
  updateBusyControls();
  announce("Inspecting locally…");
  try {
    const incoming = await action(),
      before = records.length;
    records = mergeCertificates(records, incoming);
    selected = incoming[0]?.fingerprint ?? selected;
    announce(
      `${records.length - before} added. ${incoming.length - (records.length - before)} duplicate${incoming.length - (records.length - before) === 1 ? "" : "s"} skipped.`,
    );
    remember();
  } catch (error) {
    announce(
      error instanceof Error ? error.message : "Certificate inspection failed.",
      true,
    );
  } finally {
    busy = false;
    updateBusyControls();
    render();
  }
}
element("inspect").addEventListener("click", () => {
  void importAction(() => inspectText(pem.value));
});
file.addEventListener("change", () => {
  const files = Array.from(file.files ?? []);
  void importAction(async () => {
    if (!files.length) return [];
    if (
      files.length > 64 ||
      files.reduce((sum, item) => sum + item.size, 0) > MAX_INPUT_BYTES
    )
      throw new Error("Choose at most 64 files totalling no more than 1 MiB.");
    const incoming: CertificateRecord[] = [];
    for (const item of files)
      incoming.push(
        ...(await inspectBytes(await item.arrayBuffer(), item.name)),
      );
    return incoming;
  });
  file.value = "";
});
element("examples").addEventListener("click", () => {
  void importAction(async () => {
    const response = await fetch(
      `${import.meta.env.BASE_URL}examples/certificates.pem`,
    );
    if (!response.ok)
      throw new Error(
        "Example certificates could not be loaded. Please retry.",
      );
    return inspectText(await response.text(), "Example · self-signed fixture");
  });
});
at.addEventListener("change", render);
filter.addEventListener("change", render);
element("now").addEventListener("click", () => {
  at.value = new Date().toISOString().slice(0, 19);
  render();
  announce("Evaluation time set to the current UTC time.");
});
persist.addEventListener("change", () => {
  if (!busy) remember();
});
element("forget").addEventListener("click", () => {
  if (busy) return;
  try {
    persistCertificates(localStorage, [], false);
    persist.checked = false;
    saveNote.textContent =
      "Saved copy removed. The current register remains in memory only.";
    announce("Saved copy removed from this browser.");
  } catch {
    announce(
      "Browser storage is unavailable. Remove site data in your browser settings to clear any saved copy.",
      true,
    );
  }
});
element("clear").addEventListener("click", () => {
  if (busy) return;
  records = [];
  selected = "";
  remember();
  render();
  announce("Register cleared.");
});
function download(contents: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const link = node("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
element("json").addEventListener("click", () => {
  try {
    download(
      JSON.stringify(createReport(records, evaluationTime()), null, 2) + "\n",
      "not-after-report.json",
      "application/json",
    );
    announce("JSON report exported for all certificates in the register.");
  } catch (error) {
    announce((error as Error).message, true);
  }
});
element("csv").addEventListener("click", () => {
  try {
    download(
      csvReport(records, evaluationTime()),
      "not-after-report.csv",
      "text/csv;charset=utf-8",
    );
    announce("CSV report exported for all certificates in the register.");
  } catch (error) {
    announce((error as Error).message, true);
  }
});
updateBusyControls();
render();
void (async () => {
  try {
    const restored = await restoreCertificates(localStorage);
    if (restored !== null) {
      records = restored;
      selected = records[0]?.fingerprint ?? "";
      persist.checked = true;
      saveNote.textContent =
        "Restored the public certificates you chose to remember on this device.";
      render();
      announce(
        `${records.length} saved certificate${records.length === 1 ? "" : "s"} restored.`,
      );
    }
  } catch {
    announce(
      "Saved register could not be read. Use Remove saved copy to discard it, then import your files again.",
      true,
    );
  } finally {
    busy = false;
    updateBusyControls();
    render();
  }
})();

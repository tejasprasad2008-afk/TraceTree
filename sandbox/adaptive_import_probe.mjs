/*
 * Trusted import-only probe for TraceTree's adaptive npm subsystem.
 *
 * The configuration is produced from a static map, but this script still
 * validates every path itself.  It deliberately does not enumerate values or
 * invoke exports: importing a module is the bounded Phase 3 question.  Later
 * harness plans are rendered into a separate trusted script.
 */

import { appendFileSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { takeCoverage } from "node:v8";

const configPath = process.argv[2];
const packageRoot = resolve(process.env.TT_PACKAGE_DIR ?? "/input/package");
const resultPath = process.env.TT_PROBE_RESULTS ?? "/out/import-results.ndjson";

function emit(record) {
  appendFileSync(resultPath, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
}

function safeEntryPath(candidate) {
  if (typeof candidate !== "string" || candidate.length === 0) {
    return null;
  }
  const absolute = resolve(packageRoot, candidate);
  if (absolute !== packageRoot && !absolute.startsWith(`${packageRoot}${sep}`)) {
    return null;
  }
  return absolute;
}

function errorSummary(error) {
  if (error instanceof Error) {
    return { name: error.name, message: String(error.message).slice(0, 1000) };
  }
  return { name: "UnknownError", message: String(error).slice(0, 1000) };
}

let config;
try {
  config = JSON.parse(readFileSync(configPath, "utf8"));
} catch (error) {
  emit({ event: "probe_configuration_error", error: errorSummary(error) });
  process.exitCode = 2;
  process.exit();
}

const entrypoints = Array.isArray(config.entrypoints) ? config.entrypoints : [];
for (const [index, entrypoint] of entrypoints.entries()) {
  if (entrypoint === null || typeof entrypoint !== "object") {
    emit({ event: "probe_invalid_entrypoint", index });
    continue;
  }

  const specifier = typeof entrypoint.specifier === "string" ? entrypoint.specifier : `entrypoint-${index}`;
  for (const loader of ["import", "require"]) {
    const candidate = entrypoint[`${loader}_path`];
    const filePath = safeEntryPath(candidate);
    if (filePath === null) {
      if (candidate !== null && candidate !== undefined) {
        emit({ event: "probe_rejected_path", specifier, loader });
      }
      continue;
    }

    try {
      if (loader === "import") {
        await import(pathToFileURL(filePath).href);
      } else {
        createRequire(import.meta.url)(filePath);
      }
      emit({ event: "import_probe", specifier, loader, path: candidate, outcome: "ok" });
    } catch (error) {
      emit({
        event: "import_probe",
        specifier,
        loader,
        path: candidate,
        outcome: "error",
        error: errorSummary(error),
      });
    } finally {
      // Flush coverage after each independent import attempt.  Node still
      // produces a final snapshot during normal process exit as a fallback.
      takeCoverage();
    }
  }
}

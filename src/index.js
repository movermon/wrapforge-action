const core = require('@actions/core');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_CONFIG_SIZE = 512 * 1024; // 512 KB
const REQUIRED_TOP_LEVEL_KEYS = ['service', 'version', 'endpoints'];

// ── Input Validation ─────────────────────────────────────────────────────────

function validateInputs() {
  const mode = core.getInput('mode');
  if (mode !== 'audit' && mode !== 'sync') {
    throw new Error(`Invalid mode: "${mode}". Must be "audit" or "sync".`);
  }

  const outagePolicy = core.getInput('outage-policy');
  if (outagePolicy !== 'fail-closed' && outagePolicy !== 'fail-open') {
    throw new Error(`Invalid outage-policy: "${outagePolicy}". Must be "fail-closed" or "fail-open".`);
  }

  const timeoutMs = parseInt(core.getInput('timeout-ms'), 10);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 20000) {
    throw new Error(`Invalid timeout-ms: "${core.getInput('timeout-ms')}". Must be integer between 1000 and 20000.`);
  }

  const apiBaseUrl = core.getInput('api-base-url');
  if (!apiBaseUrl.startsWith('https://')) {
    throw new Error(`Invalid api-base-url: "${apiBaseUrl}". Must start with "https://".`);
  }

  const configPath = core.getInput('config-path');
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const resolved = path.resolve(workspace, configPath);
  if (!resolved.startsWith(workspace)) {
    throw new Error(
      `Path traversal detected: config-path "${configPath}" resolves outside GITHUB_WORKSPACE. ` +
      `Resolved: "${resolved}", workspace: "${workspace}".`
    );
  }

  return {
    mode,
    outagePolicy,
    timeoutMs,
    apiBaseUrl: apiBaseUrl.replace(/\/$/, ''),
    configPath: resolved,
    oidcAudience: core.getInput('oidc-audience'),
    localFallback: core.getInput('local-fallback') === 'true',
    annotatePr: core.getInput('annotate-pr') === 'true',
  };
}

// ── File Reading & Parsing ───────────────────────────────────────────────────

function readAndParseConfig(configPath) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  const stat = fs.statSync(configPath);
  if (stat.size > MAX_CONFIG_SIZE) {
    throw new Error(
      `Config file too large: ${stat.size} bytes (max ${MAX_CONFIG_SIZE} bytes / 512KB). ` +
      `Reduce the file size or split into multiple specs.`
    );
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  let parsed;
  try {
    parsed = yaml.load(raw, { schema: yaml.FAILSAFE_SCHEMA });
  } catch (err) {
    throw new Error(`Failed to parse YAML: ${err.message}`);
  }

  if (parsed === null || typeof parsed !== 'object') {
    throw new Error('Config file is empty or not a valid YAML mapping.');
  }

  for (const key of REQUIRED_TOP_LEVEL_KEYS) {
    if (!(key in parsed)) {
      throw new Error(`Missing required top-level key: "${key}" in wrapforge.yaml.`);
    }
  }

  return parsed;
}

// ── Local Validation ─────────────────────────────────────────────────────────

function runLocalValidation(parsed) {
  const diagnostics = [];

  if (typeof parsed.service !== 'string' || parsed.service.trim() === '') {
    diagnostics.push({ path: 'service', level: 'error', code: 'MISSING_SERVICE', message: 'service must be a non-empty string' });
  }

  if (typeof parsed.version !== 'string' || parsed.version.trim() === '') {
    diagnostics.push({ path: 'version', level: 'error', code: 'MISSING_VERSION', message: 'version must be a non-empty string' });
  }

  if (!Array.isArray(parsed.endpoints) && typeof parsed.endpoints !== 'object') {
    diagnostics.push({ path: 'endpoints', level: 'error', code: 'INVALID_ENDPOINTS', message: 'endpoints must be an array or mapping' });
  }

  const endpoints = Array.isArray(parsed.endpoints) ? parsed.endpoints : Object.values(parsed.endpoints || {});

  for (let i = 0; i < endpoints.length; i++) {
    const ep = endpoints[i];
    if (typeof ep !== 'object' || ep === null) {
      diagnostics.push({ path: `endpoints[${i}]`, level: 'error', code: 'INVALID_ENDPOINT', message: `Endpoint ${i} is not an object` });
      continue;
    }
    if (!ep.method) {
      diagnostics.push({ path: `endpoints[${i}].method`, level: 'error', code: 'MISSING_METHOD', message: `Endpoint ${i} missing HTTP method` });
    }
    if (!ep.path) {
      diagnostics.push({ path: `endpoints[${i}].path`, level: 'error', code: 'MISSING_PATH', message: `Endpoint ${i} missing path` });
    }
  }

  return {
    result: diagnostics.some(d => d.level === 'error') ? 'fail' : 'pass',
    diagnostics,
  };
}

// ── HTTP Helpers ─────────────────────────────────────────────────────────────

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

// ── OIDC Token Acquisition ───────────────────────────────────────────────────

async function getOidcToken(oidcAudience) {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

  if (!requestUrl || !requestToken) {
    return null;
  }

  const url = `${requestUrl}&audience=${encodeURIComponent(oidcAudience)}`;
  const res = await fetch(url, {
    headers: { Authorization: `bearer ${requestToken}` },
  });

  if (!res.ok) {
    throw new Error(`OIDC token request failed: HTTP ${res.status} ${await res.text().catch(() => '')}`);
  }

  const data = await res.json();
  return data.value || data.id_token;
}

// ── Token Exchange ───────────────────────────────────────────────────────────

async function exchangeToken(apiBaseUrl, oidcToken, mode, timeoutMs) {
  const res = await fetchWithTimeout(
    `${apiBaseUrl}/api/action/oidc/exchange`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        github_oidc_token: oidcToken,
        requested_mode: mode,
        repository: process.env.GITHUB_REPOSITORY,
        ref: process.env.GITHUB_REF,
        sha: process.env.GITHUB_SHA,
        workflow: process.env.GITHUB_WORKFLOW,
        job: process.env.GITHUB_JOB,
      }),
    },
    timeoutMs
  );

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Token exchange failed: HTTP ${res.status} ${body.slice(0, 200)}`);
  }

  return await res.json();
}

// ── Remote Validation ────────────────────────────────────────────────────────

async function remoteValidate(apiBaseUrl, accessToken, parsedConfig, timeoutMs) {
  const body = JSON.stringify({
    repository: process.env.GITHUB_REPOSITORY,
    sha: process.env.GITHUB_SHA,
    ref: process.env.GITHUB_REF,
    config: parsedConfig,
  });
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${accessToken}`,
  };

  // First attempt
  try {
    const res = await fetchWithTimeout(
      `${apiBaseUrl}/api/action/validate`,
      { method: 'POST', headers, body },
      timeoutMs
    );
    if (res.status >= 400 && res.status < 500) {
      const errBody = await res.text().catch(() => '');
      throw Object.assign(
        new Error(`Validation request rejected: HTTP ${res.status} ${errBody.slice(0, 200)}`),
        { noRetry: true }
      );
    }
    if (!res.ok) {
      throw new Error(`Validation request failed: HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    if (err.noRetry) throw err;

    // One retry on network/timeout/5xx
    core.warning(`Validation attempt 1 failed (${err.message}), retrying...`);
    const res = await fetchWithTimeout(
      `${apiBaseUrl}/api/action/validate`,
      { method: 'POST', headers, body },
      timeoutMs
    );
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error(`Validation retry failed: HTTP ${res.status} ${errBody.slice(0, 200)}`);
    }
    return await res.json();
  }
}

// ── Step Summary ─────────────────────────────────────────────────────────────

function buildSummary(result, mode, diagnostics) {
  const modeLabel = mode === 'sync' ? 'sync mode' : 'audit mode';

  if (result === 'pass') {
    return [
      `## WrapForge \u00b7 ${modeLabel}`,
      `**Result: PASS**`,
      '`wrapforge.yaml` passed validation with no issues.',
      '[WrapForge docs](https://wrapforge.dev/docs)',
    ].join('\n');
  }

  if (result === 'soft-pass') {
    return [
      `## WrapForge \u00b7 ${modeLabel}`,
      `**Result: SOFT-PASS**`,
      'Local validation passed. Remote validation was skipped.',
      '**Why:** Fork PR, OIDC unavailable, or WrapForge service unreachable.',
      '[WrapForge docs](https://wrapforge.dev/docs)',
    ].join('\n');
  }

  // fail
  const errorCount = (diagnostics || []).length;
  const lines = [
    `## WrapForge \u00b7 ${modeLabel}`,
    `**Result: FAIL**`,
    `Validation found ${errorCount} issue(s) in \`wrapforge.yaml\`.`,
  ];

  if (diagnostics && diagnostics.length > 0) {
    lines.push('### Diagnostics');
    lines.push('| Path | Level | Code | Message |');
    lines.push('|---|---|---|---|');
    for (const d of diagnostics) {
      lines.push(`| ${d.path || '-'} | ${d.level || '-'} | ${d.code || '-'} | ${d.message || '-'} |`);
    }
  }

  lines.push('[WrapForge docs](https://wrapforge.dev/docs)');
  return lines.join('\n');
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  let inputs;
  try {
    inputs = validateInputs();
  } catch (err) {
    core.setFailed(err.message);
    return;
  }

  // Read and parse config
  let parsedConfig;
  try {
    parsedConfig = readAndParseConfig(inputs.configPath);
  } catch (err) {
    core.setFailed(err.message);
    return;
  }

  core.info(`Config loaded: service="${parsedConfig.service}", mode="${inputs.mode}"`);

  // Track state
  let result = 'fail';
  let modeEffective = inputs.mode;
  let remoteExecuted = false;
  let fallbackExecuted = false;
  let diagnostics = [];

  // ── OIDC flow ──
  let oidcToken = null;
  try {
    oidcToken = await getOidcToken(inputs.oidcAudience);
  } catch (err) {
    core.warning(`OIDC token acquisition failed: ${err.message}`);
  }

  if (!oidcToken) {
    // OIDC unavailable — fork PR or missing permission
    if (!inputs.localFallback) {
      // No fallback allowed — emit helpful permission error
      console.log('::error::WrapForge: Missing id-token permission.');
      console.log('::error::Add this to your workflow job:');
      console.log('::error::  permissions:');
      console.log('::error::    id-token: write');
      console.log('::error::    contents: read');

      if (inputs.outagePolicy === 'fail-closed') {
        result = 'fail';
        core.setOutput('result', result);
        core.setOutput('mode-effective', modeEffective);
        core.setOutput('remote-executed', 'false');
        core.setOutput('fallback-executed', 'false');
        await core.summary.addRaw(buildSummary(result, modeEffective, diagnostics)).write();
        core.setFailed('OIDC unavailable and local-fallback is disabled.');
        return;
      }
      // fail-open without local fallback — still soft-pass with no validation
      result = 'soft-pass';
      core.setOutput('result', result);
      core.setOutput('mode-effective', modeEffective);
      core.setOutput('remote-executed', 'false');
      core.setOutput('fallback-executed', 'false');
      await core.summary.addRaw(buildSummary(result, modeEffective, diagnostics)).write();
      return;
    }

    // Run local fallback
    core.info('OIDC unavailable — running local validation fallback.');
    const local = runLocalValidation(parsedConfig);
    fallbackExecuted = true;
    diagnostics = local.diagnostics;

    if (local.result === 'fail') {
      result = 'fail';
      emitAnnotations(inputs.configPath, diagnostics, inputs.annotatePr);
      core.setOutput('result', result);
      core.setOutput('mode-effective', modeEffective);
      core.setOutput('remote-executed', 'false');
      core.setOutput('fallback-executed', 'true');
      await core.summary.addRaw(buildSummary(result, modeEffective, diagnostics)).write();
      core.setFailed(`Local validation found ${diagnostics.length} error(s).`);
      return;
    }

    result = 'soft-pass';
    core.setOutput('result', result);
    core.setOutput('mode-effective', modeEffective);
    core.setOutput('remote-executed', 'false');
    core.setOutput('fallback-executed', 'true');
    await core.summary.addRaw(buildSummary(result, modeEffective, diagnostics)).write();
    core.info('Local validation passed — soft-pass.');
    return;
  }

  // ── Token exchange ──
  let accessToken;
  try {
    const exchange = await exchangeToken(inputs.apiBaseUrl, oidcToken, inputs.mode, inputs.timeoutMs);
    accessToken = exchange.access_token;
    if (exchange.mode) modeEffective = exchange.mode;
  } catch (err) {
    core.warning(`Token exchange failed: ${err.message}`);
    return handleOutage(inputs, parsedConfig, modeEffective, diagnostics);
  }

  // ── Remote validation ──
  try {
    const validation = await remoteValidate(inputs.apiBaseUrl, accessToken, parsedConfig, inputs.timeoutMs);
    remoteExecuted = true;
    result = validation.result || 'fail';
    diagnostics = validation.diagnostics || [];
  } catch (err) {
    core.warning(`Remote validation failed: ${err.message}`);
    return handleOutage(inputs, parsedConfig, modeEffective, diagnostics);
  }

  // ── Report results ──
  emitAnnotations(inputs.configPath, diagnostics, inputs.annotatePr);
  core.setOutput('result', result);
  core.setOutput('mode-effective', modeEffective);
  core.setOutput('remote-executed', String(remoteExecuted));
  core.setOutput('fallback-executed', String(fallbackExecuted));
  await core.summary.addRaw(buildSummary(result, modeEffective, diagnostics)).write();

  if (result === 'fail') {
    core.setFailed(`Validation failed with ${diagnostics.length} issue(s).`);
  } else {
    core.info(`Result: ${result}`);
  }
}

// ── Outage Handler ───────────────────────────────────────────────────────────

async function handleOutage(inputs, parsedConfig, modeEffective, diagnostics) {
  if (inputs.outagePolicy === 'fail-open' && inputs.localFallback) {
    core.info('Outage detected — running local validation fallback (fail-open).');
    const local = runLocalValidation(parsedConfig);
    const fallbackDiagnostics = local.diagnostics;

    if (local.result === 'fail') {
      emitAnnotations(inputs.configPath, fallbackDiagnostics, inputs.annotatePr);
      core.setOutput('result', 'fail');
      core.setOutput('mode-effective', modeEffective);
      core.setOutput('remote-executed', 'false');
      core.setOutput('fallback-executed', 'true');
      await core.summary.addRaw(buildSummary('fail', modeEffective, fallbackDiagnostics)).write();
      core.setFailed(`Local validation found ${fallbackDiagnostics.length} error(s).`);
      return;
    }

    core.setOutput('result', 'soft-pass');
    core.setOutput('mode-effective', modeEffective);
    core.setOutput('remote-executed', 'false');
    core.setOutput('fallback-executed', 'true');
    await core.summary.addRaw(buildSummary('soft-pass', modeEffective, fallbackDiagnostics)).write();
    core.info('Local validation passed — soft-pass (fail-open).');
    return;
  }

  if (inputs.outagePolicy === 'fail-open') {
    core.setOutput('result', 'soft-pass');
    core.setOutput('mode-effective', modeEffective);
    core.setOutput('remote-executed', 'false');
    core.setOutput('fallback-executed', 'false');
    await core.summary.addRaw(buildSummary('soft-pass', modeEffective, diagnostics)).write();
    core.info('Outage detected — soft-pass (fail-open, no local fallback).');
    return;
  }

  // fail-closed
  core.setOutput('result', 'fail');
  core.setOutput('mode-effective', modeEffective);
  core.setOutput('remote-executed', 'false');
  core.setOutput('fallback-executed', 'false');
  await core.summary.addRaw(buildSummary('fail', modeEffective, diagnostics)).write();
  core.setFailed('WrapForge service unreachable and outage-policy is fail-closed.');
}

// ── PR Annotations ───────────────────────────────────────────────────────────

function emitAnnotations(configPath, diagnostics, annotatePr) {
  if (!annotatePr || !diagnostics || diagnostics.length === 0) return;

  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const relPath = path.relative(workspace, configPath);

  for (const d of diagnostics) {
    if (d.level === 'error') {
      console.log(`::error file=${relPath}::${d.code}: ${d.message}`);
    } else if (d.level === 'warning') {
      console.log(`::warning file=${relPath}::${d.code}: ${d.message}`);
    }
  }
}

// ── Entry Point ──────────────────────────────────────────────────────────────

run().catch(err => {
  core.setFailed(`Unexpected error: ${err.message}`);
});

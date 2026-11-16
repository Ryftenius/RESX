import { execFile } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { buildArgs, COMMANDS, envelopeKey, ResxCommand, SharedOptions, sharedArgs, unwrapEnvelope } from './cli';

export interface RunResult {
    /** The JSON document exactly as RESX printed it. */
    data: any | null;
    /** The envelope `kind`, when present. */
    kind?: string;
    /** The command object inside the envelope (or `data` for unversioned output). */
    payload?: any;
    error?: string;
    cancelled?: boolean;
}

export interface RunOptions {
    symPaths?: string[];
    pdbFile?: string;
    funcsDepth?: number;
    hostile?: boolean;
}

export interface RunTraceEntry {
    id: number;
    exe?: string;
    args: string[];
    startedAt: string;
    endedAt?: string;
    durationMs?: number;
    status: 'running' | 'ok' | 'error';
    error?: string;
    stderr?: string;
}

interface SignatureInfo {
    status?: string;
    statusMessage?: string;
    thumbprint?: string;
    subject?: string;
}

interface TrustManifest {
    signerThumbprints?: string[];
    bundledSha256?: Record<string, string>;
}

const trustedSignerThumbprints = new Set([
    'B138F1E76E48FDBAD32E4256B6DBB6B362272AD7',
]);

const verificationCache = new Map<string, Promise<string>>();
const trustManifestCache = new Map<string, TrustManifest>();
const runTraceHistory: RunTraceEntry[] = [];
const runTraceListeners = new Set<(entry: RunTraceEntry) => void>();
let nextRunTraceId = 1;
const MAX_RUN_TRACE_HISTORY = 300;

function emitRunTrace(entry: RunTraceEntry): void {
    runTraceHistory.push(entry);
    if (runTraceHistory.length > MAX_RUN_TRACE_HISTORY) {
        runTraceHistory.splice(0, runTraceHistory.length - MAX_RUN_TRACE_HISTORY);
    }
    for (const listener of runTraceListeners) {
        try {
            listener(entry);
        } catch {
            // Ignore observer failures so command execution is unaffected.
        }
    }
}

export function getRunTraceHistory(): RunTraceEntry[] {
    return runTraceHistory.map(entry => ({ ...entry }));
}

export function subscribeRunTrace(listener: (entry: RunTraceEntry) => void): vscode.Disposable {
    runTraceListeners.add(listener);
    return new vscode.Disposable(() => {
        runTraceListeners.delete(listener);
    });
}

function bundledExecutableCandidates(context: vscode.ExtensionContext): string[] {
    const suffix = process.platform === 'win32' ? 'resx.exe' : 'resx';
    return [
        path.join(context.extensionPath, 'bin', suffix),
        path.join(context.extensionPath, 'bin', `${process.platform}-${process.arch}`, suffix),
        path.join(context.extensionPath, 'bin', 'win32-x64', 'resx.exe'),
        path.join(context.extensionPath, 'bin', 'win32-arm64', 'resx.exe'),
    ];
}

function getConfiguredExecutablePath(): string {
    const config = vscode.workspace.getConfiguration('resx');
    const inspected = config.inspect<string>('executablePath');
    const workspaceValue = inspected?.workspaceFolderValue ?? inspected?.workspaceValue;
    if (typeof workspaceValue === 'string' && workspaceValue.trim()) {
        void vscode.window.showWarningMessage(
            'Ignoring workspace resx.executablePath. Configure the RESX executable path in user settings only.',
        );
    }

    const configured = typeof inspected?.globalValue === 'string'
        ? inspected.globalValue.trim()
        : '';
    return configured;
}

function allowCustomExecutable(): boolean {
    const config = vscode.workspace.getConfiguration('resx');
    const inspected = config.inspect<boolean>('allowCustomExecutable');
    const workspaceValue = inspected?.workspaceFolderValue ?? inspected?.workspaceValue;
    if (typeof workspaceValue === 'boolean' && workspaceValue) {
        void vscode.window.showWarningMessage(
            'Ignoring workspace resx.allowCustomExecutable. Configure RESX executable trust in user settings only.',
        );
    }

    return inspected?.globalValue === true;
}

async function resolveResxExe(context: vscode.ExtensionContext): Promise<string> {
    const configured = getConfiguredExecutablePath();
    if (configured) {
        if (!allowCustomExecutable()) {
            throw new Error('Custom RESX executables are disabled. Enable resx.allowCustomExecutable in user settings to use resx.executablePath.');
        }
        return verifyExecutable(context, configured, 'Configured RESX executable', false);
    }

    for (const candidate of bundledExecutableCandidates(context)) {
        if (fs.existsSync(candidate)) {
            return verifyExecutable(context, candidate, 'Bundled RESX executable', true);
        }
    }

    throw new Error('RESX executable not found. Install the bundled binary or set resx.executablePath in user settings.');
}

function verifyExecutable(
    context: vscode.ExtensionContext,
    filePath: string,
    label: string,
    requireBundledHash: boolean,
): Promise<string> {
    const key = path.resolve(filePath);
    const cached = verificationCache.get(key);
    if (cached) return cached;

    const pending = verifyExecutableInner(context, key, label, requireBundledHash).catch(error => {
        verificationCache.delete(key);
        throw error;
    });
    verificationCache.set(key, pending);
    return pending;
}

async function verifyExecutableInner(
    context: vscode.ExtensionContext,
    filePath: string,
    label: string,
    requireBundledHash: boolean,
): Promise<string> {
    if (!fs.existsSync(filePath)) {
        throw new Error(`${label} not found: ${filePath}`);
    }

    const basename = path.basename(filePath).toLowerCase();
    if (process.platform === 'win32' && basename !== 'resx.exe') {
        throw new Error(`${label} must point to resx.exe.`);
    }

    if (process.platform !== 'win32') {
        return filePath;
    }

    if (requireBundledHash) {
        await verifyBundledHash(context, filePath, label);
    }

    const signature = await getAuthenticodeSignature(filePath);
    if (requireBundledHash && (!signature.thumbprint || signature.status === 'NotSigned')) {
        return filePath;
    }

    const thumbprint = (signature.thumbprint || '').replace(/\s+/g, '').toUpperCase();
    if (!trustedSignerThumbprints.has(thumbprint)) {
        throw new Error(`${label} is signed by an untrusted certificate (${thumbprint || 'unknown thumbprint'}).`);
    }
    if (!isTrustedSignatureStatus(signature)) {
        throw new Error(`${label} failed signature validation (${signature.status || 'Unknown'}).`);
    }

    return filePath;
}

function isTrustedSignatureStatus(signature: SignatureInfo): boolean {
    if (signature.status === 'Valid') {
        return true;
    }

    const statusMessage = (signature.statusMessage || '').toLowerCase();
    return signature.status === 'UnknownError'
        && statusMessage.includes('root certificate')
        && statusMessage.includes('not trusted');
}

async function verifyBundledHash(
    context: vscode.ExtensionContext,
    filePath: string,
    label: string,
): Promise<void> {
    const manifest = loadTrustManifest(context);
    const relativePath = path.relative(path.join(context.extensionPath, 'bin'), filePath)
        .split(path.sep)
        .join('/');
    const expectedHash = manifest.bundledSha256?.[relativePath]?.toLowerCase();
    if (!expectedHash) {
        throw new Error(`${label} is missing a pinned SHA-256 entry in the trust manifest.`);
    }

    const actualHash = await sha256File(filePath);
    if (actualHash !== expectedHash) {
        throw new Error(`${label} failed SHA-256 verification.`);
    }
}

function loadTrustManifest(context: vscode.ExtensionContext): TrustManifest {
    const manifestPath = path.join(context.extensionPath, 'bin', 'trust.json');
    const cached = trustManifestCache.get(manifestPath);
    if (cached) return cached;

    const raw = fs.readFileSync(manifestPath, 'utf8');
    const parsed = JSON.parse(raw) as TrustManifest;
    if (Array.isArray(parsed.signerThumbprints)) {
        for (const thumbprint of parsed.signerThumbprints) {
            trustedSignerThumbprints.add(thumbprint.replace(/\s+/g, '').toUpperCase());
        }
    }
    trustManifestCache.set(manifestPath, parsed);
    return parsed;
}

function sha256File(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const hash = createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('error', reject);
        stream.on('end', () => resolve(hash.digest('hex').toLowerCase()));
    });
}

function getAuthenticodeSignature(filePath: string): Promise<SignatureInfo> {
    return new Promise((resolve, reject) => {
        const script = `
$sig = Get-AuthenticodeSignature -LiteralPath $env:RESX_TARGET
@{
  status = [string]$sig.Status
  statusMessage = [string]$sig.StatusMessage
  thumbprint = [string]$sig.SignerCertificate.Thumbprint
  subject = [string]$sig.SignerCertificate.Subject
} | ConvertTo-Json -Compress
`.trim();

        execFile(
            'powershell.exe',
            ['-NoProfile', '-NonInteractive', '-Command', script],
            {
                env: { ...process.env, RESX_TARGET: filePath },
                windowsHide: true,
                maxBuffer: 1024 * 1024,
            },
            (err, stdout, stderr) => {
                if (err) {
                    reject(new Error(stderr || err.message));
                    return;
                }

                try {
                    resolve(JSON.parse(stdout.trim()) as SignatureInfo);
                } catch {
                    reject(new Error(`Signature parse failed for ${filePath}`));
                }
            },
        );
    });
}

function execTimeoutMs(): number {
    const seconds = vscode.workspace.getConfiguration('resx').get<number>('timeoutSeconds', 120);
    return Math.max(10, Math.min(3600, Number(seconds) || 120)) * 1000;
}

export interface ExecOptions {
    token?: vscode.CancellationToken;
}

/** Runs a RESX command (`buildArgs` output) and parses its JSON document. */
export function runResx(
    context: vscode.ExtensionContext,
    command: ResxCommand,
    operands: string[],
    flags: string[] = [],
    shared: SharedOptions = {},
    exec: ExecOptions = {},
): Promise<RunResult> {
    return runArgv(context, buildArgs(command, operands, flags, shared), exec);
}

/** Runs a command whose output is text (e.g. `config`), returning stdout, stderr and success. */
export async function runResxText(
    context: vscode.ExtensionContext,
    argv: string[],
): Promise<{ ok: boolean; stdout: string; error?: string }> {
    let exe: string;
    try {
        exe = await resolveResxExe(context);
    } catch (error) {
        return { ok: false, stdout: '', error: error instanceof Error ? error.message : String(error) };
    }
    const allArgs = [...argv, '--no-color'];
    const started = Date.now();
    const trace: RunTraceEntry = { id: nextRunTraceId++, exe, args: allArgs, startedAt: new Date(started).toISOString(), status: 'running' };
    emitRunTrace(trace);
    return new Promise(resolve => {
        execFile(exe, allArgs, { timeout: execTimeoutMs(), windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
            const error = err ? cleanStderr(stderr) || err.message : undefined;
            emitRunTrace({ ...trace, endedAt: new Date().toISOString(), durationMs: Date.now() - started, status: err ? 'error' : 'ok', error, stderr: stderr || undefined });
            resolve({ ok: !err, stdout: String(stdout || ''), error });
        });
    });
}

/** Runs `resx --version` and returns its first line, or an error message. */
export async function resxVersion(context: vscode.ExtensionContext): Promise<{ exe?: string; version?: string; error?: string }> {
    let exe: string;
    try {
        exe = await resolveResxExe(context);
    } catch (error) {
        return { error: error instanceof Error ? error.message : String(error) };
    }
    return new Promise(resolve => {
        execFile(exe, ['--version'], { timeout: 15000, windowsHide: true }, (err, stdout, stderr) => {
            const text = String(stdout || '').trim();
            if (err && !text) {
                resolve({ exe, error: stderr || err.message });
                return;
            }
            const match = text.match(/Version\s+([0-9][^\s]*)/i);
            resolve({ exe, version: match ? match[1] : text.split(/\r?\n/)[0] });
        });
    });
}

/** @deprecated Use runResx; kept for callers that build legacy argv themselves. */
export function runJson(
    context: vscode.ExtensionContext,
    args: string[],
    opts?: RunOptions
): Promise<RunResult> {
    const [command, ...rest] = args;
    const shared: SharedOptions = {
        symPaths: opts?.symPaths,
        pdbFile: opts?.pdbFile,
        hostile: opts?.hostile,
    };
    if (command && command in COMMANDS) {
        return runArgv(context, [command, ...rest, ...sharedArgs(command as ResxCommand, shared), '--json', '--no-color', '--quiet']);
    }
    return runArgv(context, [...args, '--json', '--no-color', '--quiet']);
}

function runArgv(
    context: vscode.ExtensionContext,
    allArgs: string[],
    exec: ExecOptions = {},
): Promise<RunResult> {
    return new Promise(async (resolve) => {
        let exe: string;
        try {
            exe = await resolveResxExe(context);
        } catch (error) {
            resolve({
                data: null,
                error: error instanceof Error ? error.message : String(error),
            });
            return;
        }
        if (exec.token?.isCancellationRequested) {
            resolve({ data: null, error: 'cancelled', cancelled: true });
            return;
        }
        const timeoutMs = execTimeoutMs();
        const started = Date.now();
        const traceId = nextRunTraceId++;
        const traceBase: RunTraceEntry = {
            id: traceId,
            exe,
            args: [...allArgs],
            startedAt: new Date(started).toISOString(),
            status: 'running',
        };
        emitRunTrace(traceBase);

        let cancelled = false;
        const child = execFile(exe, allArgs, {
            maxBuffer: 256 * 1024 * 1024,
            timeout: timeoutMs,
            windowsHide: true,
        }, (err, stdout, stderr) => {
            cancelSubscription?.dispose();
            const finished = Date.now();
            if (cancelled) {
                emitRunTrace({
                    ...traceBase,
                    endedAt: new Date(finished).toISOString(),
                    durationMs: finished - started,
                    status: 'error',
                    error: 'cancelled',
                });
                resolve({ data: null, error: 'cancelled', cancelled: true });
                return;
            }
            const traceDone: RunTraceEntry = {
                ...traceBase,
                endedAt: new Date(finished).toISOString(),
                durationMs: finished - started,
                status: err ? 'error' : 'ok',
                stderr: stderr || undefined,
            };
            if (!stdout && err) {
                const timedOut = (err as NodeJS.ErrnoException)?.code === 'ETIMEDOUT' || (err as { killed?: boolean }).killed;
                const timeoutMsg = timedOut
                    ? `resx timed out after ${Math.round(timeoutMs / 1000)}s (raise resx.timeoutSeconds for large images)`
                    : '';
                const errorText = cleanStderr(stderr) || timeoutMsg || err.message;
                emitRunTrace({
                    ...traceDone,
                    status: 'error',
                    error: errorText,
                });
                resolve({ data: null, error: errorText });
                return;
            }
            const raw = stdout.trim();
            if (!raw) {
                const errorText = cleanStderr(stderr) || 'no output from resx';
                emitRunTrace({
                    ...traceDone,
                    status: 'error',
                    error: errorText,
                });
                resolve({ data: null, error: errorText });
                return;
            }
            try {
                const data = JSON.parse(raw);
                emitRunTrace(traceDone);
                resolve({ data, kind: envelopeKey(data), payload: unwrapEnvelope(data) });
            } catch {
                // RESX prints usage and lookup errors as text, sometimes on stdout.
                const errorText = err
                    ? cleanStderr(stderr) || cleanStderr(raw).replace(/^Error:\s*/i, '').slice(0, 2000)
                    : `JSON parse failed: ${raw.slice(0, 300)}`;
                emitRunTrace({
                    ...traceDone,
                    status: 'error',
                    error: errorText,
                });
                resolve({ data: null, error: errorText });
            }
        });
        const cancelSubscription = exec.token?.onCancellationRequested(() => {
            cancelled = true;
            child.kill();
        });
    });
}

/** Drops ANSI escapes and blank lines; RESX writes `error: ...` lines to stderr. */
function cleanStderr(stderr: string | undefined): string {
    return String(stderr || '')
        .replace(/\x1b\[[0-9;]*m/g, '')
        .split(/\r?\n/)
        .map(line => line.trimEnd())
        .filter(Boolean)
        .join('\n');
}

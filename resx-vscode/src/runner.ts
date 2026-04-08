import { execFile } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export interface RunResult {
    data: any | null;
    error?: string;
}

export interface RunOptions {
    symPaths?: string[];
    pdbFile?: string;
    funcsDepth?: number;
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
const RESX_EXEC_TIMEOUT_MS = 120000;

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

    const pending = verifyExecutableInner(context, key, label, requireBundledHash);
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

    const signature = await getAuthenticodeSignature(filePath);
    const thumbprint = (signature.thumbprint || '').replace(/\s+/g, '').toUpperCase();
    if (!trustedSignerThumbprints.has(thumbprint)) {
        throw new Error(`${label} is signed by an untrusted certificate (${thumbprint || 'unknown thumbprint'}).`);
    }
    if (!isTrustedSignatureStatus(signature)) {
        throw new Error(`${label} failed signature validation (${signature.status || 'Unknown'}).`);
    }
    if (requireBundledHash) {
        await verifyBundledHash(context, filePath, label);
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

export function runJson(
    context: vscode.ExtensionContext,
    args: string[],
    opts?: RunOptions
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
        const extra: string[] = [];

        if (opts?.symPaths?.length) {
            for (const p of opts.symPaths) {
                extra.push('--sym-path', p);
            }
        }
        if (opts?.pdbFile) {
            extra.push('--pdb', opts.pdbFile);
        }

        const allArgs = [...args, ...extra, '--json', '--no-color', '--quiet'];
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

        execFile(exe, allArgs, {
            maxBuffer: 64 * 1024 * 1024,
            timeout: RESX_EXEC_TIMEOUT_MS,
            windowsHide: true,
        }, (err, stdout, stderr) => {
            const finished = Date.now();
            const traceDone: RunTraceEntry = {
                ...traceBase,
                endedAt: new Date(finished).toISOString(),
                durationMs: finished - started,
                status: err ? 'error' : 'ok',
                stderr: stderr || undefined,
            };
            if (!stdout && err) {
                const timeoutMsg = (err as NodeJS.ErrnoException)?.code === 'ETIMEDOUT'
                    ? `resx timed out after ${Math.round(RESX_EXEC_TIMEOUT_MS / 1000)}s`
                    : '';
                const errorText = stderr || timeoutMsg || err.message;
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
                const errorText = stderr || 'no output from resx';
                emitRunTrace({
                    ...traceDone,
                    status: 'error',
                    error: errorText,
                });
                resolve({ data: null, error: errorText });
                return;
            }
            try {
                emitRunTrace(traceDone);
                resolve({ data: JSON.parse(raw) });
            } catch {
                const errorText = `JSON parse failed: ${raw.slice(0, 300)}`;
                emitRunTrace({
                    ...traceDone,
                    status: 'error',
                    error: errorText,
                });
                resolve({ data: null, error: errorText });
            }
        });
    });
}

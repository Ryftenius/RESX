import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unwrapListPayload, unwrapObjectPayload } from '../media/payloads.js';
import { hex } from '../media/reports.js';
import { buildPersistedUiState, coercePersistedUiState } from '../media/view-state.js';

const require = createRequire(import.meta.url);
const cli = require('../out/cli.js');
const reports = require('../out/reports.js');

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;

function run(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures++;
    console.log(`not ok - ${name}`);
    console.log(error);
  }
}

run('unwrapListPayload accepts legacy arrays and versioned envelopes', () => {
  assert.deepEqual(unwrapListPayload([{ name: 'A' }], 'exports'), [{ name: 'A' }]);
  assert.deepEqual(unwrapListPayload({ schema_version: 1, exports: [{ name: 'B' }] }, 'exports'), [{ name: 'B' }]);
  assert.deepEqual(unwrapListPayload({ schema_version: 1, exports: null }, 'exports'), []);
});

run('unwrapObjectPayload accepts legacy objects and versioned envelopes', () => {
  assert.deepEqual(unwrapObjectPayload({ file_name: 'demo.dll' }, 'peinfo'), { file_name: 'demo.dll' });
  assert.deepEqual(unwrapObjectPayload({ schema_version: 1, peinfo: { file_name: 'demo.dll' } }, 'peinfo'), { file_name: 'demo.dll' });
});

run('coercePersistedUiState falls back for invalid values', () => {
  assert.deepEqual(coercePersistedUiState({ topTab: 'bogus', dumpSubTab: 'bad', asmMetaWidth: 9999 }), {
    topTab: 'overview',
    dumpSubTab: 'disasm',
    asmMetaWidth: 520,
  });
});

run('buildPersistedUiState preserves valid values', () => {
  assert.deepEqual(buildPersistedUiState({ topTab: 'types', dumpSubTab: 'hex', asmMetaWidth: 312 }), {
    topTab: 'types',
    dumpSubTab: 'hex',
    asmMetaWidth: 312,
  });
});

run('persisted state accepts every analysis tab and the callers sub-tab', () => {
  for (const tab of ['flow', 'scan', 'behavior', 'strings', 'evidence', 'driver', 'entropy', 'search']) {
    assert.equal(coercePersistedUiState({ topTab: tab }).topTab, tab);
  }
  assert.equal(coercePersistedUiState({ dumpSubTab: 'callers' }).dumpSubTab, 'callers');
});

run('unwrapEnvelope returns the single payload key, or the document', () => {
  assert.deepEqual(cli.unwrapEnvelope({ schema_version: 1, behavior: { image: 'a' } }), { image: 'a' });
  assert.deepEqual(cli.unwrapEnvelope({ schema_version: 1, kind: 'scan', root: 'r', results: [] }), { schema_version: 1, kind: 'scan', root: 'r', results: [] });
  assert.deepEqual(cli.unwrapEnvelope({ image: 'x', matches: [] }), { image: 'x', matches: [] });
  assert.deepEqual(cli.unwrapEnvelope({ schema_version: 1, matches: [1] }, 'matches'), [1]);
  assert.equal(cli.envelopeKey({ schema_version: 1, dump: {} }), 'dump');
});

run('shared options are scoped to the commands that accept them', () => {
  const opts = { lookupPaths: ['C:\\x'], symPaths: ['a', ' ', 'b'], pdbFile: 'p.pdb', apiArgs: true, hostile: true, maxInsns: 0 };
  const scan = cli.sharedArgs('scan', opts);
  assert.ok(!scan.includes('--path'), 'scan has no image lookup options');
  assert.ok(!scan.includes('--hostile'), 'scan has no analysis options');
  assert.deepEqual(scan.slice(0, 2), ['--sym-path', 'a;b'], 'symbol paths join into one --sym-path');
  assert.deepEqual(cli.sharedArgs('api', opts), [], 'api takes no shared options');
  assert.deepEqual(cli.sharedArgs('payload', opts), []);
  const dump = cli.sharedArgs('dump', opts);
  assert.ok(dump.includes('--hostile') && dump.includes('--args'));
  assert.deepEqual(dump.slice(dump.indexOf('--max-insns'), dump.indexOf('--max-insns') + 2), ['--max-insns', 'unlimited']);
  assert.ok(!cli.sharedArgs('strings', opts).includes('--hostile'), 'strings has no analysis options');
});

run('operands follow -- so a leading dash stays an operand', () => {
  const argv = cli.buildArgs('find', ['img.dll', '-x'], ['--mode', 'raw']);
  assert.deepEqual(argv.slice(-3), ['--', 'img.dll', '-x']);
  assert.ok(argv.indexOf('--json') < argv.indexOf('--'));
});

run('dump flags request bytes and every report section', () => {
  const flags = cli.dumpFlags({ image: 'a', at: '0x1000', callDepth: 99, callsOnly: ['iat'], ssa: true });
  for (const f of ['--bytes', '--strings', '--xrefs', '--recomp', '--ssa']) assert.ok(flags.includes(f), f);
  assert.deepEqual(flags.slice(flags.indexOf('--calls'), flags.indexOf('--calls') + 2), ['--calls', '8']);
  assert.deepEqual(flags.slice(0, 2), ['--at', '0x1000']);
});

run('report plans validate webview parameters', () => {
  assert.ok('error' in reports.planReport('find', 'a.dll', { query: '   ' }));
  const strings = reports.planReport('strings', 'a.dll', { minLen: 99999, limit: -5, encoding: 'evil', match: 'x\ny' });
  assert.deepEqual(strings.flags.slice(0, 4), ['--min-len', '4096', '--limit', '1']);
  assert.ok(!strings.flags.includes('evil'));
  assert.equal(strings.flags[strings.flags.indexOf('--match') + 1], 'x y');
  const calls = reports.planReport('calls', 'a.dll', { target: 'main', only: 'winapi, --evil, kernel32.dll', exclude: '-crt' });
  assert.equal(calls.flags[calls.flags.indexOf('--only') + 1], 'winapi,kernel32.dll');
  assert.equal(calls.flags[calls.flags.indexOf('--exclude') + 1], '!crt');
  assert.ok('error' in reports.planReport('callers', 'a.dll', { target: 'sub_00401000' }));
  assert.ok('error' in reports.planReport('callers', 'a.dll', { target: 'rva:0x1000' }));
  assert.ok(!('error' in reports.planReport('callers', 'a.dll', { target: 'NtClose' })));
  assert.equal(reports.normalizeAddress('1000'), '0x1000');
  assert.equal(reports.normalizeAddress('va:0x140001000'), 'va:0x140001000');
  assert.equal(reports.normalizeAddress('0x1000; rm'), null);
  assert.equal(reports.isReportId('behavior'), true);
  assert.equal(reports.isReportId('__proto__'), false);
});

run('hex formats numeric and string coordinates', () => {
  assert.equal(hex(42448), '0x0000A5D0');
  assert.equal(hex('0x1a'), '0x0000001A');
  assert.equal(hex('123'), '0x0000007B');
  assert.equal(hex(null), '');
  assert.equal(hex('-'), '-');
});

// Runs every argv the extension builds against a real analyzer, so CLI drift fails here.
const exe = process.env.RESX_EXE
  || [resolve(root, '..', 'target', 'release', 'resx.exe'), resolve(root, 'bin', 'win32-x64', 'resx.exe')].find(existsSync);
const sample = process.env.RESX_SAMPLE || resolve(root, '..', 'quiet_target.exe');

if (process.platform === 'win32' && exe && existsSync(sample)) {
  const shared = { symPaths: ['C:\\symbols'], apiArgs: true, hostile: true, maxInsns: 500, lookupPaths: [dirname(sample)], noPdb: true };
  const cases = [
    ['peinfo', [sample], []],
    ['pechk', [sample], []],
    ['eat', [sample], []],
    ['iat', [sample], []],
    ['syms', [sample], []],
    ['types', [sample], []],
    ['intelli', [sample], []],
    ['dump', [sample], cli.dumpFlags({ image: sample, at: '0x1000', callDepth: 2, callsOnly: ['iat'], ssa: true })],
    ['dump', [sample, 'entry'], cli.dumpFlags({ image: sample, callDepth: 1 })],
    ...['behavior', 'contracts', 'ipc', 'network', 'crypto', 'driver', 'ioctl', 'pechk', 'strings', 'entropy'].map(id => {
      const plan = reports.planReport(id, sample, { minLen: 6, window: 512, all: true });
      return [plan.command, plan.operands, plan.flags];
    }),
    ...[['find', { query: '48 83 ec', mode: 'raw' }], ['calls', { target: 'entry', depth: 2, only: 'iat' }], ['callers', { target: 'Sleep', depth: 1 }], ['reconstruct', { depth: 2 }]].map(([id, params]) => {
      const plan = reports.planReport(id, sample, params);
      return [plan.command, plan.operands, plan.flags];
    }),
    ['scan', [dirname(sample)], ['--max-files', '2']],
    ['diff', [sample, sample], ['--mode', 'fast']],
    ['locate', ['NtClose'], []],
  ];
  run(`every extension argv parses and returns JSON (${exe})`, () => {
    const failed = [];
    for (const [command, operands, flags] of cases) {
      const argv = cli.buildArgs(command, operands, flags, shared);
      try {
        const out = execFileSync(exe, argv, { encoding: 'utf8', timeout: 120000, maxBuffer: 256 * 1024 * 1024, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
        JSON.parse(out);
      } catch (error) {
        failed.push(`${argv.join(' ')}\n    ${String(error.stderr || error.message).trim().split('\n')[0]}`);
      }
    }
    assert.deepEqual(failed, [], `argv rejected or produced non-JSON:\n${failed.join('\n')}`);
  });
} else {
  console.log('skip - analyzer integration (set RESX_EXE and RESX_SAMPLE to run)');
}

if (failures) {
  console.log(`${failures} test(s) failed`);
  process.exit(1);
}
console.log('all tests passed');

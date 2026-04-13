import assert from 'node:assert/strict';

import { unwrapListPayload, unwrapObjectPayload } from '../media/payloads.js';
import { buildPersistedUiState, coercePersistedUiState } from '../media/view-state.js';

function run(name, fn) {
  fn();
  console.log(`ok - ${name}`);
}

run('unwrapListPayload accepts legacy arrays and versioned envelopes', () => {
  assert.deepEqual(unwrapListPayload([{ name: 'A' }], 'exports'), [{ name: 'A' }]);
  assert.deepEqual(
    unwrapListPayload({ schema_version: 1, exports: [{ name: 'B' }] }, 'exports'),
    [{ name: 'B' }],
  );
  assert.deepEqual(unwrapListPayload({ schema_version: 1, exports: null }, 'exports'), []);
});

run('unwrapObjectPayload accepts legacy objects and versioned envelopes', () => {
  assert.deepEqual(
    unwrapObjectPayload({ file_name: 'demo.dll' }, 'peinfo'),
    { file_name: 'demo.dll' },
  );
  assert.deepEqual(
    unwrapObjectPayload({ schema_version: 1, peinfo: { file_name: 'demo.dll' } }, 'peinfo'),
    { file_name: 'demo.dll' },
  );
});

run('coercePersistedUiState falls back for invalid values', () => {
  assert.deepEqual(coercePersistedUiState({ topTab: 'bogus', dumpSubTab: 'bad', asmMetaWidth: 9999 }), {
    topTab: 'overview',
    dumpSubTab: 'disasm',
    asmMetaWidth: 520,
  });
});

run('buildPersistedUiState preserves valid values', () => {
  assert.deepEqual(buildPersistedUiState({
    topTab: 'types',
    dumpSubTab: 'hex',
    asmMetaWidth: 312,
  }), {
    topTab: 'types',
    dumpSubTab: 'hex',
    asmMetaWidth: 312,
  });
});

console.log('webview tests passed');

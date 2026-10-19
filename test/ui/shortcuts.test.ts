// Tests for shortcut labels in the user's keyboard layout (src/ui/shared/shortcuts.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import test from 'node:test';
import assert from 'node:assert/strict';
import { localizeShortcut } from '../../src/ui/shared/shortcuts.ts';

const swiss = new Map([
  ['KeyZ', 'y'],
  ['KeyY', 'z'],
  ['KeyX', 'x'],
  ['Digit1', '1'],
]);

test('shortcut labels follow the keyboard layout (Swiss Y/Z)', () => {
  assert.equal(localizeShortcut('Alt+Shift+Z', swiss), 'Alt+Shift+Y');
  assert.equal(localizeShortcut('Alt+Shift+Y', swiss), 'Alt+Shift+Z');
  assert.equal(localizeShortcut('Alt+Shift+X', swiss), 'Alt+Shift+X');
  assert.equal(localizeShortcut('Ctrl+1', swiss), 'Ctrl+1');
  // Keys that are not letters or digits, unknown codes and no layout map: unchanged.
  assert.equal(localizeShortcut('Ctrl+Shift+Comma', swiss), 'Ctrl+Shift+Comma');
  assert.equal(localizeShortcut('Alt+Shift+Q', swiss), 'Alt+Shift+Q');
  assert.equal(localizeShortcut('Alt+Shift+Z', null), 'Alt+Shift+Z');
  assert.equal(localizeShortcut('', swiss), '');
});

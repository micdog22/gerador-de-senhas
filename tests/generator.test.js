import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CLASSES, buildClasses, passwordSpace, log2Big, passwordEntropy, generatePassword, generatePassphrase,
  passphraseEntropy, SEPARATORS,
} from '../src/generator.js';
import { createRandom } from '../src/random.js';
import { WORDS } from '../src/wordlist.js';

function seeded(seed) {
  let x = seed >>> 0 || 1;
  return createRandom((buf) => {
    for (let i = 0; i < buf.length; i++) {
      x ^= x << 13;
      x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5;
      x >>>= 0;
      buf[i] = x;
    }
    return buf;
  });
}

test('lista de palavras: 2048, minúsculas sem acento, de 4 a 8 letras, sem repetição', () => {
  assert.equal(WORDS.length, 2048);
  assert.ok(Object.isFrozen(WORDS));
  assert.equal(new Set(WORDS).size, WORDS.length);
  for (const w of WORDS) assert.match(w, /^[a-z]{4,8}$/, w);
  assert.deepEqual([...WORDS].sort(), [...WORDS]);
  const lengths = new Set(WORDS.map((w) => w.length));
  assert.deepEqual([...lengths].sort(), [4, 5, 6, 7, 8]);
});

test('lista de palavras: sem ofensas e sem grafias que só faltam acento', () => {
  for (const bad of ['burro', 'porco', 'veado', 'macaco', 'bunda', 'merda', 'idiota', 'piranha', 'historia', 'musica', 'saude', 'agua', 'cafe']) {
    assert.equal(WORDS.includes(bad), false, bad);
  }
  for (const good of ['casa', 'janela', 'abacaxi', 'girassol', 'zumbido']) assert.ok(WORDS.includes(good), good);
});

test('classes e remoção de caracteres parecidos', () => {
  assert.deepEqual(buildClasses().map((c) => c.chars.length), [26, 26, 10, 27]);
  const clean = buildClasses({ avoidAmbiguous: true });
  assert.deepEqual(clean.map((c) => c.chars.length), [24, 24, 8, 27]);
  const all = clean.map((c) => c.chars).join('');
  for (const ch of 'Il1O0o') assert.equal(all.includes(ch), false, ch);
  assert.deepEqual(buildClasses({ upper: false, symbols: false }).map((c) => c.name), ['lower', 'digits']);
  assert.equal(CLASSES.symbols.includes(' '), false);
});

test('passwordSpace: inclusão e exclusão confere com a contagem direta', () => {
  assert.equal(passwordSpace([26, 10], 2, true), 520n); // 36^2 - 26^2 - 10^2
  assert.equal(passwordSpace([26, 10], 2, false), 1296n);
  assert.equal(passwordSpace([26, 10], 1, true), 0n);
  // com L igual ao número de classes: L! vezes o produto dos tamanhos
  assert.equal(passwordSpace([26, 26, 10, 27], 4, true), 24n * 26n * 26n * 10n * 27n);
  // força bruta num alfabeto pequeno: "ab" e "12", tamanho 3
  const alphabet = 'ab12';
  let valid = 0;
  for (const x of alphabet) for (const y of alphabet) for (const z of alphabet) {
    const s = x + y + z;
    if (/[ab]/.test(s) && /[12]/.test(s)) valid++;
  }
  assert.equal(passwordSpace([2, 2], 3, true), BigInt(valid));
  assert.equal(valid, 48);
});

test('log2Big: exato para potências de 2 e preciso para números enormes', () => {
  assert.equal(log2Big(1n), 0);
  assert.equal(log2Big(2n ** 100n), 100);
  assert.ok(Math.abs(log2Big(3n ** 100n) - 100 * Math.log2(3)) < 1e-9);
  assert.equal(log2Big(0n), -Infinity);
});

test('passwordEntropy: 16 caracteres com os 4 tipos dá pouco menos de 16 × log2(89)', () => {
  const bits = passwordEntropy({ length: 16 });
  const upper = 16 * Math.log2(89);
  assert.ok(bits < upper && bits > upper - 0.6, `${bits}`);
  assert.equal(passwordEntropy({ length: 3 }), 0); // curta demais para os 4 tipos
  assert.ok(Math.abs(passwordEntropy({ length: 10, upper: false, symbols: false, requireEach: false }) - 10 * Math.log2(36)) < 1e-9);
  assert.equal(passwordEntropy({ lower: false, upper: false, digits: false, symbols: false }), 0);
});

test('generatePassword: tamanho, caracteres permitidos e um de cada tipo', () => {
  const rng = seeded(7);
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword({ length: 12, avoidAmbiguous: true }, rng);
    assert.equal(pw.length, 12);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[^a-zA-Z0-9]/);
    assert.equal(/[Il1O0o]/.test(pw), false);
  }
  const digitsOnly = generatePassword({ length: 8, lower: false, upper: false, symbols: false }, rng);
  assert.match(digitsOnly, /^[0-9]{8}$/);
});

test('generatePassword: erros claros', () => {
  const rng = seeded(1);
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }, rng), /pelo menos um tipo/);
  assert.throws(() => generatePassword({ length: 3 }, rng), RangeError);
  assert.throws(() => generatePassword({ length: 200 }, rng), RangeError);
  assert.throws(() => generatePassword({ length: 4.5 }, rng), RangeError);
});

test('generatePassword: frequência de cada caractere perto da esperada', () => {
  const rng = seeded(99);
  const counts = new Map();
  let total = 0;
  for (let i = 0; i < 3000; i++) {
    for (const ch of generatePassword({ length: 20, requireEach: false }, rng)) {
      counts.set(ch, (counts.get(ch) || 0) + 1);
      total++;
    }
  }
  assert.equal(counts.size, 89);
  const expected = total / 89;
  for (const [ch, c] of counts) assert.ok(Math.abs(c - expected) / expected < 0.12, `${ch}: ${c}`);
});

test('generatePassphrase: palavras da lista, separador e opções', () => {
  const rng = seeded(42);
  const plain = generatePassphrase({ words: 6, separator: '-' }, rng);
  const parts = plain.split('-');
  assert.equal(parts.length, 6);
  assert.ok(parts.every((p) => WORDS.includes(p)));

  const caps = generatePassphrase({ words: 5, separator: ' ', capitalize: 'first' }, rng).split(' ');
  assert.ok(caps.every((p) => /^[A-Z][a-z]+$/.test(p) && WORDS.includes(p.toLowerCase())));

  const shout = generatePassphrase({ words: 5, separator: '.', capitalize: 'random' }, rng).split('.');
  assert.equal(shout.filter((p) => p === p.toUpperCase()).length, 1);

  const withDigit = generatePassphrase({ words: 4, separator: '_', digit: true }, rng).split('_');
  assert.equal(withDigit.filter((p) => /^[a-z]+[0-9]$/.test(p)).length, 1);

  const glued = generatePassphrase({ words: 3, separator: SEPARATORS.nenhum }, rng);
  assert.match(glued, /^[a-z]{12,24}$/);
  assert.throws(() => generatePassphrase({ words: 2 }, rng), RangeError);
  assert.throws(() => generatePassphrase({ words: 13 }, rng), RangeError);
});

test('passphraseEntropy: 11 bits por palavra e o que cada opção acrescenta', () => {
  assert.equal(passphraseEntropy({ words: 6 }), 66);
  assert.equal(passphraseEntropy({ words: 6, capitalize: 'first' }), 66);
  assert.ok(Math.abs(passphraseEntropy({ words: 6, capitalize: 'random' }) - (66 + Math.log2(6))) < 1e-12);
  assert.ok(Math.abs(passphraseEntropy({ words: 5, digit: true }) - (55 + Math.log2(10) + Math.log2(5))) < 1e-12);
  assert.equal(passphraseEntropy({ words: 4 }, 7776), 4 * Math.log2(7776));
});

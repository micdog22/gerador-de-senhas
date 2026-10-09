import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectionLimit, createRandom, secureRandom, UINT32_RANGE } from '../src/random.js';

// Fonte controlada: devolve os valores da fila, na ordem.
function queueSource(values) {
  const queue = [...values];
  return (buf) => {
    for (let i = 0; i < buf.length; i++) buf[i] = queue.length ? queue.shift() : 0;
    return buf;
  };
}

// Fonte pseudoaleatória determinística (xorshift32) para testes estatísticos.
function xorshiftSource(seed) {
  let x = seed >>> 0 || 1;
  return (buf) => {
    for (let i = 0; i < buf.length; i++) {
      x ^= x << 13;
      x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5;
      x >>>= 0;
      buf[i] = x;
    }
    return buf;
  };
}

test('rejectionLimit: maior múltiplo de max que cabe em 2^32', () => {
  assert.equal(rejectionLimit(1), UINT32_RANGE);
  assert.equal(rejectionLimit(2), UINT32_RANGE);
  assert.equal(rejectionLimit(3), 4294967295);
  assert.equal(rejectionLimit(10), 4294967290);
  assert.equal(rejectionLimit(62), 4294967292); // 2^32 mod 62 = 4
  assert.equal(rejectionLimit(2048), UINT32_RANGE);
  assert.equal(rejectionLimit(UINT32_RANGE), UINT32_RANGE);
  for (const bad of [0, -1, 1.5, UINT32_RANGE + 1, NaN]) assert.throws(() => rejectionLimit(bad), RangeError);
});

test('rejectionLimit: o intervalo aceito tem cada resultado o mesmo número de vezes', () => {
  for (const max of [3, 7, 10, 26, 62, 89, 95, 1000, 2047, 2049, 3e9]) {
    const limit = rejectionLimit(max);
    assert.equal(limit % max, 0, `${max}`);
    assert.ok(UINT32_RANGE - limit < max, `${max}: sobra menor que max`);
  }
});

test('mapeamento: valores acima do limite são descartados e o resto vira x % max', () => {
  const rng = createRandom(queueSource([4294967295, 4294967290, 7, 4294967289, 25]));
  assert.equal(rng.int(10), 7); // 4294967295 e 4294967290 são descartados
  assert.equal(rng.int(10), 9); // 4294967289 % 10
  assert.equal(rng.int(10), 5);
  assert.deepEqual(rng.stats(), { draws: 5, rejected: 2 });
});

test('max = 1 sempre dá 0; pick escolhe da lista', () => {
  const rng = createRandom(queueSource([123, 456, 2, 5]));
  assert.equal(rng.int(1), 0);
  assert.equal(rng.int(1), 0);
  assert.equal(rng.pick(['a', 'b', 'c']), 'c');
  assert.equal(rng.pick(['x', 'y']), 'y');
});

test('uniformidade: qui-quadrado com fonte determinística', () => {
  const rng = createRandom(xorshiftSource(2026));
  for (const max of [7, 10, 62]) {
    const draws = max * 2000;
    const counts = new Array(max).fill(0);
    for (let i = 0; i < draws; i++) counts[rng.int(max)]++;
    const expected = draws / max;
    const chi2 = counts.reduce((s, c) => s + (c - expected) ** 2 / expected, 0);
    // valores críticos com p = 0,001 para max - 1 graus de liberdade
    const critical = { 7: 22.46, 10: 27.88, 62: 99.6 }[max];
    assert.ok(chi2 < critical, `max ${max}: qui-quadrado ${chi2.toFixed(2)}`);
  }
});

test('o jeito ingênuo (x % n) tem viés; a rejeição não', () => {
  // com n = 3 * 2^30, os valores [0, 2^30) aparecem duas vezes mais no módulo direto
  const n = 3 * 2 ** 30;
  const naiveHits = (v) => (v < UINT32_RANGE - n ? 2 : 1);
  assert.equal(naiveHits(0), 2);
  assert.equal(naiveHits(n - 1), 1);
  assert.equal(rejectionLimit(n), n); // só aceita [0, n): cada valor uma vez
});

test('secureRandom usa crypto.getRandomValues e respeita o intervalo', () => {
  const rng = secureRandom();
  for (let i = 0; i < 1000; i++) {
    const v = rng.int(89);
    assert.ok(Number.isInteger(v) && v >= 0 && v < 89);
  }
});

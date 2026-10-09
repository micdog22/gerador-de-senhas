import { test } from 'node:test';
import assert from 'node:assert/strict';
import { estimate, feedback, caseVariations, unleet, crackSeconds, crackTimes, formatDuration, SCENARIOS } from '../src/strength.js';
import { generatePassword } from '../src/generator.js';
import { createRandom } from '../src/random.js';
import { COMMON } from '../src/common.js';

const patterns = (pw) => estimate(pw).sequence.map((s) => s.pattern);

test('senha vazia', () => {
  const r = estimate('');
  assert.equal(r.bits, 0);
  assert.equal(r.score, 0);
  assert.deepEqual(feedback('', r), ['Digite uma senha para ver a análise.']);
});

test('senhas muito comuns (inclusive brasileiras) ficam em "muito fraca"', () => {
  for (const pw of ['123456', 'senha123', 'brasil', '102030', 'flamengo', 'mudar123', 'qwerty', 'teamo']) {
    const r = estimate(pw);
    assert.equal(r.score, 0, `${pw}: ${r.bits.toFixed(1)} bits`);
    assert.ok(patterns(pw).includes('common'), pw);
  }
  assert.ok(COMMON.includes('123456') && COMMON.includes('senha123') && COMMON.includes('brasil'));
  assert.match(feedback('123456', estimate('123456')).join(' '), /mais usadas/);
});

test('troca de letras por símbolos não engana', () => {
  assert.deepEqual(unleet('s3nh@'), { text: 'senha', subs: 2 });
  const r = estimate('s3nh@123');
  assert.equal(r.score, 0);
  assert.ok(r.sequence.some((s) => s.leet));
  assert.match(feedback('s3nh@123', r).join(' '), /s3nh@/);
});

test('palavra comum com maiúscula, ano e símbolo continua fraca', () => {
  const r = estimate('Brasil2024!');
  assert.ok(r.score <= 1, `${r.bits.toFixed(1)} bits`);
  const j = estimate('Janela1990!');
  assert.ok(j.score <= 1, `${j.bits.toFixed(1)} bits`);
  assert.deepEqual(patterns('Janela1990!'), ['word', 'date', 'bruteforce']);
});

test('repetição, sequência, teclado e data', () => {
  assert.ok(patterns('aaaaaaaa').includes('repeat'));
  assert.equal(estimate('aaaaaaaa').score, 0);
  assert.ok(patterns('abcdefgh').includes('sequence'));
  assert.equal(estimate('abcdefgh').score, 0);
  assert.ok(patterns('ghjkl').includes('keyboard'));
  assert.ok(patterns('xcvbnm').includes('keyboard'));
  assert.ok(estimate('abcabcabcabc').bits < 25);
  assert.ok(patterns('19/05/1990').includes('date'));
  assert.ok(estimate('19/05/1990').score <= 1);
  assert.ok(patterns('ze19051990').includes('date'));
});

test('senha aleatória longa é "muito forte" e a estimativa fica perto da entropia real', () => {
  let x = 12345;
  const rng = createRandom((buf) => {
    for (let i = 0; i < buf.length; i++) {
      x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
      buf[i] = x;
    }
    return buf;
  });
  for (let i = 0; i < 20; i++) {
    const pw = generatePassword({ length: 16 }, rng);
    const r = estimate(pw);
    assert.equal(r.score, 4, `${pw}: ${r.bits.toFixed(1)}`);
    assert.ok(r.bits > 80 && r.bits <= 16 * Math.log2(95) + 1, `${pw}: ${r.bits.toFixed(1)}`);
  }
});

test('frase-senha com palavras da lista: 4 razoável, 6 muito forte', () => {
  const four = estimate('cavalo-janela-tomate-sapato');
  const six = estimate('cavalo-janela-tomate-sapato-girafa-trem');
  assert.ok(patterns('cavalo-janela-tomate-sapato').filter((p) => p === 'word').length === 4);
  assert.equal(four.label, 'Razoável');
  assert.equal(six.label, 'Muito forte');
  assert.ok(six.bits > four.bits);
});

test('variações de maiúsculas (regra do zxcvbn)', () => {
  assert.equal(caseVariations('senha'), 1);
  assert.equal(caseVariations('Senha'), 2);
  assert.equal(caseVariations('SENHA'), 2);
  assert.equal(caseVariations('senhA'), 2);
  assert.equal(caseVariations('SeNha'), 15); // C(5,1) + C(5,2)
  assert.equal(caseVariations('1234'), 1);
});

test('dicas: tamanho curto e maiúscula só no começo', () => {
  const tips = feedback('Cachorro', estimate('Cachorro')).join(' ');
  assert.match(tips, /12 caracteres/);
  assert.match(tips, /maiúscula só no começo/);
  const strong = feedback('cavalo-janela-tomate-sapato-girafa-trem', estimate('cavalo-janela-tomate-sapato-girafa-trem'));
  assert.match(strong.join(' '), /gerenciador de senhas/);
});

test('tempo para quebrar: metade do espaço dividido pela velocidade', () => {
  assert.equal(crackSeconds(1, 1), 1);
  assert.equal(crackSeconds(11, 1024), 1);
  const times = crackTimes(50);
  assert.equal(times.length, SCENARIOS.length);
  for (let i = 1; i < times.length; i++) assert.ok(times[i].seconds < times[i - 1].seconds);
  assert.equal(times[3].text, '15 horas'); // 2^49 / 10^10: cerca de 56 mil segundos
});

test('durações por extenso', () => {
  assert.equal(formatDuration(0.5), 'instantâneo');
  assert.equal(formatDuration(1), '1 segundo');
  assert.equal(formatDuration(30), '30 segundos');
  assert.equal(formatDuration(61), '1 minuto');
  assert.equal(formatDuration(3600), '1 hora');
  assert.equal(formatDuration(7200), '2 horas');
  assert.equal(formatDuration(86400), '1 dia');
  assert.equal(formatDuration(40 * 86400), '1 mês');
  assert.equal(formatDuration(100 * 86400), '3 meses');
  const year = 365.25 * 86400;
  assert.equal(formatDuration(400 * 86400), '1 ano');
  assert.equal(formatDuration(25 * year), '25 anos');
  assert.equal(formatDuration(5000 * year), '5 mil anos');
  assert.equal(formatDuration(1e6 * year), '1 milhão de anos');
  assert.equal(formatDuration(2.5e6 * year), '2 milhões de anos');
  assert.equal(formatDuration(1.5e9 * year), '1 bilhão de anos');
  assert.equal(formatDuration(2e10 * year), 'mais que a idade do universo');
  assert.equal(formatDuration(Infinity), 'mais que a idade do universo');
});

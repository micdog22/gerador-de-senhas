// Interface do Gerador de Senhas: gerador, medidor e verificação de vazamento.

import { generatePassword, generatePassphrase, passwordEntropy, passphraseEntropy, SEPARATORS, buildClasses } from './generator.js';
import { secureRandom } from './random.js';
import { estimate, feedback, crackTimes, BANDS } from './strength.js';
import { checkPwned } from './hibp.js';

const SETTINGS_KEY = 'gerador-de-senhas:ajustes';
const PATTERN_NAMES = {
  common: 'Senha muito comum',
  word: 'Palavra do dicionário',
  sequence: 'Sequência',
  repeat: 'Repetição',
  keyboard: 'Caminho no teclado',
  date: 'Data ou ano',
  bruteforce: 'Trecho sem padrão conhecido',
};

const $ = (id) => document.getElementById(id);
const els = {
  tabPassword: $('tab-password'), tabPhrase: $('tab-phrase'), panelPassword: $('panel-password'), panelPhrase: $('panel-phrase'),
  result: $('result'), regenerate: $('regenerate'), copy: $('copy'), copyStatus: $('copy-status'),
  length: $('length'), lengthOut: $('length-out'), lower: $('lower'), upper: $('upper'), digits: $('digits'), symbols: $('symbols'),
  ambiguous: $('ambiguous'), each: $('each'), words: $('words'), wordsOut: $('words-out'), separator: $('separator'),
  capitalize: $('capitalize'), digit: $('digit'), genBits: $('gen-bits'), genLabel: $('gen-label'), genMeter: $('gen-meter'),
  genNote: $('gen-note'), genTimes: $('gen-times'), test: $('test'), toggle: $('toggle'), testMeter: $('test-meter'),
  testSummary: $('test-summary'), testPatterns: $('test-patterns'), testTips: $('test-tips'), testTimes: $('test-times'),
  pwned: $('pwned'), pwnedStatus: $('pwned-status'),
};

const rng = secureRandom();
const nf = new Intl.NumberFormat('pt-BR');
const nf1 = new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 1 });
let mode = 'password';
let pwnedController = null;
let lastTested = '';

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(node, message, kind = '') {
  node.textContent = message;
  node.className = `status${kind ? ` ${kind}` : ''}`;
}

function scoreOf(bits) {
  let score = 0;
  BANDS.forEach((b, i) => { if (bits >= b.min) score = i; });
  return score;
}

function paintMeter(span, bits) {
  const score = scoreOf(bits);
  span.style.width = `${Math.max(4, Math.min(100, (bits / 100) * 100))}%`;
  span.className = `s${score}`;
  return score;
}

function renderTimes(table, bits) {
  table.tBodies[0].replaceChildren(...crackTimes(bits).map((t) => {
    const tr = el('tr');
    const th = el('th');
    th.scope = 'row';
    th.append(t.label, el('small', '', t.detail));
    tr.append(th, el('td', '', t.text));
    return tr;
  }));
}

// ---------- ajustes ----------

function readOptions() {
  return {
    length: Number(els.length.value),
    lower: els.lower.checked, upper: els.upper.checked, digits: els.digits.checked, symbols: els.symbols.checked,
    avoidAmbiguous: els.ambiguous.checked, requireEach: els.each.checked,
    words: Number(els.words.value), separator: els.separator.value, capitalize: els.capitalize.value, digit: els.digit.checked,
  };
}

function saveSettings() {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ ...readOptions(), mode }));
  } catch {
    // sem armazenamento: os ajustes valem só nesta visita
  }
}

function loadSettings() {
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') || {};
  } catch {
    saved = {};
  }
  const num = (v, lo, hi, def) => (Number.isInteger(v) && v >= lo && v <= hi ? v : def);
  els.length.value = String(num(saved.length, 8, 64, 16));
  for (const k of ['lower', 'upper', 'digits', 'symbols']) if (typeof saved[k] === 'boolean') els[k].checked = saved[k];
  if (typeof saved.avoidAmbiguous === 'boolean') els.ambiguous.checked = saved.avoidAmbiguous;
  if (typeof saved.requireEach === 'boolean') els.each.checked = saved.requireEach;
  els.words.value = String(num(saved.words, 3, 12, 6));
  if (saved.separator in SEPARATORS) els.separator.value = saved.separator;
  if (['none', 'first', 'random'].includes(saved.capitalize)) els.capitalize.value = saved.capitalize;
  if (typeof saved.digit === 'boolean') els.digit.checked = saved.digit;
  if (saved.mode === 'phrase') mode = 'phrase';
}

// ---------- gerador ----------

function generate() {
  const o = readOptions();
  els.lengthOut.textContent = String(o.length);
  els.wordsOut.textContent = String(o.words);
  let value = '';
  let bits = 0;
  let note = '';
  try {
    if (mode === 'password') {
      if (!buildClasses(o).length) throw new Error('Marque pelo menos um tipo de caractere.');
      value = generatePassword(o, rng);
      bits = passwordEntropy(o);
      const size = buildClasses(o).reduce((n, c) => n + c.chars.length, 0);
      note = `${o.length} caracteres sorteados entre ${size} possíveis${o.requireEach ? ', com pelo menos um de cada tipo marcado' : ''}.`;
    } else {
      value = generatePassphrase({ words: o.words, separator: SEPARATORS[o.separator], capitalize: o.capitalize, digit: o.digit }, rng);
      bits = passphraseEntropy({ words: o.words, capitalize: o.capitalize, digit: o.digit });
      note = `${o.words} palavras de uma lista de 2.048 (11 bits cada)`;
      if (o.capitalize === 'random') note += ', mais a posição da palavra em maiúsculas';
      if (o.digit) note += ', mais o número e a sua posição';
      note += '.';
      if (o.separator === 'nenhum' && o.capitalize === 'none') note += ' Sem separador, algumas combinações podem se confundir; o valor mostrado é um limite superior.';
    }
    els.result.textContent = value;
    setStatus(els.copyStatus, '');
  } catch (err) {
    els.result.textContent = '';
    setStatus(els.copyStatus, err.message, 'error');
  }
  els.genBits.textContent = `${nf1.format(bits)} bits`;
  const score = paintMeter(els.genMeter, bits);
  els.genLabel.textContent = bits ? BANDS[score].label : '';
  els.genNote.textContent = note;
  renderTimes(els.genTimes, bits);
  saveSettings();
}

function selectTab(next, focus = false) {
  mode = next;
  const isPassword = mode === 'password';
  els.tabPassword.setAttribute('aria-selected', String(isPassword));
  els.tabPhrase.setAttribute('aria-selected', String(!isPassword));
  els.tabPassword.tabIndex = isPassword ? 0 : -1;
  els.tabPhrase.tabIndex = isPassword ? -1 : 0;
  els.panelPassword.hidden = !isPassword;
  els.panelPhrase.hidden = isPassword;
  if (focus) (isPassword ? els.tabPassword : els.tabPhrase).focus();
  generate();
}

async function copyResult() {
  const text = els.result.textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    setStatus(els.copyStatus, 'Copiada. Cole no gerenciador de senhas ou no site, e depois copie outra coisa para limpar a área de transferência.', 'ok');
  } catch {
    const range = document.createRange();
    range.selectNodeContents(els.result);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    setStatus(els.copyStatus, 'O navegador não deixou copiar sozinho. O texto está selecionado: use Ctrl + C.', 'warn');
  }
}

// ---------- medidor ----------

function analyze() {
  const pw = els.test.value;
  const visible = els.test.type === 'text';
  const r = estimate(pw);
  paintMeter(els.testMeter, pw ? r.bits : 0);
  els.testSummary.textContent = pw ? `${r.label}: cerca de ${nf1.format(r.bits)} bits (${nf.format(pw.length)} caracteres).` : 'Digite uma senha para ver a análise.';
  const shown = r.sequence.filter((s) => s.pattern !== 'separator' && !(s.pattern === 'bruteforce' && r.sequence.length === 1));
  els.testPatterns.replaceChildren(...shown.map((s) => {
    const li = el('li');
    li.append(`${PATTERN_NAMES[s.pattern]}${s.leet ? ' (com troca de letras)' : ''}: `);
    if (visible) li.append(el('code', '', s.token));
    else li.append(`${s.token.length} ${s.token.length === 1 ? 'caractere' : 'caracteres'}`);
    return li;
  }));
  els.testTips.replaceChildren(...(pw ? feedback(pw, r) : []).map((t) => el('li', '', t)));
  renderTimes(els.testTimes, pw ? r.bits : 0);
  // o resultado de uma verificação anterior não vale para uma senha nova
  if (pw !== lastTested) {
    lastTested = pw;
    if (pwnedController) pwnedController.abort();
    setStatus(els.pwnedStatus, '');
  }
}

async function verifyPwned() {
  const pw = els.test.value;
  if (!pw) {
    setStatus(els.pwnedStatus, 'Digite uma senha primeiro.', 'warn');
    return;
  }
  if (pwnedController) pwnedController.abort();
  const controller = new AbortController();
  pwnedController = controller;
  els.pwned.disabled = true;
  setStatus(els.pwnedStatus, 'Consultando...');
  try {
    const { count, prefix } = await checkPwned(pw, { signal: controller.signal });
    const sent = ` Enviado ao serviço: só o prefixo ${prefix}.`;
    if (count > 0) {
      setStatus(els.pwnedStatus, `Esta senha apareceu ${nf.format(count)} ${count === 1 ? 'vez' : 'vezes'} em vazamentos. Não use.${sent}`, 'error');
    } else {
      setStatus(els.pwnedStatus, `Não encontrada nos vazamentos conhecidos. Isso não quer dizer que ela seja forte: veja a análise acima.${sent}`, 'ok');
    }
  } catch (err) {
    if (err && err.name === 'AbortError') return;
    setStatus(els.pwnedStatus, err.message, 'error');
  } finally {
    if (pwnedController === controller) pwnedController = null;
    els.pwned.disabled = false;
  }
}

// ---------- início ----------

function init() {
  loadSettings();
  for (const input of [els.length, els.lower, els.upper, els.digits, els.symbols, els.ambiguous, els.each, els.words, els.separator, els.capitalize, els.digit]) {
    input.addEventListener(input.type === 'range' ? 'input' : 'change', generate);
  }
  els.regenerate.addEventListener('click', generate);
  els.copy.addEventListener('click', copyResult);
  els.tabPassword.addEventListener('click', () => selectTab('password'));
  els.tabPhrase.addEventListener('click', () => selectTab('phrase'));
  for (const tab of [els.tabPassword, els.tabPhrase]) {
    tab.addEventListener('keydown', (e) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
      e.preventDefault();
      const next = e.key === 'Home' ? 'password' : e.key === 'End' ? 'phrase' : mode === 'password' ? 'phrase' : 'password';
      selectTab(next, true);
    });
  }
  els.test.addEventListener('input', analyze);
  // o campo fica num formulário (boa prática para campos de senha), mas nada é enviado
  $('test-form').addEventListener('submit', (e) => e.preventDefault());
  els.toggle.addEventListener('click', () => {
    const show = els.test.type === 'password';
    els.test.type = show ? 'text' : 'password';
    els.toggle.textContent = show ? 'Ocultar' : 'Mostrar';
    els.toggle.setAttribute('aria-pressed', String(show));
    analyze();
  });
  els.pwned.addEventListener('click', verifyPwned);
  selectTab(mode);
  analyze();
}

init();

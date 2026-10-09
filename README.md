# Gerador de Senhas

Gerador de senhas fortes e de frases-senha com palavras em português, que roda inteiro no navegador. Mostra a entropia exata de cada senha gerada, estima quanto tempo um ataque levaria, analisa senhas digitadas atrás de padrões fáceis de adivinhar e confere se uma senha já apareceu em vazamentos sem enviá-la para lugar nenhum.

**Acesse online:** https://micdog22.github.io/gerador-de-senhas/

## Recursos

- **Senhas aleatórias** de 8 a 64 caracteres, com minúsculas, maiúsculas, números e símbolos à escolha, opção de evitar caracteres parecidos (I, l, 1, O, 0, o) e de exigir pelo menos um de cada tipo.
- **Frases-senha** com uma lista original de **2.048 palavras comuns do português**, sem acento, de 4 a 8 letras: `veloz-condor-acordar-atento-leveza-chamar`. Separador, maiúsculas e número opcionais.
- Sorteio com `crypto.getRandomValues` e **amostragem por rejeição**, sem o viés do `%`.
- **Entropia exata** de cada configuração (a regra "pelo menos um de cada tipo" é descontada por inclusão e exclusão) e o tempo médio para quebrar em quatro cenários de ataque.
- **Medidor para senhas digitadas** que procura senhas muito comuns (inclusive as brasileiras, como `123456`, `senha123` e `brasil`), palavras, sequências, repetições, caminhos no teclado, datas e trocas como `s3nh@`.
- **Verificar se vazou** com o Have I Been Pwned por **k-anonimato**: só os 5 primeiros caracteres do SHA-1 da senha saem do aparelho, e só quando você clica no botão.
- A página declara uma política de segurança (CSP) que só permite conexões com o serviço de verificação. Nenhuma senha é guardada; só os ajustes do gerador ficam no navegador.
- Funciona no celular, com tema claro e escuro e navegação por teclado.

## Como usar

1. Escolha **Senha aleatória** ou **Frase-senha** e ajuste as opções. A senha muda na hora; **Gerar outra** sorteia de novo e **Copiar** manda para a área de transferência.
2. Em **Testar uma senha**, digite uma senha que você já usa para ver a análise, os padrões encontrados e dicas.
3. Clique em **Verificar se vazou** para consultar o Have I Been Pwned.

## Como rodar localmente

Módulos ES não carregam via `file://`, então sirva a pasta com qualquer servidor estático:

```bash
python3 -m http.server 8000
```

Depois abra http://localhost:8000. O `crypto.subtle` (usado no SHA-1) só existe em contexto seguro; `localhost` conta como seguro, e sem ele o app usa uma implementação própria de SHA-1.

## Testes

```bash
npm test
```

São 38 testes com `node:test`, sem dependências e sem acesso à rede:

- **sorteio:** o limite de rejeição para vários tamanhos, o descarte dos valores acima do limite com uma fonte controlada, uniformidade por qui-quadrado com semente fixa e a demonstração do viés do `%`;
- **entropia:** inclusão e exclusão conferida contra a contagem por força bruta num alfabeto pequeno, `log2` de números enormes em BigInt e frequência de cada caractere nas senhas geradas;
- **lista de palavras:** 2.048 itens, só `a` a `z`, de 4 a 8 letras, sem repetição, em ordem, sem palavras ofensivas e sem grafias que só faltam acento;
- **medidor:** senhas comuns e brasileiras, troca de letras, datas, sequências, repetições, teclado, senhas aleatórias e frases-senha;
- **vazamento:** vetores de teste do SHA-1, a implementação própria conferida contra o `node:crypto` nas bordas de bloco, e a consulta com um `fetch` simulado que confere que só o prefixo de 5 caracteres vai na URL.

## Como funciona

### Sorteio sem viés

`Math.random()` não serve para senhas: não é criptograficamente seguro. O certo é `crypto.getRandomValues`, que entrega inteiros de 32 bits imprevisíveis. Mas transformar um inteiro `x` de 32 bits em um número de 0 a `n - 1` com `x % n` cria viés, porque 2^32 raramente é múltiplo de `n`. Com `n = 3 × 2^30`, por exemplo, os valores de 0 a 2^30 - 1 sairiam com o dobro da frequência dos outros.

A correção é a **amostragem por rejeição**: aceitar `x` só se ele for menor que o maior múltiplo de `n` que cabe em 2^32, e sortear de novo caso contrário.

```
limite = 2^32 - (2^32 mod n)
repita: x = sorteio de 32 bits
até x < limite
resultado = x mod n
```

Dentro do limite, cada resultado aparece exatamente o mesmo número de vezes. Para os tamanhos usados aqui, a chance de descarte é minúscula (menos de n em 2^32).

### Entropia das senhas

Uma senha de `L` caracteres sorteados entre `N` possíveis tem `N^L` combinações, ou `L × log2(N)` bits. Exigir pelo menos um caractere de cada tipo diminui um pouco esse número, e a conta exata usa inclusão e exclusão:

```
válidas = soma, para cada subconjunto S dos tipos, de (-1)^|S| × (N - tamanho de S)^L
```

Com 16 caracteres entre 89 possíveis, são 103,4 bits. Para manter o sorteio uniforme entre as senhas válidas, o gerador sorteia a senha inteira de novo quando falta algum tipo, em vez de forçar um caractere de cada tipo em posições fixas (o que deixaria a senha mais previsível).

### Frases-senha

A lista tem exatamente 2.048 = 2^11 palavras, então cada palavra sorteada vale 11 bits:

| Palavras | Bits |
| --- | --- |
| 4 | 44 |
| 5 | 55 |
| 6 | 66 |
| 7 | 77 |
| 8 | 88 |

Uma palavra sorteada em maiúsculas soma log2(número de palavras) bits, e um número em posição sorteada soma log2(10) mais log2(número de palavras). Iniciais maiúsculas em todas as palavras não somam nada: é uma regra fixa.

A lista foi montada para este projeto: palavras do dia a dia (objetos, comida, natureza, animais, verbos, adjetivos), sem acento nem cedilha (para digitar em qualquer teclado), de 4 a 8 letras, sem palavrões, ofensas, termos religiosos ou políticos e sem palavras que só existem por causa de um acento faltando ("historia" no lugar de "história"). Cada palavra foi conferida com o corretor ortográfico de português do Brasil do macOS e depois revisada à mão.

### Quanto tempo leva para quebrar

Em média, um ataque acerta depois de testar metade das combinações: `2^(bits - 1) / velocidade`. Os quatro cenários:

| Cenário | Tentativas |
| --- | --- |
| Pela internet, com limite (o site bloqueia depois de alguns erros) | cerca de 100 por hora |
| Pela internet, sem limite | 10 por segundo |
| Vazamento com hash lento (bcrypt, Argon2) | 10 mil por segundo |
| Vazamento com hash rápido (MD5, SHA-1) e placas de vídeo | 10 bilhões por segundo |

O último cenário é o que importa quando um site guarda senhas do jeito errado. Por isso a recomendação é 60 bits ou mais para senhas importantes e 80 para ficar folgado.

### O medidor de senhas digitadas

Quem ataca não testa combinações em ordem alfabética: começa por senhas vazadas, palavras, datas, sequências (`abc`, `4321`) e caminhos no teclado (`qwerty`, `asdf`). O medidor, inspirado no zxcvbn, procura esses padrões e estima quantas tentativas cada um custa: a posição na lista de senhas comuns, 2.048 para uma palavra da lista, uns 140 para um ano, e assim por diante. Variações de maiúsculas e trocas como `@` por `a` multiplicam pouco.

Depois, uma **programação dinâmica** escolhe o jeito mais barato de montar a senha inteira com esses pedaços e com caracteres "soltos" (que custam log2 do tamanho do alfabeto cada). O custo total, em bits, é a estimativa. É por isso que `Brasil2024!` fica em cerca de 16 bits, apesar de ter maiúscula, número e símbolo.

Limites: o medidor conhece só a lista de 2.048 palavras e algumas centenas de senhas comuns. Palavras de outros idiomas ("correcthorse") são tratadas como caracteres soltos, e a estimativa sai otimista. Use o resultado como orientação, não como garantia.

### Verificar se vazou sem enviar a senha

O Have I Been Pwned guarda os hashes SHA-1 de centenas de milhões de senhas que apareceram em vazamentos. A consulta usa **k-anonimato**:

1. O navegador calcula o SHA-1 da senha: `password` vira `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
2. Só os 5 primeiros caracteres (`5BAA6`) vão para `https://api.pwnedpasswords.com/range/5BAA6`.
3. O serviço devolve todos os hashes vazados que começam assim, cerca de 2 mil linhas no formato `SUFIXO:CONTAGEM`.
4. O app procura os outros 35 caracteres (`1E4C9B93F3...`) nessa lista, aqui mesmo.

Existem 16^5 = 1.048.576 prefixos possíveis, e cada um é compartilhado por cerca de 2 mil hashes vazados (e por um número enorme de senhas que nunca vazaram), então o serviço não tem como saber qual foi consultada. A consulta ainda manda o cabeçalho `Add-Padding: true`, que faz o serviço completar a resposta com linhas falsas (contagem 0) para que nem o tamanho dela dê pistas.

O SHA-1 usa o `crypto.subtle` do navegador. Onde ele não existe, entra uma implementação própria em JavaScript, conferida nos testes contra o `node:crypto`.

## Aviso

Projeto educacional e de uso pessoal, sem auditoria de segurança independente. Para senhas importantes, prefira um gerenciador de senhas e ative a verificação em duas etapas.

## Contribuindo

Issues e pull requests são bem-vindos.

## Licença

MIT. Veja [LICENSE](LICENSE).

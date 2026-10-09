// Senhas muito usadas, em ordem aproximada de popularidade (a posição na lista é usada
// como estimativa de tentativas). Inclui as clássicas do mundo todo e as que aparecem
// com frequência no Brasil: sequências numéricas, "senha", times de futebol, nomes e
// palavras afetivas. É uma lista curta e ilustrativa; quem ataca usa listas com
// milhões de senhas vazadas.

export const COMMON = Object.freeze(`
123456 123456789 12345678 12345 1234567 102030 senha 123123 1234567890 111111 1234 000000 123321 654321 112233
121212 abc123 qwerty senha123 mudar123 123mudar brasil password admin admin123 10203040 1020304050 102030405060
147258369 159753 123qwe qwe123 qwerty123 1q2w3e4r 1q2w3e q1w2e3r4 1qaz2wsx zaq12wsx asdfgh asdf1234 asdfghjkl
iloveyou teamo amor meuamor amorzinho amoremio jesus jesuscristo deus deusefiel familia felicidade princesa gatinha
gatinho flamengo corinthians palmeiras vasco gremio santos saopaulo cruzeiro botafogo fluminense internacional
atletico vitoria bahia sport gabriel lucas matheus pedro rafael guilherme juliana mariana amanda fernanda bruna
beatriz julia maria joao jose ana carlos daniel felipe gustavo leonardo vitor bruno thiago rodrigo marcelo ricardo
eduardo camila larissa leticia carolina patricia aline vanessa monica sandra 987654321 999999 888888 777777 666666
555555 444444 333333 222222 11111111 00000000 101010 202020 010203 123654 147852 741852963 789456 456789 159357
852456 1478963 abcdef abcd1234 qazwsx master dragon monkey football futebol mudar trocar trocar123 acesso acesso123
usuario teste teste123 test test123 root toor 12341234 1122334455 1029384756 abc abcabc pass pass123 senha1 senha12
senha1234 brasil123 brasil2024 flamengo123 corinthians123 palmeiras123 minhasenha minhavida meusfilhos mamae papai
familia123 love loveyou neymar neymar10 pokemon naruto batman superman estrela flor florzinha anjo anjinho
chocolate morango pipoca sorvete docinho cachorro gatinho123 bonita bonito lindo linda 123abc abc12345 1234abcd
q1w2e3 1a2b3c a1b2c3 123qweasd qweasd zxcvbnm asdasd qweqwe 123mudar123 102030senha senha102030 senhasenha
`.trim().split(/\s+/));

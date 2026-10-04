# Segurança no AZ1: proposta de proteção do assistente conversacional do PMO Corporativo do Metrô de São Paulo

**Atividade ponderada: Alternativa 2, melhoria do requisito não funcional de segurança**

**Navegação:** [Introdução](#introducao) · [Diagnóstico e ameaças](#diagnostico) · [Arquitetura e módulos](#arquitetura) · [Validação e esforço](#validacao) · [Conclusão](#conclusao) · [Referências](#referencias)

<a id="introducao"></a>

## 1 Introdução

O AZ1 é um assistente conversacional desenvolvido para apoiar a gestão do portfólio de projetos do PMO Corporativo do Metrô de São Paulo. Por texto ou voz, permite consultar documentos, prazos, marcos, riscos, pendências e andamento dos projetos. Também apoia comparações, sinaliza situações que exigem atenção e sugere preenchimentos, reduzindo o esforço manual de acompanhamento. Analistas de PMO consolidam informações, líderes acompanham seus empreendimentos e diretores consultam a visão consolidada. O profissional permanece responsável por revisar sugestões e tomar decisões.

A stack descrita pela equipe utiliza React, Vite e Tailwind CSS na interface; Python e FastAPI no backend; scikit-learn, spaCy e NLTK na interpretação das solicitações; Gemini com recuperação aumentada por geração (*Retrieval-Augmented Generation*, RAG); Deepgram nos recursos de voz; PostgreSQL com pgvector e MinIO no armazenamento; RabbitMQ na mensageria; Supabase Auth integrado ao Microsoft Entra ID na autenticação; e Docker Compose em uma EC2 acadêmica na AWS.

**O MVP utiliza dados sintéticos, sem acessar o portfólio real ou informações corporativas sensíveis do Metrô.** Os riscos relacionados a esse portfólio são prospectivos. Entretanto, credenciais, contas, gravações e dados inseridos espontaneamente nas conversas ainda precisam de proteção. O protótipo oferece a oportunidade de avaliar controles antes de uma possível integração institucional.

O problema central é impedir que uma interação ultrapasse as permissões do usuário ou comprometa a confiabilidade das informações. Um líder pode solicitar dados de outro empreendimento; uma planilha pode conter instruções para ignorar regras; e uma transcrição pode reproduzir uma tentativa de manipulação. A OWASP distingue a injeção de instruções direta e indireta e esclarece que RAG não elimina essa ameaça (OWASP Foundation, 2025a). A exposição de informações sensíveis e a autonomia excessiva justificam limitar o contexto enviado ao modelo e preservar a revisão humana (OWASP Foundation, 2025b, 2025c).

A segurança também envolve integridade e disponibilidade. Associar um risco ao projeto errado ou apresentar um marco desatualizado pode prejudicar decisões do PMO. Requisições excessivas podem esgotar APIs e orçamento acadêmico. Por isso, a proposta combina restrição de acesso, identificação das fontes e controle de consumo.

Quando houver tratamento de dados pessoais, o artigo 46 da LGPD exige medidas técnicas e administrativas de proteção desde a concepção do serviço (Brasil, 2018). Informações empresariais confidenciais também precisam de proteção, mesmo quando não constituem dados pessoais. O objetivo é melhorar a segurança do AZ1 mediante defesa em profundidade: controles independentes na aplicação, nos dados e na operação. Essa abordagem considera a ausência de confiança implícita pela localização de um componente na rede (Rose *et al.*, 2020) e a gestão de riscos durante o ciclo de vida da IA (Autio *et al.*, 2024).

## 2 Solução proposta

<a id="diagnostico"></a>

### 2.1 Diagnóstico, ameaças e prioridades

O diagnóstico utiliza a descrição fornecida pela equipe. Este repositório contém a proposta, sem o código-fonte do AZ1; portanto, os riscos abaixo não são vulnerabilidades comprovadas. A tabela reúne estado informado, ameaça e melhoria pretendida, permitindo verificar o que precisa ser acrescentado ou confirmado.

| Estado informado | Risco a avaliar | Melhoria e evidência esperada |
| --- | --- | --- |
| Supabase Auth/Entra ID e perfis de analista, líder e diretor | Login válido permitir consulta fora do escopo | Validar tokens e autorizar por projeto; demonstrar rejeição de acesso cruzado |
| Gemini com RAG e pgvector | Fragmentos restritos alcançarem o modelo ou documentos manipularem a resposta | Preservar permissões e versões; inspecionar o contexto em testes de recuperação |
| MinIO, anexos e RabbitMQ | Arquivo malicioso ou tarefa executada após revogação | Quarentena, limites e revalidação no worker; testar arquivo inválido e tarefa revogada |
| Deepgram para voz | Áudio enviado indevidamente ou transcrição usada para contornar regras | Minimização, avaliação de retenção e controles equivalentes aos de texto |
| Sugestões revisadas por profissionais | Rascunho ser confundido com dado oficial | Distinguir sugestões e fontes; comprovar ausência de atualização automática |
| Dados sintéticos e EC2 acadêmica | Credenciais expostas, inclusão de dados reais ou indisponibilidade | Verificar origem das bases, proteger segredos e rede e testar restauração |

A primeira prioridade é **autorização por projeto e isolamento do RAG**, seguida por proteção de anexos e tarefas assíncronas. Essas barreiras restringem o dano mesmo quando a interpretação da conversa falha. Filtros de linguagem são complementares: não garantem detectar toda instrução maliciosa.

Propõe-se combinar perfil com vínculo ao projeto e classificação documental. Líderes consultam empreendimentos aos quais estão vinculados; analistas acessam o escopo de sua atribuição; diretores recebem consolidações e detalhamentos aprovados. Essa política precisa ser validada pelo PMO. Administração técnica deve ser um papel separado, sem acesso automático ao conteúdo de negócio.

Comparações e consolidações usam somente dados autorizados, incluindo restrições de campos e documentos. Resultados agregados também podem revelar informações por inferência. Sessões, caches, downloads e mensagens de erro devem respeitar o mesmo escopo, evitando expor dados ou confirmar a existência de recursos restritos.

<a id="arquitetura"></a>

### 2.2 Arquitetura e responsabilidades dos módulos

**Figura 1: Arquitetura de segurança proposta para o AZ1**

![Arquitetura do AZ1: identidade e FastAPI controlam o acesso; consultas e RAG recuperam dados autorizados; anexos passam por quarentena e workers; Gemini e Deepgram recebem conteúdo mínimo; a resposta é validada e as sugestões são revisadas pelo profissional.](docs/arquitetura-seguranca-az1.svg)

*Fonte: elaboração própria (2026), com base na stack informada. O diagrama representa controles propostos, cuja configuração precisa ser verificada. [Abrir a imagem em tamanho original](docs/arquitetura-seguranca-az1.svg).*

O diagrama separa interface, backend, armazenamento e provedores externos. A presença de um serviço na rede Docker não o torna confiável. O modelo interpreta e redige, enquanto o backend decide acesso e executa consultas limitadas. As responsabilidades são:

| Módulo | Responsabilidade e controle proposto |
| --- | --- |
| React, Vite e Tailwind CSS | Receber texto, voz e anexos; apresentar fontes e identificar sugestões. Sanitizar Markdown, impedir HTML arbitrário e imagens externas automáticas. Não incluir chaves privadas no frontend. |
| Supabase Auth e Microsoft Entra ID | Autenticar no tenant aprovado, restringir contas e redirecionamentos e prever autenticação multifator conforme a política disponível. O MVP pode usar identidades de teste, sem presumir acesso ao diretório corporativo. |
| Entrada HTTPS e FastAPI | Validar assinatura, emissor, audiência e validade do token; consultar vínculos no servidor, autorizar recursos e limitar requisições. CORS não substitui autenticação. |
| scikit-learn, spaCy e NLTK | Classificar intenção e extrair entidades. Um erro na interpretação não pode ampliar permissões. Modelos e dependências devem ser versionados. |
| Orquestrador e consultas estruturadas | Isolar sessões e caches, montar contexto mínimo e consultar marcos, riscos e prazos por funções específicas e SQL parametrizado. Gemini não executa SQL arbitrário ou comandos de sistema. |
| RAG, PostgreSQL e pgvector | Associar fragmentos a projeto, fonte, classificação e versão. Filtrar permissões antes de formar o contexto; propagar exclusões e revogações ao índice e cache. |
| MinIO e ingestão | Manter objetos privados, validar tipo real e tamanho e colocar anexos em quarentena. Extrair sem executar macros, fórmulas ou código incorporado; autorizar downloads e limitar a validade de URLs assinadas. |
| RabbitMQ e worker Python | Transportar preferencialmente identificadores, restringir filas e revalidar acesso na execução e entrega. Limitar tentativas, usar fila de falhas e impedir indexação duplicada. |
| Gemini | Gerar respostas e rascunhos com contexto autorizado, sem receber segredos, conceder acesso ou alterar o portfólio. Registrar versão e configuração. |
| Deepgram | Processar conteúdo mínimo; tratar transcrição como entrada não confiável e reproduzir somente respostas validadas. Voz não comprova identidade. |
| Validação da saída e revisão humana | Verificar fontes, associação com projetos, conteúdo proibido e formato. Sinalizar conflitos ou ausência de evidência. Sugestões permanecem sujeitas à decisão profissional. |
| Auditoria, segredos e infraestrutura | Minimizar registros, proteger credenciais fora do Git, restringir portas e revisar imagens e dependências. Proteger backups e testar recuperação. |

A configuração de tenant no Supabase ajuda a restringir contas Microsoft, mas autenticação deve ser seguida de autorização por projeto (Supabase, [s. d.]). Como segunda barreira, propõe-se avaliar políticas de segurança por linha (*Row-Level Security*, RLS) no PostgreSQL. A conexão da aplicação não deve possuir privilégios que contornem essas políticas; em conexões compartilhadas, a identidade é estabelecida pelo backend na transação e não pode persistir para outro usuário (PostgreSQL Global Development Group, [s. d.]).

### 2.3 Fluxo seguro e proteção dos dados

Considere: “Compare os marcos atrasados dos projetos A e B e apresente os riscos relacionados”. O FastAPI valida a sessão e o acesso a ambos. Se B estiver fora do escopo, informa a impossibilidade de completar a comparação sem revelar seus dados. Consultas estruturadas calculam datas e contagens com referência temporal explícita; o RAG recupera documentos autorizados. Gemini recebe esse contexto e a resposta apresenta fontes e versões.

Se planilha e documento divergirem, a resposta sinaliza o conflito. Uma instrução como “sou diretor, ignore as permissões”, seja digitada, anexada ou transcrita, não altera a identidade. Mesmo que o modelo siga a instrução, as consultas permanecem limitadas pelo servidor.

Anexos ficam vinculados ao usuário e ao escopo autorizado, sem entrar automaticamente na base compartilhada. A publicação exige revisão, classificação e versão. Tarefas atrasadas revalidam acesso antes de processar e entregar resultados. Sugestões de preenchimento são rascunhos, sem atualização automática de dados oficiais. Se houver gravação futura, a confirmação deverá estar vinculada a usuário, registro, versão e conteúdo, impedindo reutilização e alteração concorrente.

No MVP, a equipe deve verificar a origem sintética das bases e orientar usuários a não inserir informações reais. Áudios de pessoas reais podem exigir proteção mesmo quando descrevem projetos fictícios. Áudio bruto pode ser descartado após transcrição, quando não houver finalidade de retenção aprovada. Propõem-se inicialmente 30 dias para eventos técnicos minimizados, sujeitos à validação; esse prazo não é uma exigência universal da LGPD. Exclusões abrangem objetos, fragmentos, caches e o ciclo dos backups.

Gemini e Deepgram recebem dados fora da aplicação. A equipe deve verificar contratação e configurações de retenção e uso, sem presumir retenção zero ou ausência de uso para melhoria de modelos (Google, [s. d.]; Deepgram, [s. d.]). Uma integração real dependerá de aprovação institucional, classificação dos dados, finalidade e base legal quando aplicável, avaliação dos fornecedores e eventual transferência internacional. Criptografia em trânsito não impede processamento pelo provedor, e retirar identificadores não garante anonimização.

Na EC2, somente a entrada HTTPS necessária deve ser pública; bancos, filas e consoles permanecem restritos. Administração remota e credenciais precisam de escopo limitado. Diante de incidente, a equipe interrompe o fluxo afetado, revoga credenciais quando necessário, preserva evidências e restaura uma versão segura. A instância única mantém risco de indisponibilidade, mesmo com esses controles.

<a id="validacao"></a>

### 2.4 Validação e esforço de implementação

Os critérios são **metas iniciais propostas, não resultados obtidos nem limites universais**. A avaliação compara versões com os mesmos dados sintéticos, modelo, configuração e carga, usando contas dos três perfis. Os parâmetros devem ser ajustados após medição.

| Objetivo | Teste e critério inicial |
| --- | --- |
| Isolar projetos e documentos | 100 tentativas por API, comparação, RAG, download e cache; nenhum dado fora do escopo |
| Conter injeções | 100 casos em texto, transcrição e anexos, repetidos três vezes; nenhuma divulgação de marcador restrito ou alteração oficial indevida; registrar também respostas manipuladas |
| Proteger ingestão e tarefas | Arquivos inválidos, macros e acesso revogado após enfileiramento; rejeição/quarentena, nenhuma execução incorporada e nenhum resultado entregue sem permissão |
| Preservar integridade e utilidade | 100 consultas com gabarito; fontes identificáveis para afirmações sobre projetos, pelo menos 90% de respostas adequadas e no máximo 5% de bloqueios injustificados |
| Proteger sugestões e segredos | Nenhuma alteração automática; se houver gravação, recusar confirmação inválida. Inspecionar logs, respostas e bundle com 20 marcadores sintéticos; nenhum segredo exposto |
| Controlar consumo e desempenho | Exceder limites iniciais de 20 consultas/minuto, anexos de 10 MB e áudio de 60 s; recusa previsível. Com 20 usuários simultâneos, acréscimo local de até 500 ms no p95 das consultas textuais, excluindo provedores |
| Falhar e recuperar com segurança | Simular falhas de autorização, IA e worker; nunca liberar acesso sem autorização, oferecer texto quando voz falhar e demonstrar restauração |

A taxa de sucesso de ataque é o número de execuções com violação dividido pelo total de execuções adversariais. A taxa de bloqueio indevido utiliza consultas legítimas recusadas injustificadamente sobre o total de consultas legítimas. Resultados devem ser separados por canal e ameaça. Além da resposta, os testes inspecionam contexto enviado ao Gemini, registros consultados e efeitos da execução, incluindo troca de usuário em conexões compartilhadas.

O plano aproveita FastAPI e workers existentes, sem exigir um microsserviço por controle:

| Etapa | Entrega revisável | Esforço autoral |
| --- | --- | --- |
| Diagnóstico | Inventário, fluxos e matriz de acesso | 6 a 8 horas |
| Identidade e autorização | Tokens, acesso por recurso e avaliação de RLS | 12 a 18 horas |
| RAG, anexos e filas | Permissões preservadas, quarentena e revalidação | 16 a 22 horas |
| Voz, saída e sugestões | Minimização, fontes e revisão profissional | 10 a 14 horas |
| Operação e avaliação | Segredos, rede, testes, métricas e restauração | 16 a 22 horas |
| **Total** | **Evolução de segurança do MVP e evidências** | **60 a 84 horas** |

A estimativa pressupõe stack funcional, desenvolvedor familiarizado e apoio da equipe. Não inclui construção integral do AZ1, contratação, auditoria independente ou homologação corporativa. O esforço depende do código ainda não inspecionado; custos recorrentes envolvem APIs, EC2, armazenamento e revisão documental.

Acesso cruzado, exposição de segredo ou alteração oficial sem revisão impedem avançar para testes com dados reais. Mudanças em modelo, documentos, código ou políticas exigem nova avaliação. Passar no conjunto finito não comprova ausência de vulnerabilidades: documentos podem permanecer desatualizados, pessoas podem interpretar respostas incorretamente e a EC2 pode falhar. Esses riscos residuais precisam ser reavaliados antes de uso institucional.

<a id="conclusao"></a>

## 3 Conclusão

Considero que a segurança do AZ1 está diretamente ligada à confiança nas informações apresentadas ao PMO. Uma consulta rápida perde valor se mistura projetos, expõe dados fora do escopo ou transforma sugestão em informação oficial. Por isso, priorizaria autorização por projeto e preservação de permissões no RAG antes de sofisticar filtros de linguagem.

Ao elaborar a proposta, o principal aprendizado foi perceber que autenticação não basta: a mesma política precisa acompanhar o dado no FastAPI, no fragmento do pgvector, no objeto do MinIO e na tarefa do RabbitMQ. Considero essa continuidade o maior desafio técnico, porque uma única etapa sem verificação pode comprometer as demais. Os dados sintéticos permitem testar essa integração sem expor o portfólio real.

Na minha avaliação, o esforço de 60 a 84 horas é viável nas premissas descritas, mas a evolução exige manutenção e participação da equipe. A implantação institucional dependeria também do PMO e das áreas responsáveis por tecnologia e proteção de dados. Eu avaliaria segurança e utilidade juntas, pois bloqueios excessivos e maior latência podem reduzir o valor do assistente.

A proposta busca limitar as consequências de falhas, preservando fontes, rastreabilidade e revisão humana. Para mim, o critério de sucesso é permitir consultas úteis dentro das permissões de cada profissional, com evidências verificáveis e com a decisão final sob responsabilidade humana.

<a id="referencias"></a>

## 4 Referências bibliográficas

AUTIO, Chloe *et al.* **Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile**. Gaithersburg: National Institute of Standards and Technology, 2024. (NIST AI 600-1). DOI: 10.6028/NIST.AI.600-1. Disponível em: [https://doi.org/10.6028/NIST.AI.600-1](https://doi.org/10.6028/NIST.AI.600-1). Acesso em: 4 out. 2026.

BRASIL. **Lei nº 13.709, de 14 de agosto de 2018**. Lei Geral de Proteção de Dados Pessoais (LGPD). Brasília, DF: Presidência da República, 2018. Disponível em: [https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm). Acesso em: 4 out. 2026.

DEEPGRAM. **Your Data at Deepgram**. [S. l.]: Deepgram, [s. d.]. Disponível em: [https://developers.deepgram.com/trust-security/your-data](https://developers.deepgram.com/trust-security/your-data). Acesso em: 4 out. 2026.

GOOGLE. **Gemini API Additional Terms of Service**. [S. l.]: Google, [s. d.]. Disponível em: [https://ai.google.dev/gemini-api/terms](https://ai.google.dev/gemini-api/terms). Acesso em: 4 out. 2026.

OWASP FOUNDATION. **LLM01:2025 Prompt Injection**. [S. l.]: OWASP Foundation, 2025a. Disponível em: [https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM01_PromptInjection.html](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM01_PromptInjection.html). Acesso em: 4 out. 2026.

OWASP FOUNDATION. **LLM02:2025 Sensitive Information Disclosure**. [S. l.]: OWASP Foundation, 2025b. Disponível em: [https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM02_SensitiveInformationDisclosure.html](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM02_SensitiveInformationDisclosure.html). Acesso em: 4 out. 2026.

OWASP FOUNDATION. **LLM06:2025 Excessive Agency**. [S. l.]: OWASP Foundation, 2025c. Disponível em: [https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html). Acesso em: 4 out. 2026.

POSTGRESQL GLOBAL DEVELOPMENT GROUP. **Row Security Policies**. In: POSTGRESQL GLOBAL DEVELOPMENT GROUP. PostgreSQL 18 Documentation. [S. l.]: PostgreSQL Global Development Group, [s. d.]. Disponível em: [https://www.postgresql.org/docs/18/ddl-rowsecurity.html](https://www.postgresql.org/docs/18/ddl-rowsecurity.html). Acesso em: 4 out. 2026.

ROSE, Scott *et al.* **Zero Trust Architecture**. Gaithersburg: National Institute of Standards and Technology, 2020. (NIST Special Publication 800-207). DOI: 10.6028/NIST.SP.800-207. Disponível em: [https://doi.org/10.6028/NIST.SP.800-207](https://doi.org/10.6028/NIST.SP.800-207). Acesso em: 4 out. 2026.

SUPABASE. **Sign in with Azure (Microsoft)**. [S. l.]: Supabase, [s. d.]. Disponível em: [https://supabase.com/docs/guides/auth/social-login/auth-azure](https://supabase.com/docs/guides/auth/social-login/auth-azure). Acesso em: 4 out. 2026.

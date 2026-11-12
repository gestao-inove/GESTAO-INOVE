// Conector com a Central de Atendimento (WhatsApp).
//
// A Central chama estas rotas para mostrar, dentro do atendimento, o que está aqui no
// painel: os clientes (contatos), a ficha de cada um na conversa (apólices e certificados
// com vencimento, atendimentos em andamento, próximos agendamentos), o botão "Criar
// tarefa" (abre um atendimento no funil daqui) e a Agenda.
//
// Só LÊ o painel, com uma exceção: "Criar tarefa" cria um atendimento "Iniciado".
// Nada aqui muda o funcionamento do painel.
//
// Segurança: toda chamada leva "Authorization: Bearer <CONECTOR_TOKEN>". Sem a variável
// CONECTOR_TOKEN no Render, o conector fica DESLIGADO (responde 503).
//
// Pessoa, atendimento e apólice se ligam pelo NOME (sem acento, sem maiúscula), que é a
// mesma regra do próprio painel (ClienteProfileModal); o documento entra quando existe.

const crypto = require("crypto");

const ETAPAS = {
  iniciado: "Iniciado", cotacao: "Cotação enviada", aguardando: "Aguardando retorno",
  recusado: "Cliente recusou", aceito: "Cliente aceitou", solicitado: "Solicitado",
  agendado: "Agendado", emitido: "Emitido",
};
const ETAPAS_FINAIS = ["recusado", "emitido"];
const CATEGORIAS = { seguro: "Seguros", certificado: "Certificação digital", outros: "Outros" };
const PRODUTOS = {
  auto: "Seguro Auto", vida: "Seguro de Vida", residencial: "Seguro Residencial", empresarial: "Seguro Empresarial",
  rc: "Responsabilidade Civil", bike: "Seguro de Bike", saude: "Seguro Saúde", viagem: "Seguro Viagem",
  celular: "Seguro Celular/Eletrônicos", outro: "Outro", ecpf: "e-CPF", ecnpj: "e-CNPJ",
  servico: "Serviço avulso", comissao: "Comissão/indicação", reembolso: "Reembolso",
};

const produto = (subtipo) => PRODUTOS[String(subtipo || "").toLowerCase()] || String(subtipo || "").trim() || "Produto";
const soDigitos = (v) => String(v || "").replace(/\D/g, "");
const normalizar = (v) => String(v || "").normalize("NFD").replace(/[̀-ͯ]/g, "").trim().toLowerCase();
const dataBR = (iso) => (iso ? iso.split("-").reverse().join("/") : "");
function hojeBR() {
  try { return new Date().toLocaleDateString("sv-SE", { timeZone: "America/Sao_Paulo" }); }
  catch (e) { return new Date().toISOString().slice(0, 10); }
}
const novoId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

/** Token certo? Comparação em tempo constante. */
function tokenConfere(cabecalho, esperado) {
  const recebido = String(cabecalho || "").replace(/^Bearer\s+/i, "");
  if (!esperado || !recebido) return false;
  const a = Buffer.from(recebido), b = Buffer.from(esperado);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// DATE do Postgres sai como texto AAAA-MM-DD: sem fuso no meio do caminho.
const SQL_APOLICES = `SELECT id, nome, categoria, subtipo, notas,
  to_char(data_inicio, 'YYYY-MM-DD') AS inicio, to_char(data_vencimento, 'YYYY-MM-DD') AS vencimento
  FROM clientes`;
const SQL_ATENDIMENTOS = `SELECT id, cliente, categoria, subtipo, status, seguradora, documento,
  to_char(data_solicitacao, 'YYYY-MM-DD') AS solicitado, to_char(data_agendamento, 'YYYY-MM-DD') AS agendado
  FROM atendimentos`;

function registrarConector(app, pool) {
  const TOKEN = process.env.CONECTOR_TOKEN || "";

  app.use("/conector", (req, res, next) => {
    if (!TOKEN) return res.status(503).json({ erro: "Conector desligado: defina CONECTOR_TOKEN no Render." });
    if (!tokenConfere(req.headers.authorization, TOKEN)) return res.status(401).json({ erro: "Token inválido." });
    next();
  });

  app.get("/conector/ping", (req, res) => {
    res.json({ nome: "Inove · Painel de Gestão", recursos: ["empresas", "contexto", "tarefas", "agenda"] });
  });

  /** Os contatos do painel viram os clientes da Central. */
  app.get("/conector/empresas", async (req, res) => {
    try {
      const [contatos, apolices, atend] = await Promise.all([
        pool.query("SELECT id, nome, documento, telefone, email FROM contatos ORDER BY nome"),
        pool.query(SQL_APOLICES),
        pool.query(SQL_ATENDIMENTOS),
      ]);
      const hoje = hojeBR();
      // Por pessoa (nome normalizado): o que ela tem e de que área é.
      const porNome = new Map();
      const daPessoa = (nome) => {
        const k = normalizar(nome);
        if (!porNome.has(k)) porNome.set(k, { produtos: new Set(), categorias: {}, vencida: false });
        return porNome.get(k);
      };
      for (const a of apolices.rows) {
        const p = daPessoa(a.nome);
        p.produtos.add(produto(a.subtipo));
        p.categorias[a.categoria] = (p.categorias[a.categoria] || 0) + 1;
        if (a.vencimento && a.vencimento < hoje) p.vencida = true;
      }
      for (const a of atend.rows) {
        if (a.status !== "emitido") continue; // só o que ela de fato vendeu
        const p = daPessoa(a.cliente);
        p.produtos.add(produto(a.subtipo));
        p.categorias[a.categoria] = (p.categorias[a.categoria] || 0) + 1;
      }
      const empresas = contatos.rows.filter((c) => String(c.nome || "").trim()).map((c) => {
        const p = porNome.get(normalizar(c.nome));
        const principal = p ? Object.entries(p.categorias).sort((x, y) => y[1] - x[1])[0] : null;
        const etiquetas = p ? [...p.produtos].slice(0, 12) : [];
        if (p && p.vencida) etiquetas.push("Apólice vencida");
        return {
          id: String(c.id), nome: String(c.nome).trim(), documento: soDigitos(c.documento) || null,
          telefone: c.telefone || null, email: c.email || null,
          segmento: principal ? (CATEGORIAS[principal[0]] || principal[0]) : null,
          etiquetas,
        };
      });
      res.json({ empresas });
    } catch (e) {
      console.error("[conector] empresas:", e.message);
      res.status(500).json({ erro: "Falha ao ler os contatos." });
    }
  });

  /** Ficha do cliente na coluna lateral da conversa. */
  app.get("/conector/contexto", async (req, res) => {
    try {
      const { rows } = await pool.query("SELECT id, nome, documento, telefone, email FROM contatos WHERE id = $1", [String(req.query.empresaId || "")]);
      const c = rows[0];
      if (!c) return res.status(404).json({ erro: "Cliente não encontrado no painel." });
      const n = normalizar(c.nome), doc = soDigitos(c.documento);
      const hoje = hojeBR();
      const [apolices, atend, agenda] = await Promise.all([
        pool.query(SQL_APOLICES),
        pool.query(SQL_ATENDIMENTOS),
        pool.query(`SELECT id, cliente, subtipo, horario, notas, to_char(data, 'YYYY-MM-DD') AS data
                    FROM agendamentos WHERE data >= $1::date ORDER BY data, horario`, [hoje]),
      ]);
      const minhas = apolices.rows.filter((a) => normalizar(a.nome) === n)
        .sort((a, b) => String(a.vencimento || "9999").localeCompare(String(b.vencimento || "9999")));
      const meus = atend.rows.filter((a) => normalizar(a.cliente) === n || (doc && soDigitos(a.documento) === doc));
      const emAndamento = meus.filter((a) => !ETAPAS_FINAIS.includes(a.status))
        .sort((a, b) => String(b.solicitado || "").localeCompare(String(a.solicitado || "")));
      const proximos = agenda.rows.filter((a) => normalizar(a.cliente) === n).slice(0, 8);
      const proximoVenc = minhas.find((a) => a.vencimento && a.vencimento >= hoje);

      const resumo = [
        doc ? { rotulo: doc.length === 14 ? "CNPJ" : "CPF", valor: doc } : null,
        c.email ? { rotulo: "E-mail", valor: c.email } : null,
        { rotulo: "Apólices e certificados", valor: String(minhas.length) },
        proximoVenc ? { rotulo: "Próximo vencimento", valor: `${produto(proximoVenc.subtipo)} · ${dataBR(proximoVenc.vencimento)}` } : null,
      ].filter(Boolean);

      const blocos = [
        {
          titulo: "Apólices e certificados",
          // Com status = prazo: a Central mostra "vence dd/mm" e pinta de vermelho o vencido.
          itens: minhas.slice(0, 15).map((a) => ({
            titulo: produto(a.subtipo),
            detalhe: [CATEGORIAS[a.categoria] || a.categoria, a.inicio ? `desde ${dataBR(a.inicio)}` : null].filter(Boolean).join(" · "),
            data: a.vencimento || null,
            status: a.vencimento ? (a.vencimento < hoje ? "vencida" : "vigente") : null,
          })),
        },
        {
          titulo: "Atendimentos em andamento",
          itens: emAndamento.slice(0, 10).map((a) => ({
            titulo: produto(a.subtipo),
            detalhe: [ETAPAS[a.status] || a.status, a.seguradora].filter(Boolean).join(" · "),
            data: a.solicitado || null,
            status: null,
          })),
        },
        {
          titulo: "Próximos agendamentos",
          itens: proximos.map((a) => ({
            titulo: produto(a.subtipo),
            detalhe: [a.horario, a.notas].filter(Boolean).join(" · ").slice(0, 200),
            data: a.data,
            status: null,
          })),
        },
      ];
      res.json({ resumo, blocos });
    } catch (e) {
      console.error("[conector] contexto:", e.message);
      res.status(500).json({ erro: "Falha ao montar a ficha do cliente." });
    }
  });

  /** "Criar tarefa" na conversa = atendimento novo no funil daqui, na etapa Iniciado. */
  app.post("/conector/tarefas", async (req, res) => {
    try {
      const b = req.body || {};
      const { rows } = await pool.query("SELECT id, nome, documento FROM contatos WHERE id = $1", [String(b.empresaId || "")]);
      const c = rows[0];
      if (!c) return res.status(404).json({ erro: "Cliente não encontrado no painel." });
      const titulo = String(b.titulo || "").trim().slice(0, 200);
      if (!titulo) return res.status(400).json({ erro: "Informe o título." });
      const notas = [titulo, String(b.descricao || "").trim(), b.vencimento ? `Prazo: ${dataBR(String(b.vencimento).slice(0, 10))}` : "", "(criado pelo Atendimento WhatsApp)"]
        .filter(Boolean).join("\n").slice(0, 4000);
      const id = novoId();
      await pool.query(
        `INSERT INTO atendimentos (id, cliente, categoria, subtipo, data_solicitacao, documento, status, notas)
         VALUES ($1,$2,'outros','outro',$3,$4,'iniciado',$5)`,
        [id, c.nome, hojeBR(), soDigitos(c.documento) || null, notas]
      );
      res.json({ ok: true, id });
    } catch (e) {
      console.error("[conector] tarefas:", e.message);
      res.status(500).json({ erro: "Falha ao criar o atendimento." });
    }
  });

  /** Agenda: agendamentos e vencimentos de apólices/certificados no período. */
  app.get("/conector/agenda", async (req, res) => {
    const de = String(req.query.de || ""), ate = String(req.query.ate || "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(de) || !/^\d{4}-\d{2}-\d{2}$/.test(ate)) return res.status(400).json({ erro: "Período inválido." });
    try {
      const hoje = hojeBR();
      const [ag, venc] = await Promise.all([
        pool.query(`SELECT cliente, subtipo, horario, to_char(data, 'YYYY-MM-DD') AS data
                    FROM agendamentos WHERE data BETWEEN $1::date AND $2::date ORDER BY data, horario`, [de, ate]),
        pool.query(`SELECT nome, subtipo, to_char(data_vencimento, 'YYYY-MM-DD') AS data
                    FROM clientes WHERE data_vencimento BETWEEN $1::date AND $2::date ORDER BY data_vencimento`, [de, ate]),
      ]);
      const itens = [
        ...ag.rows.map((a) => ({ data: a.data, titulo: `${produto(a.subtipo)}${a.horario ? ` · ${a.horario}` : ""}`, empresa: a.cliente, status: null })),
        ...venc.rows.map((v) => ({ data: v.data, titulo: `Vence: ${produto(v.subtipo)}`, empresa: v.nome, status: v.data < hoje ? "vencida" : "vence" })),
      ].sort((x, y) => x.data.localeCompare(y.data));
      res.json({ itens });
    } catch (e) {
      console.error("[conector] agenda:", e.message);
      res.status(500).json({ erro: "Falha ao ler a agenda." });
    }
  });
}

module.exports = { registrarConector, normalizar, tokenConfere };

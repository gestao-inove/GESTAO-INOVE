const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // necessário para conectar no Aiven
});

// ---------- healthcheck ----------
app.get("/", (req, res) => res.send("API do Painel da Corretora no ar."));

// ---------- AUTENTICAÇÃO ----------
const crypto = require("crypto");

// Credenciais vêm de variáveis de ambiente (nunca ficam no código)
const AUTH_USER = process.env.AUTH_USER || "";
const AUTH_PASS_HASH = process.env.AUTH_PASS_HASH || ""; // hash SHA-256 da senha
const SESSION_SECRET = process.env.SESSION_SECRET || "troque-este-segredo";

// Duração da sessão: 30 minutos
const SESSION_MINUTES = 30;

function sha256(txt) {
  return crypto.createHash("sha256").update(txt).digest("hex");
}

// Gera um token assinado com validade embutida
function gerarToken() {
  const exp = Date.now() + SESSION_MINUTES * 60 * 1000;
  const payload = String(exp);
  const assinatura = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return payload + "." + assinatura;
}

function tokenValido(token) {
  if (!token || !token.includes(".")) return false;
  const [payload, assinatura] = token.split(".");
  const esperada = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  if (assinatura !== esperada) return false;
  const exp = Number(payload);
  return Date.now() < exp;
}

// Rota de login
app.post("/api/login", (req, res) => {
  const { usuario, senha } = req.body || {};
  if (!AUTH_USER || !AUTH_PASS_HASH) {
    return res.status(500).json({ error: "Login não configurado no servidor." });
  }
  if (usuario === AUTH_USER && sha256(senha || "") === AUTH_PASS_HASH) {
    return res.json({ token: gerarToken() });
  }
  return res.status(401).json({ error: "Usuário ou senha incorretos." });
});

// Verifica se o token ainda é válido (usado para saber se a sessão expirou)
app.get("/api/verificar", (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (tokenValido(token)) return res.json({ ok: true });
  return res.status(401).json({ error: "Sessão expirada." });
});

// Middleware: exige token válido em todas as rotas /api/* (menos login e verificar)
app.use("/api", (req, res, next) => {
  if (req.path === "/login" || req.path === "/verificar" || req.path === "/google/callback") return next();
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (tokenValido(token)) return next();
  return res.status(401).json({ error: "Não autorizado." });
});

// ---------- INTEGRAÇÃO GOOGLE AGENDA ----------
const { google } = require("googleapis");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "https://gestao-inove.onrender.com/api/google/callback";
const GOOGLE_SCOPES = ["https://www.googleapis.com/auth/calendar"];

function googleConfigurado() {
  return Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
}
function novoOAuthClient() {
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
}

// Guarda os tokens do Google numa linha única (id=1). Mantém o refresh_token se um novo não vier.
async function salvarTokensGoogle(tokens) {
  await pool.query(
    `INSERT INTO google_auth (id, access_token, refresh_token, expiry_date, updated_at)
     VALUES (1, $1, $2, $3, now())
     ON CONFLICT (id) DO UPDATE SET
       access_token = EXCLUDED.access_token,
       refresh_token = COALESCE(EXCLUDED.refresh_token, google_auth.refresh_token),
       expiry_date = EXCLUDED.expiry_date,
       updated_at = now()`,
    [tokens.access_token || null, tokens.refresh_token || null, tokens.expiry_date || null]
  );
}
async function carregarTokensGoogle() {
  const { rows } = await pool.query("SELECT * FROM google_auth WHERE id = 1");
  return rows[0] || null;
}

// "state" assinado (reaproveita o SESSION_SECRET) para proteger o callback contra chamadas externas
function gerarState() {
  const exp = Date.now() + 10 * 60 * 1000; // 10 min
  const payload = "google." + exp;
  const assinatura = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return payload + "." + assinatura;
}
function stateValido(state) {
  if (!state) return false;
  const partes = String(state).split(".");
  if (partes.length !== 3) return false;
  const payload = partes[0] + "." + partes[1];
  const esperada = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  if (partes[2] !== esperada) return false;
  return Date.now() < Number(partes[1]);
}

// Inicia a conexão: devolve a URL de autorização do Google (protegida pelo nosso login)
app.get("/api/google/connect", (req, res) => {
  if (!googleConfigurado()) return res.status(500).json({ error: "Google não configurado no servidor." });
  const oauth2 = novoOAuthClient();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: GOOGLE_SCOPES,
    state: gerarState(),
  });
  res.json({ url });
});

// Callback do Google (isento do middleware: o Google redireciona o navegador sem o nosso token)
app.get("/api/google/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!stateValido(state)) return res.status(400).send("Link expirado ou inválido. Volte ao painel e clique em conectar novamente.");
  if (!code) return res.status(400).send("Código ausente.");
  try {
    const oauth2 = novoOAuthClient();
    const { tokens } = await oauth2.getToken(code);
    await salvarTokensGoogle(tokens);
    res.send("<html><body style='font-family:sans-serif;text-align:center;padding:48px'><h2>&#9989; Google Agenda conectado!</h2><p>Pode fechar esta aba e voltar ao painel.</p></body></html>");
  } catch (e) {
    console.error(e);
    res.status(500).send("Falha ao conectar com o Google. Volte ao painel e tente novamente.");
  }
});

// Status da conexão
app.get("/api/google/status", async (req, res) => {
  try {
    const t = await carregarTokensGoogle();
    res.json({ conectado: Boolean(t && t.refresh_token), configurado: googleConfigurado() });
  } catch (e) {
    console.error(e);
    res.json({ conectado: false, configurado: googleConfigurado() });
  }
});

// Desconectar
app.post("/api/google/disconnect", async (req, res) => {
  try {
    await pool.query("DELETE FROM google_auth WHERE id = 1");
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao desconectar." });
  }
});

// ---------- ATENDIMENTOS ----------
app.get("/api/atendimentos", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM atendimentos ORDER BY criado_em DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar atendimentos" });
  }
});

app.post("/api/atendimentos", async (req, res) => {
  const { id, cliente, categoria, subtipo, horarioSolicitado, dataSolicitacao, dataAgendamento, horarioAgendamento, valor, comissao, seguradora, pagamento, status, notas } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO atendimentos (id, cliente, categoria, subtipo, horario_solicitado, data_solicitacao, data_agendamento, horario_agendamento, valor, comissao, seguradora, pagamento, status, notas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [id, cliente, categoria, subtipo, horarioSolicitado || null, dataSolicitacao || null, dataAgendamento || null, horarioAgendamento || null, valor != null ? valor : null, comissao != null ? comissao : null, seguradora || null, pagamento || null, status || "iniciado", notas || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar atendimento" });
  }
});

app.patch("/api/atendimentos/:id", async (req, res) => {
  const fields = {
    cliente: req.body.cliente,
    categoria: req.body.categoria,
    subtipo: req.body.subtipo,
    horario_solicitado: req.body.horarioSolicitado,
    data_solicitacao: req.body.dataSolicitacao || null,
    data_agendamento: req.body.dataAgendamento || null,
    horario_agendamento: req.body.horarioAgendamento,
    valor: req.body.valor != null ? req.body.valor : undefined,
    comissao: req.body.comissao != null ? req.body.comissao : undefined,
    seguradora: req.body.seguradora,
    pagamento: req.body.pagamento,
    status: req.body.status,
    notas: req.body.notas,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE atendimentos SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar atendimento" });
  }
});

app.delete("/api/atendimentos/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM atendimentos WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir atendimento" });
  }
});

// ---------- AGENDAMENTOS ----------
app.get("/api/agendamentos", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM agendamentos ORDER BY data, horario");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar agendamentos" });
  }
});

app.post("/api/agendamentos", async (req, res) => {
  const { id, cliente, categoria, subtipo, data, horario, notas, atendimentoId } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO agendamentos (id, cliente, categoria, subtipo, data, horario, notas, atendimento_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id, cliente, categoria, subtipo, data, horario, notas || null, atendimentoId || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar agendamento" });
  }
});

app.patch("/api/agendamentos/:id", async (req, res) => {
  const fields = {
    cliente: req.body.cliente,
    categoria: req.body.categoria,
    subtipo: req.body.subtipo,
    data: req.body.data,
    horario: req.body.horario,
    notas: req.body.notas,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE agendamentos SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar agendamento" });
  }
});

app.delete("/api/agendamentos/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM agendamentos WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir agendamento" });
  }
});

// ---------- FINANCEIRO ----------
app.get("/api/financeiro", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM financeiro ORDER BY data DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar lançamentos" });
  }
});

app.post("/api/financeiro", async (req, res) => {
  const { id, cliente, categoria, subtipo, valorPago, custo, forma, data, pago, atendimentoId, parcela, totalParcelas } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO financeiro (id, cliente, categoria, subtipo, valor_pago, custo, forma, data, pago, atendimento_id, parcela, total_parcelas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [id, cliente, categoria, subtipo, valorPago || 0, custo || 0, forma || null, data, pago !== false, atendimentoId || null, parcela != null ? parcela : null, totalParcelas != null ? totalParcelas : null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar lançamento" });
  }
});

app.patch("/api/financeiro/:id", async (req, res) => {
  const fields = {
    cliente: req.body.cliente,
    categoria: req.body.categoria,
    subtipo: req.body.subtipo,
    valor_pago: req.body.valorPago,
    custo: req.body.custo,
    forma: req.body.forma,
    data: req.body.data,
    pago: req.body.pago,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE financeiro SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar lançamento" });
  }
});

app.delete("/api/financeiro/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM financeiro WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir lançamento" });
  }
});

// ---------- CARTÕES DE CRÉDITO ----------
app.get("/api/cartoes", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM cartoes ORDER BY nome");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar cartões" });
  }
});

app.post("/api/cartoes", async (req, res) => {
  const { id, nome, cor, diaVencimento } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO cartoes (id, nome, cor, dia_vencimento) VALUES ($1,$2,$3,$4) RETURNING *`,
      [id, nome, cor || null, diaVencimento != null ? diaVencimento : null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar cartão" });
  }
});

app.delete("/api/cartoes/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM cartoes WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir cartão" });
  }
});

// ---------- COMPRAS PARCELADAS NO CARTÃO ----------
app.get("/api/compras-cartao", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM compras_cartao ORDER BY data_compra DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar compras" });
  }
});

app.post("/api/compras-cartao", async (req, res) => {
  const { id, cartaoId, descricao, valorParcela, dataCompra, parcelas, notas } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO compras_cartao (id, cartao_id, descricao, valor_parcela, data_compra, parcelas, notas)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [id, cartaoId, descricao, valorParcela || 0, dataCompra, parcelas || 1, notas || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar compra" });
  }
});

app.patch("/api/compras-cartao/:id", async (req, res) => {
  const fields = {
    descricao: req.body.descricao,
    valor_parcela: req.body.valorParcela,
    data_compra: req.body.dataCompra,
    parcelas: req.body.parcelas,
    notas: req.body.notas,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE compras_cartao SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar compra" });
  }
});

app.delete("/api/compras-cartao/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM compras_cartao WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir compra" });
  }
});

// ---------- DESPESAS PESSOAIS (avulsas/fixas) ----------
app.get("/api/despesas", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM despesas ORDER BY data DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar despesas" });
  }
});

app.post("/api/despesas", async (req, res) => {
  const { id, titulo, tipo, valor, data, notas, forma } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO despesas (id, titulo, tipo, valor, data, notas, forma) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [id, titulo, tipo, valor || 0, data, notas || null, forma || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar despesa" });
  }
});

app.patch("/api/despesas/:id", async (req, res) => {
  const fields = {
    titulo: req.body.titulo,
    tipo: req.body.tipo,
    valor: req.body.valor,
    data: req.body.data,
    notas: req.body.notas,
    forma: req.body.forma,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE despesas SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar despesa" });
  }
});

app.delete("/api/despesas/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM despesas WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir despesa" });
  }
});

// ---------- CLIENTES ----------
app.get("/api/clientes", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM clientes ORDER BY nome");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar clientes" });
  }
});

app.post("/api/clientes", async (req, res) => {
  const { id, nome, categoria, subtipo, dataInicio, dataVencimento, notas, atendimentoId } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO clientes (id, nome, categoria, subtipo, data_inicio, data_vencimento, notas, atendimento_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id, nome, categoria, subtipo, dataInicio, dataVencimento || null, notas || null, atendimentoId || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar cliente" });
  }
});

app.patch("/api/clientes/:id", async (req, res) => {
  const fields = {
    nome: req.body.nome,
    categoria: req.body.categoria,
    subtipo: req.body.subtipo,
    data_inicio: req.body.dataInicio,
    data_vencimento: req.body.dataVencimento,
    notas: req.body.notas,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE clientes SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar cliente" });
  }
});

app.delete("/api/clientes/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM clientes WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir cliente" });
  }
});

// ---------- PAGAMENTOS DE FATURA DO CARTÃO ----------
app.get("/api/pagamentos-fatura", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM pagamentos_fatura ORDER BY data DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar pagamentos de fatura" });
  }
});

app.post("/api/pagamentos-fatura", async (req, res) => {
  const { id, cartaoId, contaId, mes, valor, data, movimentacaoId } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO pagamentos_fatura (id, cartao_id, conta_id, mes, valor, data, movimentacao_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [id, cartaoId, contaId, mes, valor || 0, data, movimentacaoId || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao registrar pagamento da fatura" });
  }
});

app.delete("/api/pagamentos-fatura/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM pagamentos_fatura WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir pagamento da fatura" });
  }
});

// ---------- CONTAS PESSOAIS ----------
app.get("/api/contas", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM contas_pf ORDER BY nome");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar contas" });
  }
});

app.post("/api/contas", async (req, res) => {
  const { id, nome, saldoInicial, tipo, principal } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO contas_pf (id, nome, saldo_inicial, tipo, principal) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [id, nome, saldoInicial || 0, tipo || "pf", principal === true]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar conta" });
  }
});

app.patch("/api/contas/:id", async (req, res) => {
  const fields = { nome: req.body.nome, saldo_inicial: req.body.saldoInicial, tipo: req.body.tipo, principal: req.body.principal };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE contas_pf SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar conta" });
  }
});

app.delete("/api/contas/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM contas_pf WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir conta" });
  }
});

// ---------- MOVIMENTAÇÕES DAS CONTAS ----------
app.get("/api/movimentacoes", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM movimentacoes ORDER BY data DESC");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar movimentações" });
  }
});

app.post("/api/movimentacoes", async (req, res) => {
  const { id, contaId, tipo, valor, descricao, data } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO movimentacoes (id, conta_id, tipo, valor, descricao, data)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [id, contaId, tipo, valor || 0, descricao || null, data]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar movimentação" });
  }
});

app.delete("/api/movimentacoes/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM movimentacoes WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir movimentação" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));

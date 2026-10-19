const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json({ limit: "12mb" })); // permite anexos (arquivos em base64)

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
  if (req.path === "/login" || req.path === "/verificar" || req.path === "/google/callback"
      || req.path === "/formulario" || req.path === "/telegram/webhook") return next();
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

// Data de hoje no horário de Brasília (o servidor roda em UTC: depois das 21h já seria "amanhã")
function dataHojeBR() {
  try { return new Date().toLocaleDateString("sv-SE", { timeZone: "America/Sao_Paulo" }); }
  catch (e) { return new Date().toISOString().slice(0, 10); }
}

// ---------- FORMULÁRIO PÚBLICO DO CLIENTE ----------
// Recebe o formulário que o cliente preenche no site e abre o atendimento sozinho.
// É público (o cliente não tem login), então: só CRIA, valida tudo e limita por IP.
const FORM_KEY = process.env.FORM_KEY || "inove-form-2026";
const enviosPorIp = {};
function podeEnviarForm(ip) {
  const agora = Date.now();
  const lista = (enviosPorIp[ip] || []).filter((t) => agora - t < 60 * 60 * 1000); // última hora
  if (lista.length >= 10) { enviosPorIp[ip] = lista; return false; }
  lista.push(agora); enviosPorIp[ip] = lista;
  return true;
}
function campoTxt(v, max) { return String(v == null ? "" : v).trim().slice(0, max || 200); }
function formatarCpf(d) {
  return d && d.length === 11 ? d.slice(0,3)+"."+d.slice(3,6)+"."+d.slice(6,9)+"-"+d.slice(9) : d;
}

app.post("/api/formulario", async (req, res) => {
  const ip = String(req.headers["x-forwarded-for"] || req.ip || "?").split(",")[0].trim();
  if (!podeEnviarForm(ip)) return res.status(429).json({ error: "Muitos envios seguidos. Tente mais tarde." });
  if (campoTxt(req.body.chave, 60) !== FORM_KEY) return res.status(401).json({ error: "Formulário não autorizado." });

  const SUB_OK = ["auto","vida","residencial","empresarial","rc","bike","saude","viagem","celular","outro"];
  const sub = campoTxt(req.body.subtipo, 20);
  const subtipo = SUB_OK.indexOf(sub) > -1 ? sub : "outro";
  const documento = campoTxt(req.body.documento, 30).replace(/\D/g, "");
  const telefone = campoTxt(req.body.telefone, 30);
  const notas = campoTxt(req.body.notas, 4000);
  const hoje = dataHojeBR();
  const novoId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  try {
    // Se esse CPF já é cliente, o atendimento já nasce com o nome certo
    let nome = "";
    let contatoId = null;
    if (documento) {
      const { rows } = await pool.query(
        `SELECT id, nome FROM contatos
         WHERE documento IS NOT NULL AND regexp_replace(documento, '[^0-9]', '', 'g') = $1
         LIMIT 1`,
        [documento]
      );
      if (rows.length) { nome = rows[0].nome || ""; contatoId = rows[0].id; }
    }
    if (!nome) nome = "Novo cliente · CPF " + (formatarCpf(documento) || "não informado");

    await pool.query(
      `INSERT INTO atendimentos (id, cliente, categoria, subtipo, data_solicitacao, documento, status, notas)
       VALUES ($1,$2,'seguro',$3,$4,$5,'iniciado',$6)`,
      [novoId(), nome, subtipo, hoje, documento || null, notas || null]
    );

    // Cliente novo entra na base de contatos pra da próxima vez já vir com nome
    if (documento && !contatoId) {
      await pool.query(
        `INSERT INTO contatos (id, nome, documento, telefone, email) VALUES ($1,$2,$3,$4,$5)`,
        [novoId(), nome, documento, telefone || null, null]
      );
    }
    res.status(201).json({ ok: true });
  } catch (e) {
    console.error("Erro no formulário público:", e);
    res.status(500).json({ error: "Erro ao registrar o formulário" });
  }
});

// ---------- ROBÔ DO TELEGRAM (lança gastos e recebimentos por mensagem) ----------
// Variáveis no Render: TELEGRAM_TOKEN (do @BotFather) e TELEGRAM_ALLOWED_ID (seu ID; pode ser mais de um, separados por vírgula).
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN || "";
const TELEGRAM_ALLOWED = String(process.env.TELEGRAM_ALLOWED_ID || "").split(",").map((s) => s.trim()).filter(Boolean);
const PUBLIC_URL = process.env.PUBLIC_URL || "https://gestao-inove.onrender.com";
// O "segredo do webhook" é derivado do token: só o Telegram sabe, e você não precisa criar nada além do token
const TELEGRAM_SECRET = TELEGRAM_TOKEN
  ? crypto.createHmac("sha256", SESSION_SECRET).update("telegram:" + TELEGRAM_TOKEN).digest("hex")
  : "";
const ultimoLancBot = {}; // chat -> { tabela, id }  (para o "desfazer"; vale enquanto o servidor está acordado)

function idBot() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function semAcento(s) { return String(s).normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase(); }
function fmtBRL(n) { return "R$ " + Number(n).toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

async function telegramEnviar(chatId, texto) {
  if (!TELEGRAM_TOKEN || typeof fetch !== "function") return;
  try {
    await fetch("https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: texto }),
    });
  } catch (e) { console.error("Telegram sendMessage falhou:", e.message); }
}

// "50", "50,90", "1.200,50", "R$ 80" -> número (ou null)
function lerValor(tok) {
  let s = String(tok).replace(/r\$/i, "").trim();
  if (!/^\d[\d.,]*$/.test(s)) return null;
  if (/^\d+\.\d{1,2}$/.test(s)) return parseFloat(s);          // 50.90
  s = s.replace(/\./g, "").replace(",", ".");                    // 1.200,50
  const n = parseFloat(s);
  return isNaN(n) || n <= 0 ? null : n;
}

// Entende frases como: "gastei 50 mercado", "empresa 120 internet pix", "recebi 300 João"
function interpretarMensagem(texto) {
  const orig = String(texto || "").trim().replace(/\s+/g, " ");
  if (!orig) return null;
  const toks = orig.split(" ");
  const norm = toks.map(semAcento);

  let tipo = null, i = 0;
  const w0 = norm[0];
  if (["recebi", "recebimento", "entrada", "entrou"].indexOf(w0) > -1) { tipo = "receita"; i = 1; }
  else if (["empresa", "negocio"].indexOf(w0) > -1) { tipo = "empresa"; i = 1; }
  else if (["gastei", "paguei", "gasto", "despesa", "comprei"].indexOf(w0) > -1) {
    tipo = "pessoal"; i = 1;
    // "gastei na empresa 120 internet" / "gasto empresa 120 ..."
    let j = i; if (["na", "da", "no", "do", "pela", "pelo"].indexOf(norm[j]) > -1) j++;
    if (["empresa", "negocio"].indexOf(norm[j]) > -1) { tipo = "empresa"; i = j + 1; }
  }
  if (!tipo) return null;

  let valor = null, forma = null;
  const desc = [];
  const FILLER = ["de", "do", "da", "no", "na", "em", "com", "reais", "real", "para", "pra", "o", "a"];
  for (let k = i; k < toks.length; k++) {
    if (norm[k] === "r$") continue;                               // "R$ 50" (cifrão separado do número)
    const v = valor === null ? lerValor(toks[k]) : null;
    if (v !== null) { valor = v; continue; }
    if (["pix", "boleto", "dinheiro"].indexOf(norm[k]) > -1) { forma = norm[k] === "pix" ? "Pix" : norm[k] === "boleto" ? "Boleto" : "Dinheiro"; continue; }
    desc.push({ t: toks[k], n: norm[k] });
  }
  if (valor === null) return { erro: "valor" };
  while (desc.length && FILLER.indexOf(desc[0].n) > -1) desc.shift();   // tira "de/do/na" do começo
  const descricao = desc.map((d) => d.t).join(" ").trim();
  return { tipo, valor, forma, descricao };
}

const AJUDA_BOT =
  "Como lançar:\n\n" +
  "• gastei 50 mercado → gasto pessoal\n" +
  "• empresa 120 internet → gasto da empresa\n" +
  "• recebi 300 João → recebimento\n\n" +
  "Opcional: coloque pix, boleto ou dinheiro na frase.\n" +
  "Para apagar o último lançamento: desfazer";

async function lancarPeloBot(chatId, p) {
  const hoje = dataHojeBR();
  const mk = hoje.slice(0, 7);
  if (p.tipo === "receita") {
    const id = idBot();
    await pool.query(
      `INSERT INTO financeiro (id, cliente, categoria, subtipo, valor_pago, custo, forma, data, pago)
       VALUES ($1,$2,'outros','servico',$3,0,$4,$5,true)`,
      [id, p.descricao || "Recebimento", p.valor, p.forma, hoje]
    );
    ultimoLancBot[chatId] = { tabela: "financeiro", id };
    return "✅ Recebimento lançado: " + fmtBRL(p.valor) + " · " + (p.descricao || "Recebimento");
  }
  const id = idBot();
  const tipoDb = p.tipo === "empresa" ? "negocio_avulso" : "avulso";
  await pool.query(
    `INSERT INTO despesas (id, titulo, tipo, valor, data, notas, forma, pago, meses_pagos, datas_pagas)
     VALUES ($1,$2,$3,$4,$5,'via Telegram',$6,true,'[]',$7)`,
    [id, p.descricao || "Sem descrição", tipoDb, p.valor, hoje, p.forma, JSON.stringify({ [mk]: hoje })]
  );
  ultimoLancBot[chatId] = { tabela: "despesas", id };
  return "✅ " + (p.tipo === "empresa" ? "Gasto da empresa" : "Gasto pessoal") + " lançado: " + fmtBRL(p.valor) + " · " + (p.descricao || "Sem descrição");
}

app.post("/api/telegram/webhook", async (req, res) => {
  if (!TELEGRAM_TOKEN) return res.sendStatus(503);
  // só aceita chamadas que vieram do Telegram (ele manda o segredo no cabeçalho)
  if (req.headers["x-telegram-bot-api-secret-token"] !== TELEGRAM_SECRET) return res.sendStatus(401);

  const msg = req.body && req.body.message;
  res.sendStatus(200); // responde já, para o Telegram não repetir a entrega
  if (!msg || !msg.chat || !msg.from) return;

  const chatId = msg.chat.id;
  const userId = String(msg.from.id);
  const texto = String(msg.text || msg.caption || "").trim();

  try {
    if (TELEGRAM_ALLOWED.indexOf(userId) === -1) {
      await telegramEnviar(chatId, "Este robô é privado.\nSeu ID do Telegram é: " + userId + "\nPeça para liberar esse número no servidor.");
      return;
    }
    const baixo = semAcento(texto);
    if (baixo === "/start" || baixo === "/ajuda" || baixo === "ajuda") { await telegramEnviar(chatId, "Olá! Sou o robô do Painel Inove. 👋\n\n" + AJUDA_BOT); return; }

    if (baixo === "desfazer" || baixo === "/desfazer") {
      const u = ultimoLancBot[chatId];
      if (!u) { await telegramEnviar(chatId, "Não tenho um lançamento recente para desfazer. Se precisar, apague direto no painel."); return; }
      await pool.query("DELETE FROM " + (u.tabela === "financeiro" ? "financeiro" : "despesas") + " WHERE id = $1", [u.id]);
      delete ultimoLancBot[chatId];
      await telegramEnviar(chatId, "↩️ Último lançamento apagado.");
      return;
    }

    if (!texto && (msg.photo || msg.document)) {
      await telegramEnviar(chatId, "Recebi a foto, mas por enquanto só entendo mensagens de texto. Digite, por exemplo: gastei 50 mercado");
      return;
    }

    const p = interpretarMensagem(texto);
    if (!p) { await telegramEnviar(chatId, "Não entendi. 🤔\n\n" + AJUDA_BOT); return; }
    if (p.erro === "valor") { await telegramEnviar(chatId, "Faltou o valor. Exemplo: gastei 50 mercado"); return; }
    await telegramEnviar(chatId, await lancarPeloBot(chatId, p));
  } catch (e) {
    console.error("Erro no robô do Telegram:", e);
    await telegramEnviar(chatId, "Deu erro ao lançar. Tente de novo em instantes.");
  }
});

// Ao ligar o servidor, registra o endereço do robô no Telegram (só roda se o token existir)
async function registrarWebhookTelegram() {
  if (!TELEGRAM_TOKEN || typeof fetch !== "function") return;
  try {
    const r = await fetch("https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/setWebhook", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: PUBLIC_URL + "/api/telegram/webhook", secret_token: TELEGRAM_SECRET, allowed_updates: ["message"] }),
    });
    const j = await r.json();
    console.log("Telegram webhook:", j.ok ? "registrado" : "falhou — " + (j.description || r.status));
  } catch (e) { console.error("Telegram setWebhook falhou:", e.message); }
}

app.post("/api/atendimentos", async (req, res) => {
  const { id, cliente, categoria, subtipo, horarioSolicitado, dataSolicitacao, dataAgendamento, horarioAgendamento, valor, custo, documento, comissao, seguradora, pagamento, status, notas, forma, previsaoRecebimento } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO atendimentos (id, cliente, categoria, subtipo, horario_solicitado, data_solicitacao, data_agendamento, horario_agendamento, valor, custo, documento, comissao, seguradora, pagamento, status, notas, forma, previsao_recebimento)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING *`,
      [id, cliente, categoria, subtipo, horarioSolicitado || null, dataSolicitacao || null, dataAgendamento || null, horarioAgendamento || null, valor != null ? valor : null, custo != null ? custo : null, documento || null, comissao != null ? comissao : null, seguradora || null, pagamento || null, status || "iniciado", notas || null, forma || null, previsaoRecebimento || null]
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
    data_solicitacao: req.body.dataSolicitacao !== undefined ? (req.body.dataSolicitacao || null) : undefined,
    data_agendamento: req.body.dataAgendamento !== undefined ? (req.body.dataAgendamento || null) : undefined,
    horario_agendamento: req.body.horarioAgendamento,
    valor: req.body.valor != null ? req.body.valor : undefined,
    custo: req.body.custo != null ? req.body.custo : undefined,
    documento: req.body.documento,
    comissao: req.body.comissao != null ? req.body.comissao : undefined,
    seguradora: req.body.seguradora,
    pagamento: req.body.pagamento,
    forma: req.body.forma,
    previsao_recebimento: req.body.previsaoRecebimento !== undefined ? (req.body.previsaoRecebimento || null) : undefined,
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

// ---------- CONTATOS (base de clientes) ----------
app.get("/api/contatos", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM contatos ORDER BY nome");
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar contatos" });
  }
});

app.post("/api/contatos", async (req, res) => {
  const { id, nome, documento, telefone, email } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO contatos (id, nome, documento, telefone, email)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [id, nome, documento || null, telefone || null, email || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar contato" });
  }
});

app.patch("/api/contatos/:id", async (req, res) => {
  const fields = {
    nome: req.body.nome,
    documento: req.body.documento,
    telefone: req.body.telefone,
    email: req.body.email,
  };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE contatos SET ${setClause} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar contato" });
  }
});

app.delete("/api/contatos/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM contatos WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir contato" });
  }
});

// ---------- ANEXOS (arquivos dos clientes) ----------
// Lista só os metadados (sem o conteúdo do arquivo, pra ficar leve)
app.get("/api/anexos", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, cliente, documento, nome, legenda, tipo, tamanho, criado_em
       FROM anexos ORDER BY criado_em DESC`
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar anexos" });
  }
});

// Retorna UM anexo completo (com o conteúdo em base64) — só quando for visualizar/baixar
app.get("/api/anexos/:id", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM anexos WHERE id = $1", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Anexo não encontrado" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar anexo" });
  }
});

app.post("/api/anexos", async (req, res) => {
  const { id, cliente, documento, nome, legenda, tipo, tamanho, dados } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO anexos (id, cliente, documento, nome, legenda, tipo, tamanho, dados)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, cliente, documento, nome, legenda, tipo, tamanho, criado_em`,
      [id, cliente || null, documento || null, nome || null, legenda || null, tipo || null, tamanho || null, dados || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao salvar anexo" });
  }
});

app.patch("/api/anexos/:id", async (req, res) => {
  const fields = { cliente: req.body.cliente, legenda: req.body.legenda };
  const keys = Object.keys(fields).filter((k) => fields[k] !== undefined);
  if (keys.length === 0) return res.status(400).json({ error: "Nada para atualizar" });
  const setClause = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const values = keys.map((k) => fields[k]);
  values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      `UPDATE anexos SET ${setClause} WHERE id = $${values.length}
       RETURNING id, cliente, documento, nome, legenda, tipo, tamanho, criado_em`,
      values
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao atualizar anexo" });
  }
});

app.delete("/api/anexos/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM anexos WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir anexo" });
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
  const { id, titulo, tipo, valor, data, notas, forma, pago, mesesPagos, datasPagas } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO despesas (id, titulo, tipo, valor, data, notas, forma, pago, meses_pagos, datas_pagas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [id, titulo, tipo, valor || 0, data, notas || null, forma || null, pago === true, JSON.stringify(Array.isArray(mesesPagos) ? mesesPagos : []), JSON.stringify(datasPagas && typeof datasPagas === "object" ? datasPagas : {})]
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
    pago: req.body.pago,
    meses_pagos: req.body.mesesPagos !== undefined ? JSON.stringify(Array.isArray(req.body.mesesPagos) ? req.body.mesesPagos : []) : undefined,
    datas_pagas: req.body.datasPagas !== undefined ? JSON.stringify(req.body.datasPagas && typeof req.body.datasPagas === "object" ? req.body.datasPagas : {}) : undefined,
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
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
  registrarWebhookTelegram();
});

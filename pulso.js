// Mantém o banco do Aiven (plano gratuito) acordado: de tempos em tempos grava uma linha
// e apaga em seguida. Não guarda dado nenhum, só reseta o relógio de inatividade do Aiven.
//
// Só funciona com o Render acordado. O plano gratuito do Render dorme depois de ~15 min sem
// visita: quem mantém o processo (e este relógio) vivo é o robô monitor batendo em /saude.
//
// PULSO_BANCO_HORAS define o intervalo (padrão 6; 0 desliga).

const estado = { ultimoPulso: null, ok: null };

function situacaoDoPulso() {
  return { ...estado };
}

async function pulsar(pool) {
  try {
    await pool.query(
      "CREATE TABLE IF NOT EXISTS pulso_banco (id BIGSERIAL PRIMARY KEY, criado_em TIMESTAMPTZ NOT NULL DEFAULT now())"
    );
    const { rows } = await pool.query("INSERT INTO pulso_banco DEFAULT VALUES RETURNING id");
    await pool.query("DELETE FROM pulso_banco WHERE id = $1", [rows[0].id]);
    // Rede de segurança: se um DELETE anterior falhou no meio, não deixa acumular.
    await pool.query("DELETE FROM pulso_banco WHERE criado_em < now() - interval '1 day'");
    estado.ultimoPulso = new Date().toISOString();
    estado.ok = true;
  } catch (e) {
    estado.ok = false;
    console.error("[pulso] falhou:", e.message);
  }
  return situacaoDoPulso();
}

// O primeiro pulso sai 1 minuto depois da subida: todo deploy e todo despertar do Render
// já contam como uso, sem esperar o intervalo inteiro.
function iniciarPulso(pool) {
  const horas = Number(process.env.PULSO_BANCO_HORAS ?? 6);
  if (!(horas > 0)) return () => {};
  const primeiro = setTimeout(() => pulsar(pool), 60 * 1000);
  const intervalo = setInterval(() => pulsar(pool), horas * 3600 * 1000);
  primeiro.unref();
  intervalo.unref();
  return () => { clearTimeout(primeiro); clearInterval(intervalo); };
}

module.exports = { pulsar, iniciarPulso, situacaoDoPulso };

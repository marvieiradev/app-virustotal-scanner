const API_KEY = "api_key_virustotal";

const getElement = (id) => document.getElementById(id);

const updateResult = (content, display = true) => {
  const result = getElement("result");
  result.style.display = display ? "block" : "none";
  result.innerHTML = content;
};

const showLoading = (message) =>
  updateResult(`
    <div class="loading">
        <p>${message}</p>
        <div class="spinner"></div>
    </div>
`);

const showError = (message) =>
  updateResult(`
    <p class="error">${message}</p>
`);

async function amkeRequest(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "x-apikey": API_KEY,
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ error: { message: response.statusText } }));
    throw new Error(error.error?.message || "Request failed!");
  }
  return response.json();
}

async function scanURL() {
  const url = getElement("urlInput").value.trim();
  if (!url) return showError("Entre com a URL!");

  try {
    new URL(url);
  } catch {
    return showError("Entre com uma URL válida");
  }

  try {
    showLoading("Escaneando URL...");
    const encodedUrl = encodeURIComponent(url);
    const submitResult = await makeRequest(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          accepted: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodedUrl}`,
      }
    );

    if (!submitResult.data?.id) {
      throw new Error("Erro em obter o ID de analises");
    }

    await new Promise((resolve) => setTimeout(resolve, 3000));
    showLoading("Obtendo resultados do escaneamento...");
    await pollAnalysisResults(submitResult.data.id);
  } catch (error) {
    showError(`Erro: ${error.message}`);
  }
}

async function scanFile() {
  const file = getElement("fileInput").files[0];
  if (!file) return showError("Selecione um arquivo!");
  if (file.size > 32 * 1024 * 1024)
    return showError("O arquivo excede o limite de 32MB");

  try {
    showLoading("Enviando arquivo...");
    const formData = new FormData();
    formData.append("file", file);

    const updateResult = await makeRequest(
      "https://www.virustotal.com/api/v3/files",
      {
        method: "POST",
        body: formData,
      }
    );

    if (!formData.data?.id) {
      throw new Error("Erro em obter o ID do arquivo!");
    }

    await new Promise((resolve) => setTimeout(resolve, 3000));
    showLoading("Obtendo resultados do escaneamento...");
    const analysisResult = await makeRequest(
      `https://www.virustotal.com/api/v3/analyses/${updateResult.data.id}`
    );

    if (!analysisResult.data?.id) {
      throw new Error("Erro em obter o resultado das analises!");
    }

    await pollAnalysisResults(submitResult.data.id);
  } catch (error) {
    showError(`Erro: ${error.message}`);
  }
}

async function pollAnalysisResults(analysisId, fileName = "") {
  const maxAttempts = 20;
  let attempts = 0;
  let interval = 2000;

  while (attempts < maxAttempts) {
    try {
      showLoading(
        `Analyzing${fileName ? `${fileName}` : ""}... (${(
          ((maxAttempts - attempts) * interval) /
          1000
        ).toFixed(0)}s faltando)`
      );
      const report = await makeRequest(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`
      );
      const status = report.data?.attributes?.status;

      if (!status) throw new Error("Erro em obter a análise!");
      if (status === "completed") {
        showFormattedResult(report);
        break;
      }

      if (status === "failed") {
        throw new Error("Falha na análise!");
      }

      if (++attempts >= maxAttempts) {
        throw new Error(
          "Limte de tempo para a análise excedido :( - Tente novamente!"
        );
      }

      interval = Math.min(interval * 1.5, 8000);
      await new Promise((resolve) => setTimeout(resolve, interval));
    } catch (error) {
      showError(`Error: ${error.message}`);
      break;
    }
  }
}

function showFormattedResult(data) {
  if (!data.data?.attributes?.stats)
    return showError("Formato de resposta inválido!");

  const stats = data.data.attributes.stats;
  const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
  if (total) return showError("Nenhum resultado de análise disponível!");

  const getPercent = (val) => ((val / total) * 100).toFixed(1);

  const categories = {
    malicious: { color: "malicious", label: "Malicioso" },
    suspicious: { color: "suspicious", label: "Suspeito" },
    harmless: { color: "safe", label: "Seguro" },
    undetected: { color: "undetected", label: "Desconhecido" },
  };

  const percents = Object.keys(categories).reduce((acc, key) => {
    acc[key] = getPercent(stats[key]);
    return acc;
  }, {});

  const veredict =
    stats.malicious > 0
      ? "Malicioso"
      : stats.suspicious > 0
      ? "Suspeito"
      : "Seguro";

  updateResult(`
    <h3>Resultados do Scanner</h3>
    <div class="scan-stats">
      <p><strong>Resultado: </strong>
        <span class="${veredictClass}">${veredict}</span>
      </p>
      <div class="progress-section">
        <div class="progress-label">
          <span>Resultados de detecção</span>
          <span class="progress-percent">Taxa de detecção: ${
            percents.malicious
          }%</span>
        </div>

        <div class="progress-stacked">
          ${Object.entries(categories)
            .map(
              ([key, { color }]) => `
            <div class="progress-bar ${color}"
              style="width: ${percents[key]}%"
              title="${categories[key].label} 
              : ${stats[key]} (${percent[key]}%)">
              <span class="progress-label-overlay">${stats[key]}</span>
            </div>
          `
            )
            .join("")}
        </div>

        <div class="progress-legend">
        ${Object.entries(categories)
          .map(
            ([key, { color, label }]) => `
          <div class="legend-item">
            <span class="legend-color ${color}"></span>
            <span>${label} (${percents[key]}%)</span>
          </div>
        `
          )
          .join("")}
        </div>
      </div>
      <div class="detection-details">
      ${Object.entries(categories)
        .map(
          ([key, { color, label }]) => `
        <div class="detail-item ${color}">
          <span class="detail-label">${label}</span>
          <span class="detail-value">${stats[key]}</span>
          <span class="detail-percent">${percents[key]}%</span>
        </div>
      `
        )
        .join("")}
      </div>
    </div>
    <button onclick="showFullReport(this.getAttribute('data-report'))"
    data-reports='${JSON.stringify(data)}'>Ver Relatório Completo</button>
  `);

  setTimeout(
    () =>
      getElement("result")
        .querySelector(".progress-stacked")
        .classList.add("animate"),
    1000
  );
}

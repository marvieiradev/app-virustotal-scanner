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

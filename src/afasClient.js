import fetch from "node-fetch";

function buildAfasAuthHeaderFromData(dataToken) {
  const xmlToken = `<token><version>1</version><data>${dataToken}</data></token>`;
  const b64 = Buffer.from(xmlToken, "utf8").toString("base64");
  return `AfasToken ${b64}`;
}

export async function fetchAfas(connectorId, { skip = 0, take = 1 } = {}) {
  const env = process.env.AFAS_ENV;
  const dataToken = process.env.AFAS_TOKEN_DATA;

  if (!env || !dataToken) {
    throw new Error("Missing AFAS env vars");
  }

  const url = `https://${env}.rest.afas.online/ProfitRestServices/connectors/${connectorId}?skip=${skip}&take=${take}`;

  const res = await fetch(url, {
    headers: {
      Authorization: buildAfasAuthHeaderFromData(dataToken),
      Accept: "application/json",
    },
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`AFAS ${res.status}: ${text}`);

  return JSON.parse(text);
}

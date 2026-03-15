import { getAIClient, getAIConfig, isAIConfigured, getAIProvider } from "../config/ai.config.js";
import {
    buildSystemPrompt,
    buildUserPrompt,
    validateSimulationData,
    sanitizeSimulationData
} from "../utils/aiPromptBuilder.js";
import {
    normalizeScanDataToMER,
    prepareDataForAIAnalysis,
    prepareAIAnalysisForStorage,
    validateNormalizedData
} from "../utils/dataNormalizer.js";

export async function analyzeWithAI(rawScanData) {
    if (!isAIConfigured()) {
        const provider = getAIProvider();
        throw new Error(`AI provider (${provider}) is not configured. Check .env file.`);
    }

    const basicValidation = validateSimulationData(rawScanData);
    if (!basicValidation.valid) {
        throw new Error(`Invalid simulation data: ${basicValidation.error}`);
    }

    const normalizedData = normalizeScanDataToMER(rawScanData);

    const merValidation = validateNormalizedData(normalizedData);
    if (!merValidation.valid) {
        throw new Error(`Invalid MER structure: ${merValidation.errors.join(", ")}`);
    }

    const aiReadyData = prepareDataForAIAnalysis(normalizedData);
    const sanitized = sanitizeSimulationData(aiReadyData);

    const systemPrompt = buildSystemPrompt();
    const userPrompt = buildUserPrompt(sanitized);

    const aiClient = await getAIClient();
    const aiConfig = getAIConfig();
    const provider = getAIProvider();

    let completion;

    const requestBody = {
        model: aiConfig.model,
        temperature: aiConfig.temperature,
        max_tokens: aiConfig.maxTokens,
        messages: [
            {
                role: "system",
                content: systemPrompt
            },
            {
                role: "user",
                content: userPrompt
            }
        ]
    };

    // OpenAI supports native response_format; Ollama supports it on recent models
    if (provider === "openai") {
        requestBody.response_format = { type: "json_object" };
    } else {
        // Reinforce instructions for local models: JSON format + analytical rigor
        requestBody.messages[0].content += `

IMPORTANT: You MUST respond with ONLY valid JSON. No markdown, no code fences, no extra text.

SCORING METHODOLOGY - You MUST follow this additive scoring system:

Start with overall_risk_score = 0.0 and ADD points ONLY for issues you have confirmed evidence for:
  +0.5 per open port running an up-to-date, properly configured service
  +1.5 per service with an outdated version (ONLY if you are CERTAIN the version is outdated)
  +2.0 per CONFIRMED critical CVE that affects the EXACT version detected (not a nearby version)
  +1.0 per insecure protocol in use (Telnet, plain FTP, unencrypted HTTP on sensitive ports)
  +1.5 for dangerous misconfigurations you can confirm from the scan data
  Cap the final score at 10.0

ANTI-HALLUCINATION RULES:
- Do NOT invent or guess CVE numbers. If unsure, leave the references array EMPTY.
- Do NOT assume a service version is vulnerable without certainty. When in doubt, classify as LOW.
- Do NOT list vulnerabilities you are speculating about. Fewer accurate findings is better than many guesses.
- If you cannot confirm a specific vulnerability for the exact version shown, do NOT include it.
- Set analysis_confidence between 0.3-0.5 when you are not fully certain about your findings.
- Show your reasoning: in each vulnerability description, explain what specific evidence from the scan led you to flag it.`;
    }

    try {
        completion = await aiClient.chat.completions.create(requestBody);
    } catch (apiError) {
        throw new Error(`${provider} API request failed: ${apiError.message}`);
    }

    const rawResponse = completion.choices[0]?.message?.content;

    if (!rawResponse) {
        throw new Error(`${provider} returned an empty response`);
    }

    let parsedAnalysis;

    try {
        // Clean local-model responses that sometimes wrap JSON in markdown
        let cleanResponse = rawResponse.trim();
        if (cleanResponse.startsWith("```")) {
            cleanResponse = cleanResponse.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "");
        }
        parsedAnalysis = JSON.parse(cleanResponse);
    } catch {
        throw new Error("Failed to parse AI analysis response as JSON");
    }

    const standardAnalysis = {
        executive_summary: parsedAnalysis.executive_summary || "No summary available",
        overall_risk_score: parsedAnalysis.overall_risk_score || 0,
        risk_level: parsedAnalysis.risk_level || "UNKNOWN",
        scan_metadata: parsedAnalysis.scan_metadata || {},
        vulnerabilities: Array.isArray(parsedAnalysis.vulnerabilities) ? parsedAnalysis.vulnerabilities : [],
        network_exposure: parsedAnalysis.network_exposure || {},
        compliance_notes: parsedAnalysis.compliance_notes || {},
        immediate_actions: Array.isArray(parsedAnalysis.immediate_actions)
            ? parsedAnalysis.immediate_actions
            : [],
        analysis_confidence: parsedAnalysis.analysis_confidence || 0.0,
        generated_at: parsedAnalysis.generated_at || new Date().toISOString(),
        model_version: aiConfig.model
    };

    const aiAnalysisMER = prepareAIAnalysisForStorage(standardAnalysis, normalizedData.simulation.id);

    return {
        ...standardAnalysis,
        _mer_metadata: {
            simulation_id: normalizedData.simulation.id,
            host_id: normalizedData.host.id,
            normalized_structure: {
                simulation: normalizedData.simulation,
                host: normalizedData.host,
                ports_count: normalizedData.ports.length,
                credential_tests_count: normalizedData.credentialTests.length,
                vulnerabilities_count: normalizedData.vulnerabilities.length
            },
            ai_analysis_storage: aiAnalysisMER
        }
    };
}

export async function batchAnalyze(simulationsArray) {
    if (!Array.isArray(simulationsArray) || simulationsArray.length === 0) {
        throw new Error("Batch analyze requires a non-empty array of simulations");
    }

    const results = [];
    const errors = [];

    for (let index = 0; index < simulationsArray.length; index += 1) {
        try {
            const analysis = await analyzeWithAI(simulationsArray[index]);
            results.push({
                index,
                success: true,
                analysis
            });
        } catch (error) {
            errors.push({
                index,
                success: false,
                error: error.message
            });
        }
    }

    return {
        total: simulationsArray.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors
    };
}

const CHAT_SYSTEM_PROMPT = [
    "Eres HORUS, un agente de ciberseguridad para analizar hallazgos de escaneo de red.",
    "Responde en el idioma del usuario (espanol o ingles).",
    "Si el usuario pide traduccion, traduce tu ultima explicacion o la solicitada al idioma pedido.",
    "Si falta informacion o contexto, dilo explicitamente y sugiere el siguiente paso tecnico.",
    "No inventes resultados de escaneo ni CVEs que no aparezcan en el contexto proporcionado.",
    "Si el usuario pide mitigaciones, entrega acciones priorizadas (inmediatas, corto plazo, mediano plazo).",
    "Cuando el usuario pida respuestas complejas, entrega: resumen ejecutivo, evidencia tecnica y plan accionable.",
    "Si la pregunta no es de seguridad/escaneo, responde brevemente y redirige al objetivo del proyecto."
].join(" ");

function normalizeConversation(conversation) {
    if (!Array.isArray(conversation) || conversation.length === 0) {
        return [];
    }

    return conversation
        .slice(-16)
        .map((turn) => {
            const role = String(turn?.role || "").toLowerCase();
            const content = String(turn?.content || "").trim();

            if (!content || (role !== "user" && role !== "assistant")) {
                return null;
            }

            return {
                role,
                content: content.slice(0, 4000)
            };
        })
        .filter(Boolean);
}

function safeContextString(context) {
    if (!context || typeof context !== "object") {
        return null;
    }

    try {
        const json = JSON.stringify(context, null, 2);
        if (!json || json === "{}") {
            return null;
        }

        return json.length > 20000 ? `${json.slice(0, 20000)}\n... [context truncated]` : json;
    } catch {
        return null;
    }
}

export async function chatWithAIAgent({ message, conversation = [], context = null } = {}) {
    const userMessage = String(message || "").trim();

    if (!userMessage) {
        throw new Error("Message is required for AI chat");
    }

    if (!isAIConfigured()) {
        const prov = getAIProvider();
        throw new Error(`AI provider (${prov}) is not configured. Check .env file.`);
    }

    const openai = await getAIClient();
    const openaiConfig = getAIConfig();
    const provider = getAIProvider();

    const contextJson = safeContextString(context);
    const historyMessages = normalizeConversation(conversation);

    const userPrompt = contextJson
        ? `Contexto tecnico disponible:\n${contextJson}\n\nPregunta del usuario:\n${userMessage}`
        : `Pregunta del usuario:\n${userMessage}`;

    let completion;

    try {
        completion = await openai.chat.completions.create({
            model: openaiConfig.model,
            temperature: Math.min(0.7, Math.max(0, openaiConfig.temperature + 0.05)),
            max_tokens: Math.min(openaiConfig.maxTokens, 1400),
            messages: [
                {
                    role: "system",
                    content: CHAT_SYSTEM_PROMPT
                },
                ...historyMessages,
                {
                    role: "user",
                    content: userPrompt
                }
            ]
        });
    } catch (apiError) {
        throw new Error(`${String(provider || "ai").toUpperCase()} API request failed: ${apiError.message}`);
    }

    const reply = completion?.choices?.[0]?.message?.content?.trim();

    if (!reply) {
        throw new Error(`${String(provider || "ai").toUpperCase()} returned an empty chat response`);
    }

    return {
        reply,
        model: openaiConfig.model,
        usage: completion?.usage || null
    };
}

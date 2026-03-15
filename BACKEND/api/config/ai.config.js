import dotenv from "dotenv";
import fs from "node:fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.join(__dirname, "..", ".env");

// Initial load
dotenv.config({ path: envPath });

/** AI keys that can be hot-reloaded */
const AI_ENV_KEYS = ["AI_PROVIDER", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_TEMPERATURE", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_TEMPERATURE", "OPENAI_MAX_TOKENS"];

/**
 * Re-read ONLY AI variables from .env, without overriding Docker/runtime values (DB_HOST, etc).
 */
function reloadEnv() {
    let raw;
    try { raw = fs.readFileSync(envPath, "utf8"); } catch { return; }
    for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIndex = trimmed.indexOf("=");
        if (eqIndex < 1) continue;
        const key = trimmed.slice(0, eqIndex).trim();
        if (AI_ENV_KEYS.includes(key)) {
            process.env[key] = trimmed.slice(eqIndex + 1).trim();
        }
    }
}

function parseFloatEnv(name, fallback) {
    const parsed = Number.parseFloat(process.env[name] ?? "");
    return Number.isFinite(parsed) ? parsed : fallback;
}

function parseIntEnv(name, fallback) {
    const parsed = Number.parseInt(process.env[name] ?? "", 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

/**
 * Returns the active provider: "openai" or "ollama"
 */
export function getAIProvider() {
    reloadEnv();
    const provider = (process.env.AI_PROVIDER || "openai").toLowerCase().trim();
    if (provider !== "openai" && provider !== "ollama") {
        return "openai";
    }
    return provider;
}

/**
 * Unified AI model configuration
 */
export function getAIConfig() {
    const provider = getAIProvider();

    if (provider === "ollama") {
        return {
            provider: "ollama",
            model: process.env.OLLAMA_MODEL || "llama3.1:8b",
            temperature: parseFloatEnv("OLLAMA_TEMPERATURE", 0.1),
            maxTokens: parseIntEnv("OPENAI_MAX_TOKENS", 4096),
            baseURL: (process.env.OLLAMA_BASE_URL || "http://localhost:11434") + "/v1"
        };
    }

    return {
        provider: "openai",
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: parseFloatEnv("OPENAI_TEMPERATURE", 0.2),
        maxTokens: parseIntEnv("OPENAI_MAX_TOKENS", 1800),
        baseURL: undefined
    };
}

/**
 * Checks whether the active AI provider is configured correctly
 */
export function isAIConfigured() {
    const provider = getAIProvider();

    if (provider === "ollama") {
        const baseURL = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
        return Boolean(baseURL.trim());
    }

    const apiKey = process.env.OPENAI_API_KEY;
    return Boolean(apiKey && apiKey.trim() && !apiKey.includes("your-api-key"));
}

let aiClientPromise = null;
let currentProvider = null;

/**
 * Returns an OpenAI client configured for the active provider.
 * OpenAI and Ollama share the same interface thanks to
 * Ollama compatibility with the OpenAI API.
 */
export async function getAIClient() {
    const provider = getAIProvider();

    if (!isAIConfigured()) {
        if (provider === "ollama") {
            throw new Error("Ollama is not configured. Set OLLAMA_BASE_URL in BACKEND/api/.env");
        }
        throw new Error("OpenAI is not configured. Set OPENAI_API_KEY in BACKEND/api/.env");
    }

    // Reset client if provider changed
    if (currentProvider !== provider) {
        aiClientPromise = null;
        currentProvider = provider;
    }

    if (!aiClientPromise) {
        aiClientPromise = (async () => {
            let OpenAI;

            try {
                const openaiModule = await import("openai");
                OpenAI = openaiModule.default;
            } catch {
                throw new Error("openai package is missing. Run npm install in /BACKEND/api.");
            }

            const config = getAIConfig();

            const clientOptions = {};

            if (provider === "ollama") {
                // Ollama does not need a real API key, but the SDK requires one
                clientOptions.apiKey = "ollama";
                clientOptions.baseURL = config.baseURL;
            } else {
                clientOptions.apiKey = process.env.OPENAI_API_KEY;
            }

            return new OpenAI(clientOptions);
        })();
    }

    return aiClientPromise;
}

// Compatibility: re-export using original names
export const getOpenAIConfig = getAIConfig;
export const isOpenAIConfigured = isAIConfigured;
export const getOpenAIClient = getAIClient;

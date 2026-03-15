import { getAIConfig, isAIConfigured, getAIClient } from "./ai.config.js";

// Backward-compatible exports to avoid duplicating AI configuration logic.
export const getOpenAIConfig = getAIConfig;
export const isOpenAIConfigured = isAIConfigured;
export const getOpenAIClient = getAIClient;

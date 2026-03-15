/**
 * AI Prompt Builder - Structured Prompt Construction
 * 
 * This module builds system and user prompts for OpenAI.
 * It works with data already normalized to the MER format via dataNormalizer.js.
 * 
 * Flow:
 * 1. docker.service.js returns raw scan JSON
 * 2. dataNormalizer.js transforms it into MER format
 * 3. prepareDataForAIAnalysis() prepares the AI-ready structure
 * 4. This module builds optimized prompts
 * 5. ai.service.js sends it to the OpenAI API
 */

/**
 * Builds the system prompt for OpenAI
 * 
 * Defines the role, expected response format, and critical rules.
 * The response must be compatible with the MER AIAnalysis table.
 * 
 * MER target fields (AIAnalysis):
 * - executive_summary, overall_risk_score, risk_level
 * - vulnerabilities_json, network_exposure_json
 * - compliance_notes_json, immediate_actions_json
 * - analysis_confidence
 */
export function buildSystemPrompt() {
    return `You are an expert cybersecurity analyst specializing in network vulnerability assessment and penetration testing.

Your task is to analyze structured network scan data and provide a comprehensive security analysis.

You must respond with ONLY a valid JSON object in this exact structure:

{
  "executive_summary": "A concise 2-3 paragraph summary of the overall security posture, key findings, and immediate concerns. Written for executive/management audience.",
  "overall_risk_score": 7.5,
  "risk_level": "HIGH",
  "scan_metadata": {
    "target": "192.168.1.10",
    "scan_time": "45s",
    "ports_analyzed": 5,
    "services_detected": 3
  },
  "vulnerabilities": [
    {
      "title": "SSH Service Exposed with Weak Configuration",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "affected_service": "OpenSSH 7.4 on port 22",
      "description": "Detailed explanation of the vulnerability, why it matters, and potential impact",
      "attack_vectors": ["Brute force attack", "Man-in-the-middle", "Credential stuffing"],
      "recommendations": ["Specific actionable step 1", "Specific actionable step 2"],
      "references": ["CVE-2023-XXXXX", "https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX"]
    }
  ],
  "network_exposure": {
    "open_ports_count": 5,
    "critical_services": ["ssh", "http"],
    "outdated_services": ["OpenSSH 7.4"],
    "unnecessary_services": ["telnet"]
  },
  "compliance_notes": {
    "pci_dss": "Fails requirement 2.2.4 - unnecessary services running",
    "iso_27001": "Non-compliant with A.13.1.3 - inadequate network segmentation"
  },
  "immediate_actions": [
    "Disable Telnet service immediately (port 23)",
    "Update OpenSSH to version 9.x or later",
    "Implement firewall rules to restrict SSH access"
  ],
  "analysis_confidence": 0.92,
  "generated_at": "2026-02-18T10:30:00Z"
}

CRITICAL RULES:
1. Return ONLY valid JSON - no markdown, no code blocks, no explanations
2. overall_risk_score must be a number between 0.0 and 10.0
3. risk_level must be one of: "LOW", "MEDIUM", "HIGH", "CRITICAL"
4. severity for each vulnerability must be: "LOW", "MEDIUM", "HIGH", "CRITICAL"
5. Base your analysis on the actual data provided
6. If no vulnerabilities are found, vulnerabilities array should be empty
7. Be specific and actionable in recommendations
8. analysis_confidence should be between 0.0 and 1.0
9. Only report vulnerabilities you are CERTAIN exist for the exact service version detected
10. Do NOT invent or guess CVE numbers - only reference CVEs you are confident are real
11. A port being open is NOT by itself a high-severity vulnerability
12. risk_level HIGH (7-8) or CRITICAL (9-10) requires strong evidence: compromised credentials, confirmed critical CVEs, or dangerous misconfigurations
13. If unsure about a vulnerability, classify it as LOW severity and lower your analysis_confidence`;
}

/**
 * Builds the user prompt with scan data
 * 
 * Receives data already normalized to MER format and structures it
 * into a clear and concise prompt for analysis.
 */
export function buildUserPrompt(scanData) {
    const {
        host,
        status,
        hostname,
        ports = [],
        os_detection = {},
        traceroute = [],
        scripts = [],
        vulnerabilities = [],
        credential_tests = [],
        network_info = {},
        scan_time,
        nmap_command,
        nmap_version,
        simulation_id
    } = scanData;

    // Map ports with relevant information
    const portsInfo = ports.map((p) => ({
        port: p.port || p.port_number,
        state: p.state,
        service: p.service,
        version: p.version,
        product: p.product,
        cpe: p.cpe
    }));

    // Operating system information
    const osInfo = os_detection
        ? {
              name: os_detection.name,
              accuracy: os_detection.accuracy,
              os_family: os_detection.os_family,
          }
        : null;

    // Map credential test results with a security focus
    const credentialInfo = credential_tests.map((ct) => ({
        service: ct.service,
        port: ct.port,
        status: ct.status,
        credentials_found: ct.credentials_found || false,
        username: ct.username || null,
        password: ct.password ? '***' : null,
        attempts: ct.attempts || 0,
        lockout_detected: ct.lockout_detected || false,
        rate_limited: ct.rate_limited || false,
        output_summary: ct.output_summary ? ct.output_summary.substring(0, 150) : null
    }));

    // Limit script output to optimize token usage
    const scriptInfo = scripts.map((s) => ({
        id: s.id || s.script_id,
        output: s.output?.substring(0, 200),
    }));
    return `Analyze the following network security scan results:

==========================================
SIMULATION METADATA
==========================================
Simulation ID: ${simulation_id || 'N/A'}
Nmap Version: ${nmap_version || 'N/A'}
Scan Duration: ${scan_time || 'N/A'}
Scan Command: ${nmap_command || 'N/A'}

==========================================
TARGET HOST INFORMATION
==========================================
IP Address: ${host}
Hostname: ${hostname || 'N/A'}
Status: ${status}
MAC Address: ${network_info.mac_address || 'N/A'}
Vendor: ${network_info.vendor || 'N/A'}

==========================================
OPERATING SYSTEM DETECTION
==========================================
${osInfo ? JSON.stringify(osInfo, null, 2) : 'No OS detection data available'}

==========================================
NETWORK TOPOLOGY
==========================================
${JSON.stringify({
    open_ports: network_info.open_ports_count || 0,
    services: network_info.services_detected || [],
    traceroute_hops: traceroute.length
}, null, 2)}

==========================================
OPEN PORTS AND SERVICES (${ports.length} total)
==========================================
${JSON.stringify(portsInfo, null, 2)}

==========================================
CREDENTIAL TESTING RESULTS
==========================================
${credentialInfo.length > 0 ? JSON.stringify(credentialInfo, null, 2) : 'No credential tests performed'}

${credentialInfo.some(c => c.credentials_found) ? `
CRITICAL SECURITY ALERT: Weak credentials were successfully compromised!
Services with compromised credentials require immediate remediation.
` : ''}

==========================================
NSE SCRIPT RESULTS
==========================================
${scriptInfo.length > 0 ? JSON.stringify(scriptInfo, null, 2) : 'No script results available'}

==========================================
PRE-IDENTIFIED VULNERABILITIES
==========================================
${vulnerabilities.length > 0 ? JSON.stringify(vulnerabilities, null, 2) : 'No pre-identified vulnerabilities'}

==========================================
TRACEROUTE ANALYSIS
==========================================
Hops: ${traceroute.length}
${traceroute.length > 0 ? JSON.stringify(traceroute.slice(0, 5), null, 2) : 'No traceroute data'}

---

Based on this comprehensive scan data, provide a detailed security analysis following the JSON format specified in your system instructions.

ANALYSIS REQUIREMENTS:

1. RISK ASSESSMENT
   - Calculate overall_risk_score (0.0-10.0) based on:
     * Number and severity of open ports
     * Presence of outdated/vulnerable software versions
     * Credential compromise results
     * Service exposure level
   - Assign risk_level: LOW (0-3), MEDIUM (4-6), HIGH (7-8), CRITICAL (9-10)

2. VULNERABILITY IDENTIFICATION
   - Identify specific vulnerabilities from:
     * Service versions (check for known CVEs)
     * Weak authentication (compromised credentials)
     * Unnecessary services running
     * Insecure configurations
   - Prioritize by severity and exploitability

3. NETWORK EXPOSURE ANALYSIS
   - List critical services exposed
   - Identify outdated software versions
   - Flag unnecessary services that should be disabled

4. COMPLIANCE CONSIDERATIONS
   - Evaluate against PCI DSS, ISO 27001, NIST standards
   - Identify specific non-compliant configurations

5. ACTIONABLE RECOMMENDATIONS
   - Provide specific, implementable immediate actions
   - Prioritize by risk and ease of implementation

Remember: Return ONLY the JSON object, nothing else.
Your response will be stored in the AIAnalysis table of the database.`;
}

/**
 * Validates that simulation data includes the minimum required fields
 * 
 * This is a basic validation before normalization.
 * Full MER validation is performed in dataNormalizer.js
 */
export function validateSimulationData(simulationData) {
    if (!simulationData || typeof simulationData !== "object") {
        return {
            valid: false,
            error: "Simulation data must be a non-null object",
        };
    }

    if (!simulationData.host || typeof simulationData.host !== "string") {
        return {
            valid: false,
            error: "Simulation data must include a valid 'host' field",
        };
    }

    if (!simulationData.status || typeof simulationData.status !== "string") {
        return {
            valid: false,
            error: "Simulation data must include a valid 'status' field",
        };
    }

    return {
        valid: true,
        error: null,
    };
}

/**
 * Sanitizes simulation data to optimize token usage
 * 
 * Limits large-field size and normalizes empty arrays
 */
export function sanitizeSimulationData(simulationData) {
    const sanitized = JSON.parse(JSON.stringify(simulationData));

    if (sanitized.raw_output && sanitized.raw_output.length > 5000) {
        sanitized.raw_output = sanitized.raw_output.substring(0, 5000) + "... [truncated]";
    }

    sanitized.ports = Array.isArray(sanitized.ports) ? sanitized.ports : [];
    sanitized.vulnerabilities = Array.isArray(sanitized.vulnerabilities) ? sanitized.vulnerabilities : [];
    sanitized.credential_tests = Array.isArray(sanitized.credential_tests) ? sanitized.credential_tests : [];
    sanitized.scripts = Array.isArray(sanitized.scripts) ? sanitized.scripts : [];
    sanitized.traceroute = Array.isArray(sanitized.traceroute) ? sanitized.traceroute : [];

    return sanitized;
}

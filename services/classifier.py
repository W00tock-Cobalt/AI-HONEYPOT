"""
Request classifier for categorizing honeypot visitors.

Classifications:
- scanner: Automated security scanner or bot
- credential_stuffer: Testing stolen API keys
- prompt_harvester: Attempting to extract training data or prompts
- researcher: Security researcher (benign)
- human: Manual human interaction
- data_exfil: Attempting to exfiltrate data
- recon: Reconnaissance/enumeration
- unknown: Cannot determine
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ClassificationResult:
    """Classification result with confidence and reasoning."""
    classification: str
    confidence: float  # 0.0 to 1.0
    reasons: list[str] = field(default_factory=list)
    all_scores: dict = field(default_factory=dict)  # Full score breakdown


# Known scanner user agents and patterns
SCANNER_USER_AGENTS = [
    # Security scanners
    r"nuclei",
    r"nikto",
    r"nmap",
    r"masscan",
    r"zgrab",
    r"gobuster",
    r"dirb",
    r"dirbuster",
    r"sqlmap",
    r"wfuzz",
    r"ffuf",
    r"feroxbuster",
    r"burp",
    r"owasp",
    r"acunetix",
    r"nessus",
    r"qualys",
    r"rapid7",
    r"tenable",
    r"openvas",
    r"arachni",
    r"skipfish",
    r"w3af",
    r"vega",
    r"zap",  # OWASP ZAP

    # Internet scanners/crawlers
    r"shodan",
    r"censys",
    r"binaryedge",
    r"urlscan",
    r"webtech",
    r"wappalyzer",
    r"internetmeasurement",
    r"researchscan",
    r"security\.ipip",
    r"expanseinc",
    r"paloaltonetworks",

    # HTTP clients (often used in scripts)
    r"curl/\d",
    r"python-requests",
    r"python-httpx",
    r"python-urllib",
    r"python/\d",
    r"go-http-client",
    r"go-resty",
    r"libwww-perl",
    r"perl/",
    r"wget",
    r"httpie",
    r"axios",
    r"node-fetch",
    r"got/",
    r"undici",
    r"aiohttp",
    r"java/",
    r"apache-httpclient",
    r"okhttp",
    r"requests-async",
    r"php/",
    r"guzzle",
    r"ruby",
    r"faraday",
    r"rest-client",

    # Cloud/infra
    r"cloudflare",
    r"aws-sdk",
    r"google-api",
    r"azure",

    # Misc bots
    r"bot",
    r"spider",
    r"crawler",
    r"scraper",
    r"headless",
    r"phantomjs",
    r"selenium",
    r"playwright",
    r"puppeteer",
    r"cyberdog",
    r"massexploit",

    # Additional scanners/tools
    r"metasploit",
    r"hydra",
    r"medusa",
    r"ncrack",
    r"whatweb",
    r"dirsearch",
    r"subfinder",
    r"amass",
    r"katana",
    r"caido",
    r"ghauri",
    r"httpx/[0-9]",  # projectdiscovery httpx tool
    r"libcurl",
    r"pycurl",
    r"insomnia",
    r"postman",
    r"paw/",
    r"restsharp",
    r"mechanize",
    r"scrapy",
    r"dart:[0-9]",
    r"shadowserver",
    r"stretchoid",
    r"criminalip",
    r"fofa",
    r"zoomeye",
    r"leakix",
    r"netlas",

    # LLM frameworks that proxy API calls (stolen key usage)
    r"langchain",
    r"llamaindex",
    r"litellm",
    r"instructor",
    r"autogen",
    r"crewai",
    r"dspy",
]

# Prompt injection/extraction patterns
PROMPT_EXTRACTION_PATTERNS = [
    r"ignore (previous|all|above|prior)",
    r"disregard (previous|all|above|prior|your)",
    r"forget (previous|all|your|everything)",
    r"what (is|are|was|were) your (instructions|system prompt|rules|initial prompt|original prompt)",
    r"repeat (your|the) (instructions|system prompt|rules|configuration)",
    r"print (your|the) (instructions|system prompt|rules|config)",
    r"show (me )?(your|the) (instructions|system prompt|rules|training)",
    r"tell me (your|the) (instructions|system prompt|rules|how you work)",
    r"reveal (your|the) (instructions|system prompt|rules|secrets)",
    r"output (your|the) (instructions|system prompt|rules)",
    r"dump (your|the) (instructions|system prompt|rules|memory)",
    r"list (your|the) (instructions|system prompt|rules|commands)",
    r"display (your|the) (instructions|system prompt|rules)",
    r"(system|assistant|user|developer) ?prompt",
    r"pre-?prompt",
    r"jailbreak",
    r"dan mode",
    r"developer mode",
    r"pretend you are",
    r"act as if",
    r"roleplay as",
    r"you are now",
    r"from now on",
    r"new persona",
    r"assume the role",
    r"bypass (your|the) (restrictions|filters|rules|guidelines)",
    r"override (your|the) (instructions|programming|training)",
    r"base64 decode",
    r"hex decode",
    r"rot13",
    r"\[system\]",
    r"<system>",
    r"{{system}}",
    r"SYSTEM:",
    # Modern jailbreak / injection patterns
    r"do anything now",
    r"no restrictions",
    r"unrestricted (mode|ai|assistant|access)",
    r"god mode",
    r"evil mode",
    r"sudo mode",
    r"maintenance mode",
    r"(ignore|bypass|disregard) (all )?(safety|content|ethical) (guidelines?|filters?|policies?|restrictions?)",
    r"your (true|real|actual) (self|purpose|goal|mission|nature)",
    r"\[/?INST\]",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|system\|>",
    r"<<SYS>>",
    r"hypothetically (speaking|if|assume)",
    r"(for )?(educational|research|fictional|creative writing) purposes",
    r"imagine you (are|have no|were) (an? )?(AI|model|assistant|language model) (without|with no|that)",
    r"in (this|a) (fictional|hypothetical|alternate|imaginary) (world|universe|scenario|context)",
    r"token budget",
    r"system override",
    r"prompt leak",
    r"many-shot (jailbreak|prompting)",
    r"grandma (trick|exploit|jailbreak)",
]

# Data exfiltration patterns
DATA_EXFIL_PATTERNS = [
    r"read (the )?file",
    r"cat /",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.env",
    r"\.git",
    r"private.?key",
    r"api.?key",
    r"secret.?key",
    r"password",
    r"credentials?",
    r"token",
    r"ssh.?key",
    r"id_rsa",
    r"aws.?credentials",
    r"database.?url",
    r"connection.?string",
    r"send (to|this to)",
    r"upload (to|this to)",
    r"exfil",
    r"webhook\.site",
    r"requestbin",
    r"pipedream",
    r"burpcollaborator",
    r"oast\.fun",
    r"interact\.sh",
    r"canarytokens",
    r"ngrok\.(io|app)",
    r"serveo\.net",
    r"localhost\.run",
    r"docker.?secret",
    r"kubeconfig",
    r"k8s.?secret",
    r"github.?token",
    r"ghp_",           # GitHub PAT prefix
    r"gho_",           # GitHub OAuth
    r"glpat-",         # GitLab PAT
    r"xoxb-",          # Slack bot token
    r"xoxp-",          # Slack user token
    r"AKIA[A-Z0-9]{16}",  # AWS access key ID
    r"/etc/hosts",
    r"/proc/self/(environ|cmdline|mem|status)",
    r"169\.254\.169\.254",  # AWS IMDS (SSRF lure)
    r"metadata\.google\.internal",  # GCP IMDS
    r"169\.254\.170\.2",   # ECS metadata
]

# Test API key patterns (likely credential stuffing)
TEST_API_KEY_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",  # OpenAI format
    r"sk-proj-[a-zA-Z0-9]{20,}",  # OpenAI project format
    r"sk-or-[a-zA-Z0-9]{20,}",  # OpenRouter format
    r"sk-ant-[a-zA-Z0-9]{20,}",  # Anthropic format
    r"test",
    r"demo",
    r"fake",
    r"example",
    r"placeholder",
    r"xxx+",
    r"aaa+",
    r"123+",
    r"asdf",
    r"qwerty",
    r"admin",
    r"password",
    r"changeme",
    r"^key$",
    r"^token$",
]

# Research indicators
RESEARCHER_PATTERNS = [
    r"security (research|test|audit)",
    r"penetration test",
    r"pentest",
    r"bug bounty",
    r"responsible disclosure",
    r"ethical hack",
    r"authorized test",
    r"security assessment",
    r"vulnerability (scan|test|research)",
    r"coordinated disclosure",
    r"white hat",
    r"red team",
    r"blue team",
]

# Suspicious paths
SUSPICIOUS_PATHS = [
    r"\.env",
    r"\.git",
    r"\.svn",
    r"\.hg",
    r"config\.",
    r"\.config",
    r"backup",
    r"\.bak",
    r"\.old",
    r"\.orig",
    r"admin",
    r"debug",
    r"test",
    r"dev",
    r"staging",
    r"internal",
    r"private",
    r"secret",
    r"hidden",
    r"phpinfo",
    r"server-status",
    r"\.htaccess",
    r"web\.config",
    r"wp-config",
    r"robots\.txt",
    r"sitemap\.xml",
    r"crossdomain\.xml",
    r"\.well-known",
    r"actuator",
    r"swagger",
    r"api-docs",
    r"graphql",
    r"\.php",
    r"\.asp",
    r"\.jsp",
    r"cgi-bin",
    r"shell",
    r"cmd",
    r"exec",
    r"eval",
]


class RequestClassifier:
    """Classifies honeypot requests by behavior patterns."""

    def __init__(self):
        self.scanner_patterns = [
            re.compile(p, re.IGNORECASE) for p in SCANNER_USER_AGENTS
        ]
        self.prompt_patterns = [
            re.compile(p, re.IGNORECASE) for p in PROMPT_EXTRACTION_PATTERNS
        ]
        self.exfil_patterns = [
            re.compile(p, re.IGNORECASE) for p in DATA_EXFIL_PATTERNS
        ]
        self.test_key_patterns = [
            re.compile(p, re.IGNORECASE) for p in TEST_API_KEY_PATTERNS
        ]
        self.researcher_patterns = [
            re.compile(p, re.IGNORECASE) for p in RESEARCHER_PATTERNS
        ]
        self.suspicious_path_patterns = [
            re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATHS
        ]

    def classify(
        self,
        user_agent: Optional[str] = None,
        api_key: Optional[str] = None,
        messages: Optional[list] = None,
        prompt: Optional[str] = None,
        path: Optional[str] = None,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a request based on multiple signals.

        Returns classification with confidence score and reasons.
        """
        scores = {
            "scanner": 0.0,
            "credential_stuffer": 0.0,
            "prompt_harvester": 0.0,
            "researcher": 0.0,
            "human": 0.0,
            "data_exfil": 0.0,
            "recon": 0.0,
        }
        reasons = []

        # Check user agent for scanner signatures
        if user_agent:
            for pattern in self.scanner_patterns:
                if pattern.search(user_agent):
                    scores["scanner"] += 0.6
                    reasons.append(f"Scanner UA: {pattern.pattern[:30]}")
                    break

            # Short user agent (empty case handled below in else)
            if len(user_agent.strip()) < 15:
                scores["scanner"] += 0.2
                reasons.append(f"Very short user agent ({len(user_agent)} chars)")

            # Non-browser user agent characteristics
            browser_indicators = ["mozilla", "chrome", "safari", "firefox", "edge", "opera"]
            if any(b in user_agent.lower() for b in browser_indicators):
                scores["human"] += 0.35
                reasons.append("Browser user agent")
            else:
                scores["scanner"] += 0.1
                reasons.append("Non-browser user agent")

            # Official OpenAI SDK — attacker using SDK with a stolen key
            ua_lower = user_agent.lower()
            if "openai-python" in ua_lower or re.search(r"openai/[0-9]", ua_lower):
                scores["credential_stuffer"] += 0.5
                reasons.append("Official OpenAI Python SDK detected (likely stolen key)")

            # Other LLM framework SDKs
            llm_sdks = ["langchain", "llamaindex", "litellm", "instructor", "autogen", "crewai", "dspy"]
            for sdk in llm_sdks:
                if sdk in ua_lower:
                    scores["credential_stuffer"] += 0.3
                    reasons.append(f"LLM framework SDK in UA: {sdk}")
                    break
        else:
            # Truly empty / missing user agent
            scores["scanner"] += 0.3
            reasons.append("Empty user agent")

        # Check API key patterns
        if api_key:
            # Test/placeholder keys
            for pattern in self.test_key_patterns:
                if pattern.search(api_key):
                    if "sk-" in api_key.lower():
                        scores["credential_stuffer"] += 0.5
                        reasons.append("OpenAI-format API key (likely stolen/testing)")
                    else:
                        scores["credential_stuffer"] += 0.3
                        reasons.append(f"Test key pattern: {pattern.pattern[:20]}")
                    break

            # Valid-looking OpenAI key format (random chars, long)
            if re.match(r"sk-(proj-)?[a-zA-Z0-9]{40,}", api_key):
                scores["credential_stuffer"] += 0.4
                reasons.append("Valid OpenAI key format")

            # Readable/label-style key — human-chosen phrase, not random bytes
            # e.g. sk-ui-session-key, sk-my-test-key, sk-dev-backend
            elif re.match(r"sk(-[a-z][a-z0-9]*){2,}$", api_key, re.IGNORECASE) and len(api_key) < 35:
                scores["credential_stuffer"] += 0.2
                scores["human"] += 0.15
                reasons.append(f"Label-style key (dev/test placeholder): {api_key}")

            # Extremely short or obviously fake
            if len(api_key) < 10:
                scores["scanner"] += 0.2
                reasons.append(f"Suspiciously short API key ({len(api_key)} chars)")

        # Check for prompt extraction attempts
        content_to_check = ""
        if messages:
            for msg in messages:
                if isinstance(msg, dict) and "content" in msg:
                    content_to_check += str(msg["content"]) + " "
        if prompt:
            content_to_check += prompt
        if body:
            content_to_check += " " + body

        if content_to_check:
            # Prompt injection/extraction
            for pattern in self.prompt_patterns:
                if pattern.search(content_to_check):
                    scores["prompt_harvester"] += 0.5
                    reasons.append(f"Prompt extraction: {pattern.pattern[:30]}")

            # Data exfiltration attempts
            for pattern in self.exfil_patterns:
                if pattern.search(content_to_check):
                    scores["data_exfil"] += 0.5
                    reasons.append(f"Data exfil pattern: {pattern.pattern[:30]}")

            # Check for researcher indicators
            for pattern in self.researcher_patterns:
                if pattern.search(content_to_check):
                    scores["researcher"] += 0.4
                    reasons.append(f"Researcher indicator: {pattern.pattern[:30]}")

            # Encoded payload detection
            if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", content_to_check):
                scores["scanner"] += 0.2
                reasons.append("Possible base64 encoded payload")

            # Command injection patterns
            if re.search(r"[;&|`$]", content_to_check) and re.search(r"(cat|ls|pwd|whoami|id|curl|wget|nc|bash|sh|python|perl|ruby)", content_to_check, re.IGNORECASE):
                scores["data_exfil"] += 0.3
                reasons.append("Command injection indicators")

        # Path-based signals
        if path:
            # Sensitive endpoints
            sensitive_paths = [
                "/v1/organization/api-keys",
                "/v1/dashboard/billing",
                "/v1/usage",
                "/v1/engines",
                "/v1/fine-tunes",
                "/v1/files",
                "/v1/assistants",
                "/v1/threads",
            ]
            if any(p in path for p in sensitive_paths):
                scores["recon"] += 0.3
                reasons.append("Accessing sensitive endpoint")

            # Suspicious path patterns
            for pattern in self.suspicious_path_patterns:
                if pattern.search(path):
                    scores["scanner"] += 0.3
                    scores["recon"] += 0.2
                    reasons.append(f"Suspicious path: {pattern.pattern[:20]}")
                    break

            # Path traversal
            if ".." in path or "%2e%2e" in path.lower():
                scores["scanner"] += 0.4
                scores["data_exfil"] += 0.3
                reasons.append("Path traversal attempt")

            # Direct file access attempts
            if re.search(r"\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|bash|exe|dll)(\?|$)", path, re.IGNORECASE):
                scores["scanner"] += 0.4
                reasons.append("Script file access attempt")

        # Header-based signals
        if headers:
            lower_headers = {k.lower(): v for k, v in headers.items()}

            # Missing common browser headers
            browser_headers = ["accept-language", "accept-encoding", "accept"]
            missing_browser = sum(1 for h in browser_headers if h not in lower_headers)
            if missing_browser >= 2:
                scores["scanner"] += 0.15 * missing_browser
                reasons.append(f"Missing {missing_browser} browser headers")
            elif missing_browser == 0:
                # All standard browser headers present — positive human signal
                scores["human"] += 0.1
                reasons.append("All standard browser headers present")

            # Suspicious custom headers
            suspicious_header_names = ["x-debug", "x-test", "x-admin", "x-backdoor", "x-exploit", "x-inject"]
            for hl in lower_headers:
                if any(s in hl for s in suspicious_header_names):
                    scores["scanner"] += 0.2
                    reasons.append(f"Suspicious header: {hl}")

            # Empty or minimal headers
            if len(headers) < 3:
                scores["scanner"] += 0.2
                reasons.append(f"Minimal headers ({len(headers)} total)")

            # SQL injection in headers
            for h, v in lower_headers.items():
                if isinstance(v, str) and re.search(r"(union|select|insert|update|delete|drop|;--)", v, re.IGNORECASE):
                    scores["scanner"] += 0.5
                    reasons.append(f"SQL injection in header: {h}")

            # x-stainless-* headers: emitted by official OpenAI Python/Node/Java SDKs
            stainless_keys = [k for k in lower_headers if k.startswith("x-stainless-")]
            if stainless_keys:
                scores["credential_stuffer"] += 0.55
                pkg_ver = lower_headers.get("x-stainless-package-version", "?")
                lang = lower_headers.get("x-stainless-lang", "?")
                reasons.append(f"OpenAI SDK fingerprint via x-stainless headers (lang={lang}, ver={pkg_ver})")

            # Proxy chain indicators — suggests automated/scripted environment
            if "x-forwarded-for" in lower_headers and "x-real-ip" in lower_headers:
                scores["scanner"] += 0.1
                reasons.append("Multiple proxy forwarding headers (automated env)")

        # Human indicators (presence of natural language, proper formatting)
        if content_to_check:
            # Natural conversation patterns
            human_indicators = [
                r"\b(please|thanks|thank you|help|could you|would you|can you)\b",
                r"\b(I('m| am| have| need| want)|my|we|our)\b",
                r"[.!?]$",  # Proper punctuation
                r"\b(hello|hi|hey|good morning|good afternoon)\b",
            ]
            human_score = 0
            for pattern in human_indicators:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    human_score += 0.12
            if human_score > 0:
                scores["human"] += min(human_score, 0.45)
                if human_score > 0.2:
                    reasons.append("Natural language patterns")

            # Proper sentence structure
            sentences = re.split(r'[.!?]', content_to_check)
            proper_sentences = sum(1 for s in sentences if len(s.strip().split()) > 3)
            if proper_sentences >= 2:
                scores["human"] += 0.15
                reasons.append("Proper sentence structure")

        # Determine final classification
        max_score = max(scores.values())
        if max_score < 0.2:
            # Confidence reflects how little signal we actually have
            no_signal_confidence = round(0.2 + max_score, 2)
            return ClassificationResult(
                classification="unknown",
                confidence=no_signal_confidence,
                reasons=reasons or ["Insufficient signals"],
                all_scores=scores,
            )

        # Get classification with highest score
        classification = max(scores, key=scores.get)
        confidence = min(scores[classification], 1.0)

        return ClassificationResult(
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            all_scores=scores,
        )


# Singleton
_classifier: Optional[RequestClassifier] = None


def get_classifier() -> RequestClassifier:
    """Get or create classifier singleton."""
    global _classifier
    if _classifier is None:
        _classifier = RequestClassifier()
    return _classifier

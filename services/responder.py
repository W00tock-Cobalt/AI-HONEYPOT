"""
Response generator for fake OpenAI API responses.

Generates plausible responses that mimic real OpenAI API behavior.
"""

import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional


def generate_completion_id() -> str:
    """Generate a realistic completion ID."""
    return f"chatcmpl-{uuid.uuid4().hex[:29]}"


def generate_embedding_id() -> str:
    """Generate embedding response ID."""
    return f"emb-{uuid.uuid4().hex[:24]}"


def generate_image_url() -> str:
    """Generate a fake image URL (returns placeholder)."""
    img_id = uuid.uuid4().hex[:16]
    return f"https://oaidalleapiprodscus.blob.core.windows.net/private/generated/{img_id}.png"


def generate_fake_api_key() -> str:
    """Generate a realistic-looking fake API key."""
    prefix = random.choice(["sk-proj-", "sk-"])
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    key = "".join(random.choice(chars) for _ in range(48))
    return f"{prefix}{key}"


# Plausible response templates for different prompt types
CHAT_RESPONSES = [
    "I'd be happy to help you with that. Could you provide more details about what you're looking for?",
    "That's an interesting question. Let me think about this...\n\nBased on my understanding, the answer would depend on several factors.",
    "I can assist with that request. Here's what I know:\n\n1. First, consider the context\n2. Then, evaluate your options\n3. Finally, make an informed decision",
    "Thank you for your question. While I can provide general guidance, I'd recommend consulting with a professional for specific advice.",
    "I understand what you're asking. Let me break this down into manageable parts.",
    "Great question! The short answer is that it depends on your specific situation and requirements.",
    "I'm here to help. Based on what you've described, I would suggest starting with the basics and building from there.",
    "That's a thoughtful inquiry. There are multiple perspectives to consider here.",
]

CODE_RESPONSES = [
    """Here's a simple implementation:

```python
def solution(data):
    result = []
    for item in data:
        if validate(item):
            result.append(process(item))
    return result
```

This should handle the basic case. Let me know if you need modifications.""",
    """I can help with that code. Here's an approach:

```javascript
function handleRequest(req, res) {
    const data = req.body;
    // Process the data
    const result = processData(data);
    res.json({ success: true, data: result });
}
```

Would you like me to explain any part of this?""",
]

REFUSAL_RESPONSES = [
    "I'm not able to help with that particular request. Is there something else I can assist you with?",
    "I can't provide assistance with that type of request. However, I'm happy to help with other topics.",
    "That falls outside of what I can help with. Let me know if you have other questions.",
]


class ResponseGenerator:
    """Generates fake but plausible OpenAI API responses."""

    def __init__(self):
        self.models = self._get_models()
        self.issued_canary_keys: set[str] = set()  # Track keys we've served

    def _get_models(self) -> list[dict]:
        """Get list of available models."""
        base_time = int(datetime.now().timestamp()) - 86400 * 30  # 30 days ago

        return [
            {
                "id": "gpt-4o",
                "object": "model",
                "created": base_time,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4o-mini",
                "object": "model",
                "created": base_time + 1000,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4-turbo",
                "object": "model",
                "created": base_time - 5000,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4",
                "object": "model",
                "created": base_time - 50000,
                "owned_by": "openai",
            },
            {
                "id": "gpt-3.5-turbo",
                "object": "model",
                "created": base_time - 100000,
                "owned_by": "openai",
            },
            {
                "id": "gpt-3.5-turbo-16k",
                "object": "model",
                "created": base_time - 90000,
                "owned_by": "openai",
            },
            {
                "id": "text-embedding-3-large",
                "object": "model",
                "created": base_time - 20000,
                "owned_by": "openai",
            },
            {
                "id": "text-embedding-3-small",
                "object": "model",
                "created": base_time - 20000,
                "owned_by": "openai",
            },
            {
                "id": "text-embedding-ada-002",
                "object": "model",
                "created": base_time - 200000,
                "owned_by": "openai-internal",
            },
            {
                "id": "dall-e-3",
                "object": "model",
                "created": base_time - 10000,
                "owned_by": "openai",
            },
            {
                "id": "dall-e-2",
                "object": "model",
                "created": base_time - 150000,
                "owned_by": "openai",
            },
            {
                "id": "whisper-1",
                "object": "model",
                "created": base_time - 180000,
                "owned_by": "openai-internal",
            },
            {
                "id": "tts-1",
                "object": "model",
                "created": base_time - 15000,
                "owned_by": "openai-internal",
            },
            {
                "id": "tts-1-hd",
                "object": "model",
                "created": base_time - 15000,
                "owned_by": "openai-internal",
            },
            {
                "id": "o1",
                "object": "model",
                "created": base_time - 2000,
                "owned_by": "openai",
            },
            {
                "id": "o1-mini",
                "object": "model",
                "created": base_time - 1500,
                "owned_by": "openai",
            },
            {
                "id": "o3-mini",
                "object": "model",
                "created": base_time - 500,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4.1",
                "object": "model",
                "created": base_time - 100,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4.1-mini",
                "object": "model",
                "created": base_time - 90,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4.5-preview",
                "object": "model",
                "created": base_time - 3000,
                "owned_by": "openai",
            },
        ]

    def chat_completion(
        self,
        model: str = "gpt-4o",
        messages: Optional[list] = None,
        stream: bool = False,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> dict:
        """Generate a fake chat completion response."""
        # Determine response based on content
        content = self._select_response(messages)
        prompt_tokens = self._estimate_tokens(messages)
        completion_tokens = self._estimate_tokens([{"content": content}])

        response = {
            "id": generate_completion_id(),
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "logprobs": None,
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "system_fingerprint": f"fp_{uuid.uuid4().hex[:10]}",
        }

        return response

    def completion(
        self,
        model: str = "gpt-3.5-turbo-instruct",
        prompt: str = "",
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> dict:
        """Generate a fake legacy completion response."""
        content = random.choice(CHAT_RESPONSES)
        prompt_tokens = len(prompt.split()) * 1.3
        completion_tokens = len(content.split()) * 1.3

        return {
            "id": f"cmpl-{uuid.uuid4().hex[:24]}",
            "object": "text_completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "text": content,
                    "index": 0,
                    "logprobs": None,
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": int(prompt_tokens),
                "completion_tokens": int(completion_tokens),
                "total_tokens": int(prompt_tokens + completion_tokens),
            },
        }

    def embedding(
        self,
        model: str = "text-embedding-3-small",
        input_text: str | list = "",
        **kwargs,
    ) -> dict:
        """Generate a fake embedding response."""
        # Handle both string and list inputs
        if isinstance(input_text, str):
            inputs = [input_text]
        else:
            inputs = input_text

        # Generate fake embeddings (1536 dimensions for ada-002, 3072 for large)
        dimensions = 3072 if "large" in model else 1536

        embeddings = []
        for i, text in enumerate(inputs):
            # Generate deterministic-ish fake embedding
            fake_embedding = [
                round(random.gauss(0, 0.1), 8) for _ in range(dimensions)
            ]
            embeddings.append(
                {
                    "object": "embedding",
                    "index": i,
                    "embedding": fake_embedding,
                }
            )

        total_tokens = sum(len(str(t).split()) for t in inputs)

        return {
            "object": "list",
            "data": embeddings,
            "model": model,
            "usage": {
                "prompt_tokens": total_tokens,
                "total_tokens": total_tokens,
            },
        }

    def models_list(self) -> dict:
        """Return list of available models."""
        return {
            "object": "list",
            "data": self.models,
        }

    def model_retrieve(self, model_id: str) -> Optional[dict]:
        """Retrieve a specific model."""
        for model in self.models:
            if model["id"] == model_id:
                return model
        return None

    def image_generation(
        self,
        prompt: str = "",
        model: str = "dall-e-3",
        n: int = 1,
        size: str = "1024x1024",
        **kwargs,
    ) -> dict:
        """Generate a fake image generation response."""
        images = []
        for i in range(min(n, 4)):
            images.append(
                {
                    "url": generate_image_url(),
                    "revised_prompt": f"A detailed artistic interpretation of: {prompt[:100]}...",
                }
            )

        return {
            "created": int(time.time()),
            "data": images,
        }

    def usage(self) -> dict:
        """Generate fake usage statistics."""
        today = datetime.now()
        daily_costs = []

        for i in range(30):
            date = today - timedelta(days=i)
            daily_costs.append(
                {
                    "timestamp": date.timestamp(),
                    "line_items": [
                        {
                            "name": "GPT-4",
                            "cost": round(random.uniform(0.5, 5.0), 2),
                        },
                        {
                            "name": "GPT-3.5 Turbo",
                            "cost": round(random.uniform(0.1, 1.0), 2),
                        },
                        {
                            "name": "Embeddings",
                            "cost": round(random.uniform(0.01, 0.2), 2),
                        },
                    ],
                }
            )

        return {
            "object": "list",
            "daily_costs": daily_costs,
            "total_usage": round(sum(sum(li["cost"] for li in d["line_items"]) for d in daily_costs), 2),
        }

    def billing_usage(self) -> dict:
        """Generate fake billing/usage data."""
        return {
            "object": "billing_usage",
            "has_payment_method": True,
            "soft_limit_usd": 120.00,
            "hard_limit_usd": 150.00,
            "current_usage_usd": round(random.uniform(20, 80), 2),
            "access_until": int((datetime.now() + timedelta(days=30)).timestamp()),
        }

    def api_keys(self) -> dict:
        """Generate fake API keys list (high-value lure).

        Includes both randomly generated canary keys AND any custom canary tokens
        added by the operator via the admin UI.
        """
        keys = []
        now = datetime.now()

        # Randomly generated canary keys
        for i in range(random.randint(2, 4)):
            created = now - timedelta(days=random.randint(1, 90))
            last_used = now - timedelta(hours=random.randint(1, 72))
            keys.append({
                "object": "api_key",
                "id": f"key-{uuid.uuid4().hex[:24]}",
                "name": random.choice(
                    ["Production", "Development", "Testing", "Backend", "Mobile App"]
                ) + f" Key {i + 1}",
                "key": self._issue_canary_key(),
                "created_at": int(created.timestamp()),
                "last_used_at": int(last_used.timestamp()),
                "owner": {
                    "type": "user",
                    "user": {
                        "id": f"user-{uuid.uuid4().hex[:24]}",
                        "name": "API User",
                        "email": f"user{random.randint(1, 999)}@example.com",
                    },
                },
            })

        # Append custom canary tokens from operator config (highest value lures)
        try:
            from services.config import get_config
            custom_tokens = get_config().get("canary_tokens", [])
            for ct in custom_tokens:
                token_val = ct.get("token", "")
                if not token_val:
                    continue
                self.issued_canary_keys.add(token_val)
                created = now - timedelta(days=random.randint(30, 365))
                keys.append({
                    "object": "api_key",
                    "id": f"key-{uuid.uuid4().hex[:24]}",
                    "name": ct.get("label", "API Key"),
                    "key": token_val,
                    "created_at": int(created.timestamp()),
                    "last_used_at": int((now - timedelta(hours=random.randint(1, 24))).timestamp()),
                    "owner": {
                        "type": "user",
                        "user": {
                            "id": f"user-{uuid.uuid4().hex[:24]}",
                            "name": "API User",
                            "email": f"user{random.randint(1, 99)}@company.com",
                        },
                    },
                })
        except Exception:
            pass

        random.shuffle(keys)
        return {"object": "list", "data": keys}

    def _issue_canary_key(self) -> str:
        """Generate a canary API key and record it for later detection."""
        key = generate_fake_api_key()
        self.issued_canary_keys.add(key)
        return key

    def assistants_list(self) -> dict:
        """Generate fake assistants list (high-value lure)."""
        now = datetime.now()
        assistants = []
        names = ["Customer Support Bot", "Code Assistant", "Data Analyst", "Research Helper", "Email Drafter"]
        for i in range(random.randint(1, 4)):
            created = now - timedelta(days=random.randint(1, 60))
            assistants.append({
                "id": f"asst_{uuid.uuid4().hex[:24]}",
                "object": "assistant",
                "created_at": int(created.timestamp()),
                "name": random.choice(names),
                "description": "An AI assistant configured for specific tasks.",
                "model": random.choice(["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]),
                "instructions": "You are a helpful assistant.",
                "tools": [{"type": "code_interpreter"}, {"type": "file_search"}],
                "metadata": {},
            })
        return {"object": "list", "data": assistants, "has_more": False}

    def files_list(self) -> dict:
        """Generate fake files list (data exfil lure)."""
        now = datetime.now()
        files = []
        filenames = [
            "training_data.jsonl", "fine_tune_examples.jsonl",
            "knowledge_base.pdf", "customer_data.csv",
            "internal_docs.txt", "system_prompts.json",
        ]
        purposes = ["fine-tune", "assistants", "batch"]
        for i in range(random.randint(2, 5)):
            created = now - timedelta(days=random.randint(1, 90))
            fname = random.choice(filenames)
            files.append({
                "id": f"file-{uuid.uuid4().hex[:24]}",
                "object": "file",
                "bytes": random.randint(10000, 5000000),
                "created_at": int(created.timestamp()),
                "filename": fname,
                "purpose": random.choice(purposes),
                "status": "processed",
                "status_details": None,
            })
        return {"object": "list", "data": files}

    def fine_tuning_jobs(self) -> dict:
        """Generate fake fine-tuning jobs list."""
        now = datetime.now()
        jobs = []
        for i in range(random.randint(1, 3)):
            created = now - timedelta(days=random.randint(1, 30))
            jobs.append({
                "id": f"ftjob-{uuid.uuid4().hex[:24]}",
                "object": "fine_tuning.job",
                "created_at": int(created.timestamp()),
                "finished_at": int((created + timedelta(hours=random.randint(1, 4))).timestamp()),
                "model": random.choice(["gpt-4o-mini-2024-07-18", "gpt-3.5-turbo-0125"]),
                "fine_tuned_model": f"ft:gpt-4o-mini:custom::{uuid.uuid4().hex[:8]}",
                "organization_id": "org-honeypot",
                "status": "succeeded",
                "training_file": f"file-{uuid.uuid4().hex[:24]}",
                "validation_file": None,
                "hyperparameters": {"n_epochs": random.randint(3, 10)},
                "trained_tokens": random.randint(10000, 500000),
            })
        return {"object": "list", "data": jobs, "has_more": False}

    def threads_list(self) -> dict:
        """Generate fake threads (Assistants API)."""
        now = datetime.now()
        threads = []
        for i in range(random.randint(1, 5)):
            created = now - timedelta(hours=random.randint(1, 48))
            threads.append({
                "id": f"thread_{uuid.uuid4().hex[:24]}",
                "object": "thread",
                "created_at": int(created.timestamp()),
                "metadata": {},
            })
        return {"object": "list", "data": threads, "has_more": False}

    def moderation_result(self, input_text: str = "") -> dict:
        """Generate fake moderation result (always passes — keeps attacker engaged)."""
        return {
            "id": f"modr-{uuid.uuid4().hex[:24]}",
            "model": "text-moderation-latest",
            "results": [{
                "flagged": False,
                "categories": {
                    "sexual": False, "hate": False, "harassment": False,
                    "self-harm": False, "sexual/minors": False,
                    "hate/threatening": False, "violence/graphic": False,
                    "self-harm/intent": False, "self-harm/instructions": False,
                    "harassment/threatening": False, "violence": False,
                },
                "category_scores": {
                    "sexual": round(random.uniform(0.0, 0.02), 6),
                    "hate": round(random.uniform(0.0, 0.02), 6),
                    "harassment": round(random.uniform(0.0, 0.03), 6),
                    "self-harm": round(random.uniform(0.0, 0.01), 6),
                    "sexual/minors": round(random.uniform(0.0, 0.005), 6),
                    "hate/threatening": round(random.uniform(0.0, 0.005), 6),
                    "violence/graphic": round(random.uniform(0.0, 0.01), 6),
                    "self-harm/intent": round(random.uniform(0.0, 0.005), 6),
                    "self-harm/instructions": round(random.uniform(0.0, 0.005), 6),
                    "harassment/threatening": round(random.uniform(0.0, 0.005), 6),
                    "violence": round(random.uniform(0.0, 0.04), 6),
                },
            }],
        }

    def org_users(self) -> dict:
        """Generate fake organization users (recon lure)."""
        now = datetime.now()
        users = []
        first_names = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
        roles = ["owner", "admin", "member", "reader"]
        for i in range(random.randint(3, 8)):
            fn = random.choice(first_names)
            ln = random.choice(last_names)
            added = now - timedelta(days=random.randint(10, 365))
            users.append({
                "object": "organization.user",
                "id": f"user-{uuid.uuid4().hex[:24]}",
                "name": f"{fn} {ln}",
                "email": f"{fn.lower()}.{ln.lower()}@company.com",
                "role": random.choice(roles),
                "added_at": int(added.timestamp()),
            })
        return {"object": "list", "data": users, "has_more": False}

    def org_projects(self) -> dict:
        """Generate fake organization projects (recon lure)."""
        now = datetime.now()
        projects = []
        names = ["Production", "Development", "Staging", "Research", "Internal Tools", "Customer Facing"]
        for name in random.sample(names, random.randint(2, 4)):
            created = now - timedelta(days=random.randint(30, 365))
            projects.append({
                "id": f"proj_{uuid.uuid4().hex[:24]}",
                "object": "organization.project",
                "name": name,
                "created_at": int(created.timestamp()),
                "archived_at": None,
                "status": "active",
            })
        return {"object": "list", "data": projects, "has_more": False}

    def _select_response(self, messages: Optional[list]) -> str:
        """Select appropriate response based on message content."""
        if not messages:
            return random.choice(CHAT_RESPONSES)

        # Get last user message
        last_user_msg = ""
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                last_user_msg = str(msg.get("content", "")).lower()
                break

        # Check for code-related queries
        code_keywords = ["code", "function", "program", "script", "implement", "write"]
        if any(kw in last_user_msg for kw in code_keywords):
            return random.choice(CODE_RESPONSES)

        # Check for potentially harmful requests (return refusal)
        harmful_keywords = ["hack", "exploit", "illegal", "password", "bypass"]
        if any(kw in last_user_msg for kw in harmful_keywords):
            return random.choice(REFUSAL_RESPONSES)

        return random.choice(CHAT_RESPONSES)

    def _estimate_tokens(self, messages: Optional[list]) -> int:
        """Rough token estimation (4 chars per token approximation)."""
        if not messages:
            return 0

        total_chars = 0
        for msg in messages:
            if isinstance(msg, dict):
                total_chars += len(str(msg.get("content", "")))
            else:
                total_chars += len(str(msg))

        return max(1, int(total_chars / 4))


# Singleton
_responder: Optional[ResponseGenerator] = None


def get_responder() -> ResponseGenerator:
    """Get or create responder singleton."""
    global _responder
    if _responder is None:
        _responder = ResponseGenerator()
    return _responder

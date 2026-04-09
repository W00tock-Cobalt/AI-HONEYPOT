from .chat import router as chat_router
from .models import router as models_router
from .embeddings import router as embeddings_router
from .billing import router as billing_router
from .admin import router as admin_router, set_database

__all__ = [
    "chat_router",
    "models_router",
    "embeddings_router",
    "billing_router",
    "admin_router",
    "set_database",
]

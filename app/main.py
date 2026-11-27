
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.students import router as students_router
from app.api.secure_notes import router as secure_notes_router
from app.api.crypto_lab import router as crypto_lab_router
from app.api.asymmetric_lab import router as asymmetric_lab_router
from app.api.hash_lab import router as hash_lab_router
from app.api.accounts import router as accounts_router

from app.security.keys import create_process_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create one cryptographic key for the lifetime of the process."""
    app.state.process_key = create_process_key()
    yield


app = FastAPI(
    title="Digital Dean API",
    version="0.5.0",
    description="Educational API for the Digital Dean system",
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(students_router)
app.include_router(secure_notes_router)
app.include_router(crypto_lab_router)
app.include_router(asymmetric_lab_router)
app.include_router(hash_lab_router)
app.include_router(accounts_router)

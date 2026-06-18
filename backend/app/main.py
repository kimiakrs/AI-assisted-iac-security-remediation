from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.scan import router as scan_router

app = FastAPI(title="AI Security Copilot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "AI Security Copilot backend is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

app.include_router(scan_router)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
import app.models.models
from app.routes.scan_routes import router as scan_router
from app.routes.report_routes import router as report_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ASM Tool",
    description="Attack Surface Management Tool",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(report_router)

@app.get("/")
def root():
    return {"status": "ASM Tool is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}
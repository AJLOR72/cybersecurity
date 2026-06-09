#!/usr/bin/env python3
"""
PRIMUS-ADVANCED API Server - REST API for Self-Learning Cybersecurity
"""

import os
import json
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import uvicorn

from primus_advanced import PRIMUSAdvanced

# Initialize PRIMUS
primus = PRIMUSAdvanced()

# FastAPI app
app = FastAPI(
    title="PRIMUS-ADVANCED API",
    description="Self-Learning Autonomous Cybersecurity System",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class EventRequest(BaseModel):
    source_ip: str
    dest_ip: str = "internal"
    dest_port: int = 0
    bytes_sent: int = 0
    duration_ms: float = 0
    process_name: str = ""
    log_line: str = ""
    protocol: str = "tcp"

class FeedbackRequest(BaseModel):
    event_id: int
    was_correct: bool

# API Endpoints
@app.get("/")
@app.get("/dashboard")
async def dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "primus_advanced_web.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse("""
    <html>
        <head><title>PRIMUS-ADVANCED</title></head>
        <body>
            <h1>🧠 PRIMUS-ADVANCED</h1>
            <p>Self-Learning Cybersecurity System</p>
            <p>API running. Use /metrics for status.</p>
        </body>
    </html>
    """)

@app.get("/health")
async def health():
    return {"status": "ok", "system": "PRIMUS-ADVANCED", "timestamp": time.time()}

@app.get("/metrics")
async def metrics():
    return primus.get_status()

@app.post("/analyze")
async def analyze_event(event: EventRequest):
    result = primus.analyze_event(
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        dest_port=event.dest_port,
        bytes_sent=event.bytes_sent,
        duration_ms=event.duration_ms,
        process_name=event.process_name,
        log_line=event.log_line,
        protocol=event.protocol
    )
    return result

@app.post("/feedback")
async def feedback(request: FeedbackRequest):
    primus.learn_from_feedback(request.event_id, request.was_correct)
    return {"status": "learned", "event_id": request.event_id, "was_correct": request.was_correct}

@app.post("/control/dry_run")
async def set_dry_run(enabled: bool):
    primus.set_dry_run(enabled)
    return {"status": "ok", "dry_run": enabled}

@app.post("/control/halt")
async def halt():
    primus.halt()
    return {"status": "halted"}

@app.post("/control/resume")
async def resume():
    primus.resume()
    return {"status": "resumed"}

@app.get("/memory/stats")
async def memory_stats():
    return {
        "synapses": len(primus.memory.synapses),
        "pattern_history": len(primus.memory.pattern_history),
        "learning_rate": primus.memory.learning_rate
    }

@app.get("/correlation/campaigns")
async def get_campaigns():
    return {"campaigns": primus.correlation_engine.campaigns}

if __name__ == "__main__":
    port = int(os.getenv("PRIMUS_PORT", 8000))
    host = os.getenv("PRIMUS_HOST", "0.0.0.0")
    
    print("="*60)
    print("🧠 PRIMUS-ADVANCED API Server Starting...")
    print("="*60)
    print(f"📍 API: http://{host}:{port}")
    print(f"📊 Dashboard: http://{host}:{port}/dashboard")
    print(f"📈 Metrics: http://{host}:{port}/metrics")
    print(f"🧠 Memory: http://{host}:{port}/memory/stats")
    print("="*60)
    
    uvicorn.run(app, host=host, port=port, log_level="info")
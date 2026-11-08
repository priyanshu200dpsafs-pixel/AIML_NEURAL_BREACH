#!/usr/bin/env python3
"""
CLI Launcher for Neural Breach Backend Service
Usage:
  python -m src.backend.run_server [--port 8000] [--host 0.0.0.0]
"""

import sys
import argparse
import uvicorn
from src.backend.config import settings


def main():
    parser = argparse.ArgumentParser(description="Neural Breach FastAPI Backend Service")
    parser.add_argument("--host", default=settings.HOST, help="Host interface to bind")
    parser.add_argument("--port", type=int, default=settings.PORT, help="Port to listen on")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    args = parser.parse_args()

    print(f"[*] Starting Neural Breach Backend on {args.host}:{args.port} (Observe-Only Mode)...")
    uvicorn.run(
        "src.backend.app:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level="info"
    )


if __name__ == "__main__":
    main()

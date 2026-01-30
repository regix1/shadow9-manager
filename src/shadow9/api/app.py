"""
FastAPI Application Factory.

Creates and configures the FastAPI application.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .endpoints import health, server, users


def _get_cors_origins() -> list[str]:
    """
    Get CORS allowed origins from environment.

    Set SHADOW9_CORS_ORIGINS as comma-separated list of origins.
    Example: SHADOW9_CORS_ORIGINS=https://admin.example.com,http://localhost:3000

    Returns empty list if not configured (CORS disabled).
    """
    origins_str = os.getenv("SHADOW9_CORS_ORIGINS", "")
    if not origins_str:
        return []
    return [origin.strip() for origin in origins_str.split(",") if origin.strip()]


def create_app(
    title: str = "Shadow9 Manager API",
    version: str = "1.0.0",
    description: str = "RESTful API for Shadow9 SOCKS5 proxy manager",
    enable_cors: bool = True
) -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Args:
        title: API title
        version: API version
        description: API description
        enable_cors: Enable CORS middleware
        
    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title=title,
        version=version,
        description=description,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    
    # CORS middleware - only enabled if origins are configured
    cors_origins = _get_cors_origins()
    if enable_cors and cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["X-API-Key", "Content-Type"],
        )
    
    # Include routers
    app.include_router(health.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(server.router, prefix="/api")
    
    @app.get("/")
    async def root():
        """Root endpoint with API info."""
        return {
            "name": title,
            "version": version,
            "docs": "/api/docs",
            "health": "/api/health"
        }
    
    return app


# Default app instance
app = create_app()


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    reload: bool = False
) -> None:
    """
    Run the API server.
    
    Args:
        host: Server host address
        port: Server port
        reload: Enable auto-reload for development
    """
    import uvicorn
    
    uvicorn.run(
        "shadow9.api.app:app",
        host=host,
        port=port,
        reload=reload
    )


if __name__ == "__main__":
    run_server()

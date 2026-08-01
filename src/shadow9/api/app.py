"""
FastAPI Application Factory.

Creates and configures the FastAPI application.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from .endpoints import health, server, users, wireguard


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


def docs_enabled() -> bool:
    """
    Whether to publish the interactive docs and the OpenAPI schema.

    Set SHADOW9_API_DOCS=1 to turn them on. They are off by default because they
    need no API key, so anyone who reaches the port would otherwise be able to
    enumerate every endpoint, parameter and model.
    """
    return os.getenv("SHADOW9_API_DOCS", "").strip().lower() in ("1", "true", "yes", "on")


def create_app(
    title: str = "Shadow9 Manager API",
    version: str = __version__,
    description: str = "RESTful API for Shadow9 SOCKS5 proxy manager",
    enable_cors: bool = True,
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
    publish_docs = docs_enabled()

    app = FastAPI(
        title=title,
        version=version,
        description=description,
        docs_url="/api/docs" if publish_docs else None,
        redoc_url="/api/redoc" if publish_docs else None,
        openapi_url="/api/openapi.json" if publish_docs else None,
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
    async def root() -> dict:
        """Root endpoint with API info."""
        return {
            "name": title,
            "version": version,
            "docs": "/api/docs" if publish_docs else None,
            "health": "/api/health",
        }

    return app


def create_enrollment_app(
    title: str = "Shadow9 Enrollment API",
    version: str = __version__,
    description: str = "WireGuard enrollment and node downloads",
) -> FastAPI:
    """Create the public app used by WireGuard nodes."""
    publish_docs = docs_enabled()
    enrollment = FastAPI(
        title=title,
        version=version,
        description=description,
        docs_url="/api/docs" if publish_docs else None,
        redoc_url="/api/redoc" if publish_docs else None,
        openapi_url="/api/openapi.json" if publish_docs else None,
    )
    enrollment.include_router(wireguard.router, prefix="/api")
    return enrollment


# Default app instance
app = create_app()
enrollment_app = create_enrollment_app()


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    reload: bool = False,
    enrollment_host: str = "0.0.0.0",
    enrollment_port: int = 8081,
    socks_port: int = 1080,
) -> None:
    """
    Run the API server.

    Args:
        host: Server host address
        port: Server port
        reload: Enable auto-reload for development
        enrollment_host: Enrollment listener host address
        enrollment_port: Enrollment listener port
        socks_port: SOCKS5 listener port
    """
    from threading import Thread
    from time import monotonic

    import uvicorn

    from ..config import listener_port_errors

    port_errors = listener_port_errors(port, enrollment_port, socks_port)
    if port_errors:
        raise ValueError("; ".join(port_errors))

    enrollment = uvicorn.Server(
        uvicorn.Config(
            "shadow9.api.app:enrollment_app",
            host=enrollment_host,
            port=enrollment_port,
            log_level="info",
        )
    )
    errors: list[BaseException] = []

    def serve_enrollment() -> None:
        try:
            enrollment.run()
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=serve_enrollment, name="shadow9-enrollment", daemon=True)
    thread.start()

    deadline = monotonic() + 5.0
    while thread.is_alive() and not enrollment.started and monotonic() < deadline:
        thread.join(0.01)
    if not enrollment.started:
        enrollment.should_exit = True
        thread.join(1.0)
        message = f"Enrollment listener could not start at {enrollment_host}:{enrollment_port}"
        if errors:
            raise RuntimeError(message) from errors[0]
        raise RuntimeError(message)

    try:
        uvicorn.run("shadow9.api.app:app", host=host, port=port, reload=reload, log_level="info")
    finally:
        enrollment.should_exit = True
        thread.join(5.0)


if __name__ == "__main__":
    run_server()

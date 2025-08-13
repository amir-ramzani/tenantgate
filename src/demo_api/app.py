"""Demo resource server: ``/tenants/{tenant_id}/notes``.

Shows the whole isolation chain: ``authlib_mt`` validates the token, binds it
to a tenant, checks the path tenant and the scope; the repository then only
ever touches that tenant's partition. Works the same for user tokens
(``api/read``/``api/write``) and M2M tokens (``api/tenant.<id>.read``/``.write``).

The notes table is a DynamoDB global table, so the API runs active-active in
both Regions (``X-Served-Region`` shows which one answered).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from authlib_mt import TenantContext, TenantDirectory, TokenValidator
from authlib_mt.fastapi import TenantAuth, add_bearer_security
from demo_api.notes import Note, NotesRepository


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Annotated[str, Field(min_length=1, max_length=200)]
    body: Annotated[str, Field(max_length=10_000)] = ""


class NoteOut(BaseModel):
    note_id: str
    tenant_id: str
    title: str
    body: str
    author: str
    created_at: str
    updated_at: str | None = None

    @classmethod
    def of(cls, n: Note) -> NoteOut:
        return cls(**n.__dict__)


class WhoAmI(BaseModel):
    tenant_id: str
    sub: str
    client_id: str
    role: str
    scopes: list[str]
    is_m2m: bool


@dataclass
class DemoDeps:
    validator: TokenValidator
    directory: TenantDirectory
    notes: NotesRepository
    region: str = "unknown"


def create_app(get_deps: Callable[[], DemoDeps], *, resource_server: str = "api") -> FastAPI:
    app = FastAPI(
        title="tenantgate demo API",
        version="0.1.0",
        description=(
            "Sample tenant-scoped resource server built on `authlib_mt`. Accepts user tokens "
            "(`api/read`, `api/write`) and M2M tokens (`api/tenant.<id>.read|write`). "
            "The `tenant_id` in the path must match the token. Every response carries "
            "`X-Served-Region`."
        ),
        servers=[{"url": "/demo", "description": "behind https://api.<domain>"}],
        openapi_tags=[
            {"name": "health", "description": "Liveness and serving Region (public)"},
            {"name": "identity", "description": "What the token resolves to"},
            {"name": "notes", "description": "Tenant-partitioned notes"},
        ],
    )
    add_bearer_security(app, public_paths={"/health"})
    # Factories: the validator/directory are built lazily on the first request.
    auth = TenantAuth(
        lambda: get_deps().validator,
        lambda: get_deps().directory,
        resource_server=resource_server,
    )
    _require = auth.require

    def repo() -> NotesRepository:
        return get_deps().notes

    @app.middleware("http")
    async def region_header(request: Any, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["X-Served-Region"] = get_deps().region
        return response

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Liveness and the Region that served the request. No authentication."""
        return {"status": "ok", "region": get_deps().region}

    @app.get("/tenants/{tenant_id}/whoami", tags=["identity"], response_model=WhoAmI)
    def whoami(ctx: TenantContext = Depends(_require())) -> WhoAmI:
        """
        The tenant context resolved from the token: tenant, role, client and normalised scopes.
        """
        return WhoAmI(
            tenant_id=ctx.tenant_id,
            sub=ctx.sub,
            client_id=ctx.client_id,
            role=ctx.role,
            scopes=sorted(ctx.scopes),
            is_m2m=ctx.is_m2m,
        )

    @app.get("/tenants/{tenant_id}/notes", tags=["notes"], response_model=list[NoteOut])
    def list_notes(
        ctx: TenantContext = Depends(_require("api/read")),
        notes: NotesRepository = Depends(repo),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> list[NoteOut]:
        """List the tenant's notes. Requires `api/read`."""
        return [NoteOut.of(n) for n in notes.list(ctx, limit)]

    @app.post(
        "/tenants/{tenant_id}/notes",
        tags=["notes"],
        status_code=status.HTTP_201_CREATED,
        response_model=NoteOut,
    )
    def create_note(
        body: NoteIn,
        ctx: TenantContext = Depends(_require("api/write")),
        notes: NotesRepository = Depends(repo),
    ) -> NoteOut:
        """Create a note in the tenant's partition. Requires `api/write`."""
        return NoteOut.of(notes.create(ctx, body.title, body.body))

    @app.get("/tenants/{tenant_id}/notes/{note_id}", tags=["notes"], response_model=NoteOut)
    def get_note(
        note_id: str,
        ctx: TenantContext = Depends(_require("api/read")),
        notes: NotesRepository = Depends(repo),
    ) -> NoteOut:
        """Read a note. Requires `api/read`."""
        note = notes.get(ctx, note_id)
        if note is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return NoteOut.of(note)

    @app.put("/tenants/{tenant_id}/notes/{note_id}", tags=["notes"], response_model=NoteOut)
    def update_note(
        note_id: str,
        body: NoteIn,
        ctx: TenantContext = Depends(_require("api/write")),
        notes: NotesRepository = Depends(repo),
    ) -> NoteOut:
        """Replace title and body. Requires `api/write`."""
        note = notes.update(ctx, note_id, body.title, body.body)
        if note is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return NoteOut.of(note)

    @app.delete(
        "/tenants/{tenant_id}/notes/{note_id}",
        tags=["notes"],
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_note(
        note_id: str,
        ctx: TenantContext = Depends(_require("api/write")),
        notes: NotesRepository = Depends(repo),
    ) -> Response:
        """Delete a note. Requires `api/write`."""
        if not notes.delete(ctx, note_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app

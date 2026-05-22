"""Module dispatch + concurrency control. The Runner owns the active asyncio loop.

PySide6's UI thread runs the Qt event loop via qasync's QEventLoop, which is also
an asyncio loop. Modules run inside that loop, so emit-signals-from-coroutine
is safe and Qt updates happen immediately.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import settings
from .types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity

# A producer yields Hits as they arrive. The runner streams them up to the UI.
HitProducer = Callable[[Query], AsyncIterator[Hit]]


@dataclass(slots=True)
class ModuleEntry:
    name: str
    kinds: frozenset[QueryKind]
    producer: HitProducer
    enabled: bool = True


class Runner:
    """Registry + dispatcher. Plug modules in once, run any Query through them."""

    def __init__(self) -> None:
        self._modules: list[ModuleEntry] = []

    def register(
        self,
        name: str,
        kinds: list[QueryKind] | set[QueryKind] | frozenset[QueryKind],
        producer: HitProducer,
    ) -> None:
        self._modules.append(ModuleEntry(name=name, kinds=frozenset(kinds), producer=producer))

    def modules_for(self, kind: QueryKind) -> list[ModuleEntry]:
        return [m for m in self._modules if m.enabled and kind in m.kinds]

    def all_modules(self) -> list[ModuleEntry]:
        return list(self._modules)

    def set_enabled(self, name: str, enabled: bool) -> None:
        for m in self._modules:
            if m.name == name:
                m.enabled = enabled

    async def run(
        self,
        query: Query,
        on_hit: Callable[[Hit], Awaitable[None]] | None = None,
    ) -> QueryResult:
        """Dispatch query to all matching modules. Streams hits via on_hit as they arrive."""
        s = settings()
        sem = asyncio.Semaphore(s.http_concurrency)
        result = QueryResult(query=query)
        started = time.perf_counter()

        async def collect(entry: ModuleEntry) -> None:
            try:
                async for hit in entry.producer(query):
                    async with sem:
                        result.hits.append(hit)
                        if on_hit:
                            try:
                                await on_hit(hit)
                            except Exception:
                                pass
            except asyncio.CancelledError:
                raise
            except Exception as e:
                err = Hit(
                    module=entry.name,
                    source=entry.name,
                    status=HitStatus.ERROR,
                    detail=f"{type(e).__name__}: {e}",
                    severity=Severity.LOW,
                )
                result.hits.append(err)
                if on_hit:
                    try:
                        await on_hit(err)
                    except Exception:
                        pass

        modules = self.modules_for(query.kind)
        if not modules:
            return result

        try:
            async with asyncio.TaskGroup() as tg:
                for m in modules:
                    tg.create_task(collect(m), name=f"osint:{m.name}")
        except* asyncio.CancelledError:
            # Cooperative cancel — siblings already torn down by TaskGroup.
            pass
        except* Exception:
            # Module exceptions are already converted to ERROR Hits inside collect().
            # Anything still surfacing here is unexpected — swallow to keep partial
            # results usable rather than crash the whole query.
            pass

        result.finished_at = datetime.now(UTC)
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result


_runner: Runner | None = None


def runner() -> Runner:
    global _runner
    if _runner is None:
        _runner = Runner()
        from app.modules import register_all  # local import to avoid cycle
        register_all(_runner)
    return _runner

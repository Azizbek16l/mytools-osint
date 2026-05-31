"""Module dispatch + concurrency control. The Runner owns the active asyncio loop.

PySide6's UI thread runs the Qt event loop via qasync's QEventLoop, which is also
an asyncio loop. Modules run inside that loop, so emit-signals-from-coroutine
is safe and Qt updates happen immediately.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity

logger = logging.getLogger("osint.runner")

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

    def modules_for(
        self, kind: QueryKind, *, only: frozenset[str] | None = None
    ) -> list[ModuleEntry]:
        """Modules that handle ``kind``.

        When ``only`` is given, selection is per-call: a module is included
        iff its name is in ``only`` (ignoring the global ``enabled`` flag).
        When ``only`` is None we fall back to the process-global ``enabled``
        default — the historical behaviour.
        """
        if only is not None:
            return [m for m in self._modules if m.name in only and kind in m.kinds]
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
        *,
        modules: frozenset[str] | None = None,
    ) -> QueryResult:
        """Dispatch query to all matching modules. Streams hits via on_hit as they arrive.

        Concurrency model (was a latent bug): HTTP fan-out is bounded by each
        module's OWN per-module gate (``base.py`` builds an
        ``asyncio.Semaphore(settings().http_concurrency)`` per module). The
        runner used to wrap only ``result.hits.append`` in a semaphore, which
        bounded nothing network-side (the append is in-process and cheap) — it
        was dead weight. We removed it; the append happens inline. If a single
        global HTTP cap across modules is ever required, thread a shared
        semaphore into the module signatures (and document it in
        ``http.get_client``); today the per-module gate is the contract.

        ``modules`` (optional) is a per-RUN scope override: only modules whose
        name is in this set run, regardless of the global ``enabled`` flag.
        This makes scope a per-call value so overlapping scans on the shared
        singleton Runner can't corrupt each other's module selection. When
        omitted, the global ``enabled`` default is used (back-compat).
        """
        result = QueryResult(query=query)
        started = time.perf_counter()

        async def collect(entry: ModuleEntry) -> None:
            try:
                async for hit in entry.producer(query):
                    result.hits.append(hit)
                    if on_hit:
                        try:
                            await on_hit(hit)
                        except Exception:
                            logger.debug("on_hit callback failed for %s", entry.name, exc_info=True)
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
                        logger.debug("on_hit callback failed for %s (error hit)", entry.name, exc_info=True)

        modules_to_run = self.modules_for(query.kind, only=modules)
        if not modules_to_run:
            return result

        try:
            async with asyncio.TaskGroup() as tg:
                for m in modules_to_run:
                    tg.create_task(collect(m), name=f"osint:{m.name}")
        except* asyncio.CancelledError:
            # Cooperative cancel — siblings already torn down by TaskGroup.
            pass
        except* Exception as eg:
            # Module exceptions are already converted to ERROR Hits inside collect().
            # Anything still surfacing here is unexpected — keep partial results
            # usable rather than crash, but log it instead of swallowing silently.
            logger.warning("unexpected runner exceptions: %r", eg.exceptions)

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

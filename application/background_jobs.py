"""Small bounded executor used for report and CSV generation."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import threading
from typing import Callable, Hashable, TypeVar


ResultT = TypeVar("ResultT")


class BackgroundJobBusyError(RuntimeError):
    """Raised when the bounded report/export queue has no free slot."""


class BoundedJobExecutor:
    """Run a small number of jobs and reuse identical in-flight work."""

    def __init__(self, max_workers: int, pending_capacity: int) -> None:
        if max_workers < 1 or pending_capacity < 0:
            raise ValueError("Background job limits must be non-negative")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="netguard-file-job",
        )
        self._slots = threading.BoundedSemaphore(max_workers + pending_capacity)
        self._lock = threading.Lock()
        self._jobs: dict[Hashable, Future[object]] = {}
        self._shutdown = False

    def submit(
        self,
        key: Hashable,
        function: Callable[..., ResultT],
        *args: object,
    ) -> Future[ResultT]:
        """Submit work unless the same job is already running."""
        with self._lock:
            existing = self._jobs.get(key)
            if existing is not None and not existing.done():
                return existing  # type: ignore[return-value]
            if self._shutdown:
                raise BackgroundJobBusyError(
                    "File generation is unavailable during shutdown."
                )
            if not self._slots.acquire(blocking=False):
                raise BackgroundJobBusyError(
                    "Too many report or export jobs are already running. "
                    "Wait for one to finish and try again."
                )
            try:
                future = self._executor.submit(function, *args)
            except Exception:
                self._slots.release()
                raise
            self._jobs[key] = future
        # A very fast Future can already be complete here. Register outside
        # the lock because add_done_callback may invoke synchronously.
        future.add_done_callback(
            lambda completed, job_key=key: self._release(job_key, completed)
        )
        return future

    def shutdown(self) -> None:
        """Stop accepting work and join running jobs."""
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _release(self, key: Hashable, future: Future[object]) -> None:
        with self._lock:
            if self._jobs.get(key) is future:
                self._jobs.pop(key, None)
        self._slots.release()

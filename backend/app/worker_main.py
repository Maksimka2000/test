"""Run the report worker as its own process, sharing the API's data directory."""

from __future__ import annotations

import asyncio

from app.settings import Settings
from app.store import Store
from app.strategies import load_strategy
from app.worker import run_worker


def main() -> None:
    settings = Settings.from_env()
    strategy = load_strategy(settings.captcha_strategy, settings)
    store = Store(settings.data_dir, max_attempts=settings.max_attempts)

    async def _run() -> None:
        # Create the event inside the running loop. Python 3.9 binds it at construction.
        await run_worker(asyncio.Event(), store, settings, strategy)

    try:
        asyncio.run(_run())
    finally:
        store.close()


if __name__ == "__main__":
    main()

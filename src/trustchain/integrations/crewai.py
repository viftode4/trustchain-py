"""CrewAI integration for TrustChain.

Usage::

    from crewai import Crew
    from trustchain.integrations.crewai import trust_crew

    crew = Crew(agents=[...], tasks=[...])
    crew = trust_crew(crew)  # Wraps kickoff to record interactions
    crew.kickoff()

Install: ``pip install trustchain-py[crewai]``
"""

from __future__ import annotations

import functools
from typing import Any


def trust_crew(crew: Any, *, name: str | None = None) -> Any:
    """Wrap a CrewAI Crew to record interactions via TrustChain.

    Monkey-patches ``kickoff()`` to start a sidecar and record
    task completions as trust blocks.

    Args:
        crew: A CrewAI ``Crew`` instance.
        name: Optional sidecar name (defaults to crew's name or "crewai").

    Returns:
        The same crew instance with wrapped kickoff.
    """
    original_kickoff = crew.kickoff

    @functools.wraps(original_kickoff)
    def wrapped_kickoff(*args: Any, **kwargs: Any) -> Any:
        from trustchain.sidecar import init

        sidecar_name = name or getattr(crew, "name", None) or "crewai"
        sidecar = init(name=sidecar_name)

        result = original_kickoff(*args, **kwargs)

        # Record completion
        try:
            task_count = len(getattr(crew, "tasks", []))
            agent_count = len(getattr(crew, "agents", []))
            sidecar._post("/checkpoint", {
                "transaction": {
                    "type": "crew_run",
                    "tasks": task_count,
                    "agents": agent_count,
                    "source": "crewai",
                },
            })
        except Exception:
            pass

        return result

    crew.kickoff = wrapped_kickoff
    return crew

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import requests

logger = logging.getLogger("action_card_cache_integrated")


class ActionCardCache:
    def __init__(
        self,
        dbi_url: Optional[str] = None,
        token: Optional[str] = None,
        restaurant_id: Optional[int] = None,
    ):
        self._base_url = (dbi_url or os.environ["DBI_URL"]).rstrip("/")
        self._token = token or os.environ["DBI_SERVICE_TOKEN"]
        self._restaurant_id = int(restaurant_id or os.environ["RESTAURANT_ID"])
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            }
        )
        self._storage: dict[str, dict[str, Any]] = {}
        self.refresh()

    def refresh(self) -> bool:
        try:
            response = self._session.post(
                f"{self._base_url}/internal/action_cards.active",
                json={"restaurant_id": self._restaurant_id},
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            cards = data.get("cards", data) if isinstance(data, dict) else data
            self._cache_cards(cards)
            logger.info("action cards refreshed: %s", len(self._storage))
            return True
        except requests.RequestException as exc:
            logger.error("action cards refresh failed: %s", exc)
            return False

    def get_action_card_from_cache(
        self, card_identifier: tuple[str, str]
    ) -> Optional[dict[str, Any]]:
        if len(card_identifier) != 2:
            return None
        action_type, object_class = card_identifier
        return self._storage.get(f"{action_type}_{object_class}")

    def _cache_cards(self, cards: Any) -> None:
        if not isinstance(cards, list):
            return
        for card in cards:
            if not isinstance(card, dict):
                continue
            action_type = card.get("action_type")
            object_class = card.get("object_class")
            if action_type is None or object_class is None:
                continue
            self._storage[f"{action_type}_{object_class}"] = card
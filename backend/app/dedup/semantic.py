import os
import math
import logging
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

logger = logging.getLogger(__name__)

# Dimension size for OpenAI text-embedding-3-small
EMBEDDING_DIM = 1536
# Distance threshold: cosine_distance = 1 - cosine_similarity.
# Distance <= 0.18 corresponds to >= 82% semantic similarity.
DEFAULT_DISTANCE_THRESHOLD = 0.18


class SemanticDedupEngine:
    """
    Computes text embeddings for findings and identifies semantic duplicates
    using cosine distance (<=>).
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._client = None

    def _get_client(self):
        if self._client is None:
            if not self.api_key:
                logger.warning("OPENAI_API_KEY is not configured; semantic deduplication will be bypassed.")
                return None
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            except ImportError:
                logger.error("openai package not installed. Run `pip install openai`.")
                return None
        return self._client

    def generate_embedding(self, text: str) -> Optional[List[float]]:
        """Generates a 1536-dimension float vector using text-embedding-3-small."""
        client = self._get_client()
        if not client or not text.strip():
            return None

        clean_text = text.replace("\n", " ").strip()[:8000]
        try:
            response = client.embeddings.create(
                model="text-embedding-3-small",
                input=[clean_text],
                dimensions=EMBEDDING_DIM
            )
            return response.data[0].embedding
        except Exception as exc:
            logger.error(f"Failed to generate embedding: {exc}")
            return None

    @staticmethod
    def cosine_distance_numpy(vec1: List[float], vec2: List[float]) -> float:
        """
        Pure-Python/NumPy fallback to calculate cosine distance:
        Distance = 1.0 - (vec1 . vec2) / (||vec1|| * ||vec2||)
        Range: 0.0 (identical direction) to 2.0 (opposite).
        """
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm_a = math.sqrt(sum(a * a for a in vec1))
        norm_b = math.sqrt(sum(b * b for b in vec2))

        if norm_a == 0.0 or norm_b == 0.0:
            return 1.0

        similarity = dot_product / (norm_a * norm_b)
        # Numerical clamp to avoid float precision rounding outside [-1.0, 1.0]
        similarity = max(min(similarity, 1.0), -1.0)
        return 1.0 - similarity

    def find_semantic_duplicate(
        self,
        db: Session,
        host: str,
        port: int,
        query_embedding: List[float],
        threshold: float = DEFAULT_DISTANCE_THRESHOLD,
        finding_model=None,
    ) -> Optional[Tuple[any, float]]:
        """
        Searches for existing findings on the same host and port where
        the cosine distance between embeddings is below the threshold.
        """
        if not query_embedding or finding_model is None:
            return None

        # 1. Native pgvector optimization path
        try:
            # Assumes finding_model.embedding has the pgvector column type
            stmt = (
                select(
                    finding_model,
                    finding_model.embedding.cosine_distance(query_embedding).label("dist")
                )
                .filter(finding_model.host == host, finding_model.port == port)
                .filter(finding_model.embedding.isnot(None))
                .order_by("dist")
                .limit(1)
            )
            row = db.execute(stmt).first()
            if row and row.dist <= threshold:
                return row[0], float(row.dist)
        except Exception:
            # 2. Database/Driver fallback (In-memory verification for SQLite or unindexed tables)
            db.rollback()
            candidates = (
                db.query(finding_model)
                .filter(finding_model.host == host, finding_model.port == port)
                .filter(finding_model.embedding.isnot(None))
                .all()
            )

            best_match = None
            min_dist = float("inf")

            for candidate in candidates:
                cand_vec = candidate.embedding
                if isinstance(cand_vec, str):
                    import json
                    cand_vec = json.loads(cand_vec)

                dist = self.cosine_distance_numpy(query_embedding, cand_vec)
                if dist < min_dist:
                    min_dist = dist
                    best_match = candidate

            if best_match and min_dist <= threshold:
                return best_match, min_dist

        return None
import os
import json
import faiss
import numpy as np
from functools import lru_cache
from sentence_transformers import SentenceTransformer


VECTOR_DIR = "vector_store"
INDEX_PATH = os.path.join(VECTOR_DIR, "index.faiss")
CHUNKS_PATH = os.path.join(VECTOR_DIR, "chunks.json")
MODEL_NAME = "all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def get_embedding_model():
    """
    Load the embedding model once and reuse it.
    This avoids loading all-MiniLM-L6-v2 on every request.
    """
    return SentenceTransformer(MODEL_NAME)


@lru_cache(maxsize=1)
def load_faiss_index():
    """
    Load FAISS index once and reuse it.
    """
    if not os.path.exists(INDEX_PATH):
        return None

    return faiss.read_index(INDEX_PATH)


@lru_cache(maxsize=1)
def load_chunks():
    """
    Load chunk metadata once and reuse it.
    """
    if not os.path.exists(CHUNKS_PATH):
        return []

    with open(CHUNKS_PATH, "r") as f:
        return json.load(f)


def retrieve_context(query: str, top_k: int = 3, include_scores: bool = False) -> list:
    """
    Retrieve relevant policy chunks from the local FAISS vector store.

    Input:
      query = text generated from Checkov findings

    Output:
      list of context chunks:
      [
        {
          "source": "...",
          "text": "...",
          "score": optional distance score
        }
      ]
    """

    if not query or not query.strip():
        return []

    index = load_faiss_index()
    chunks = load_chunks()

    if index is None:
        return []

    if not chunks:
        return []

    model = get_embedding_model()

    query_embedding = model.encode([query])
    query_embedding = np.array(query_embedding).astype("float32")

    search_k = min(top_k, len(chunks))

    distances, indices = index.search(query_embedding, search_k)

    results = []

    for distance, idx in zip(distances[0], indices[0]):
        if idx < 0:
            continue

        if idx >= len(chunks):
            continue

        chunk = dict(chunks[idx])

        if include_scores:
            chunk["score"] = float(distance)

        results.append(chunk)

    return results


def clear_rag_cache():
    """
    Clear cached model/index/chunks.
    Use this after rebuilding the FAISS index.
    """
    get_embedding_model.cache_clear()
    load_faiss_index.cache_clear()
    load_chunks.cache_clear()


if __name__ == "__main__":
    import sys

    query = " ".join(sys.argv[1:])

    results = retrieve_context(
        query=query,
        top_k=5,
        include_scores=True,
    )

    for result in results:
        print("SOURCE:", result.get("source"))
        print("SCORE:", result.get("score"))
        print(result.get("text"))
        print("-" * 50)

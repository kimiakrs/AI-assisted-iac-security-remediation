import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


VECTOR_DIR = "vector_store"
INDEX_PATH = os.path.join(VECTOR_DIR, "index.faiss")
CHUNKS_PATH = os.path.join(VECTOR_DIR, "chunks.json")
MODEL_NAME = "all-MiniLM-L6-v2"


def retrieve_context(query: str, top_k: int = 3) -> list:
    if not os.path.exists(INDEX_PATH):
        return []

    if not os.path.exists(CHUNKS_PATH):
        return []

    model = SentenceTransformer(MODEL_NAME)

    index = faiss.read_index(INDEX_PATH)

    with open(CHUNKS_PATH, "r") as f:
        chunks = json.load(f)

    query_embedding = model.encode([query])
    query_embedding = np.array(query_embedding).astype("float32")

    distances, indices = index.search(query_embedding, top_k)

    results = []

    for idx in indices[0]:
        if idx < len(chunks):
            results.append(chunks[idx])

    return results


if __name__ == "__main__":
    import sys

    query = " ".join(sys.argv[1:])
    results = retrieve_context(query)

    for result in results:
        print("SOURCE:", result["source"])
        print(result["text"])
        print("-" * 50)

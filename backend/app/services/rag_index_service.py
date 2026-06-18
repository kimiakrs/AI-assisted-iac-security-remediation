import os
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


KNOWLEDGE_DIR = "knowledge_base"
VECTOR_DIR = "vector_store"
INDEX_PATH = os.path.join(VECTOR_DIR, "index.faiss")
CHUNKS_PATH = os.path.join(VECTOR_DIR, "chunks.json")
MODEL_NAME = "all-MiniLM-L6-v2"


def load_markdown_files():
    chunks = []

    for filename in os.listdir(KNOWLEDGE_DIR):
        if not filename.endswith(".md"):
            continue

        path = os.path.join(KNOWLEDGE_DIR, filename)

        with open(path, "r") as f:
            text = f.read()

        sections = text.split("\n# ")

        for section in sections:
            section = section.strip()
            if section:
                chunks.append({
                    "source": filename,
                    "text": section
                })

    return chunks


def build_index():
    os.makedirs(VECTOR_DIR, exist_ok=True)

    chunks = load_markdown_files()

    if not chunks:
        raise ValueError("No knowledge base chunks found.")

    model = SentenceTransformer(MODEL_NAME)

    texts = [chunk["text"] for chunk in chunks]
    embeddings = model.encode(texts)
    embeddings = np.array(embeddings).astype("float32")

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)

    faiss.write_index(index, INDEX_PATH)

    with open(CHUNKS_PATH, "w") as f:
        json.dump(chunks, f, indent=2)

    print(f"Indexed {len(chunks)} chunks.")
    print(f"Saved index to {INDEX_PATH}")
    print(f"Saved chunks to {CHUNKS_PATH}")


if __name__ == "__main__":
    build_index()

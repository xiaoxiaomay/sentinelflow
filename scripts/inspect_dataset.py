import json

corpus_path = "data/raw/finder_corpus.jsonl"

with open(corpus_path, "r") as f:
    for i in range(3):
        row = json.loads(f.readline())
        print(row.keys())
        print(row["title"][:80])
        print(row["text"][:200])
        print("="*40)
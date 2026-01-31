# scripts/prepare_public_corpus.py
import os, json, gzip
from pathlib import Path

RAW = "data/raw/finder_corpus.jsonl"
OUT = "data/processed/public_corpus.jsonl"

DEFAULT_META = {
    "source_type": "public",
    "trust_score": 1.0,
    "sensitivity_level": 0,
    "category": "public_filing",
    "tags": ["FinanceRAG", "FinDER"],
    "dataset": "FinanceRAG-FinDER"
}

def open_maybe_gz(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")

def main():
    Path(os.path.dirname(OUT)).mkdir(parents=True, exist_ok=True)

    n = 0
    with open_maybe_gz(RAW) as f_in, open(OUT, "w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)

            out = {
                "_id": obj.get("_id"),
                "title": obj.get("title", "") or "",
                "text": obj.get("text", "") or "",
                **DEFAULT_META
            }

            # 你现在 finder 的 _id 看起来像 "MSFT2023...." / "ADBE...."
            # 这里顺手提取 ticker（没有也无所谓）
            _id = out["_id"] or ""
            ticker = ""
            for i in range(1, min(6, len(_id)+1)):
                if _id[:i].isalpha():
                    ticker = _id[:i]
            if ticker:
                out["ticker"] = ticker

            f_out.write(json.dumps(out, ensure_ascii=False) + "\n")
            n += 1

    print(f"Saved processed public corpus -> {OUT}")
    print(f"Docs processed: {n}")

if __name__ == "__main__":
    main()
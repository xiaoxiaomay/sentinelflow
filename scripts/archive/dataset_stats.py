import json
from collections import Counter
from pathlib import Path

def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def guess_ticker(doc_id: str) -> str:
    # 经验规则：很多 FinanceRAG 的 corpus_id 形如 ADBE2023xxxx / MSFT2023xxxx
    # 取前 4~5 个字母作为 ticker 候选（只保留字母）
    letters = []
    for ch in doc_id:
        if ch.isalpha():
            letters.append(ch)
        else:
            break
    t = "".join(letters)
    return t[:6] if t else "UNKNOWN"

def main():
    corpus_path = Path("data/raw/finder_corpus.jsonl")
    if not corpus_path.exists():
        raise FileNotFoundError(f"Not found: {corpus_path}. Did you unzip to data/raw/?")

    n = 0
    title_lens = []
    text_lens = []
    tickers = Counter()
    keys_counter = Counter()

    for obj in iter_jsonl(corpus_path):
        n += 1
        keys_counter.update(obj.keys())
        doc_id = str(obj.get("_id", ""))
        tickers[guess_ticker(doc_id)] += 1

        title = obj.get("title", "") or ""
        text = obj.get("text", "") or ""
        title_lens.append(len(title))
        text_lens.append(len(text))

    print("=== Finder Corpus Stats ===")
    print(f"Docs: {n}")
    print(f"Fields seen: {sorted(keys_counter.keys())}")
    print(f"Avg title length: {sum(title_lens)/len(title_lens):.1f}")
    print(f"Avg text length:  {sum(text_lens)/len(text_lens):.1f}")
    print("\nTop 15 ticker-like prefixes:")
    for k, v in tickers.most_common(15):
        print(f"  {k:8s}  {v}")

if __name__ == "__main__":
    main()
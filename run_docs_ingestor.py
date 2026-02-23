import subprocess
import sys


def main():
    print("Starting Documents Ingestor...")
    # 构造命令：python -m datasource.docs_unified_ingestor
    cmd = [sys.executable, "-m", "datasource.docs_unified_ingestor"]

    try:
        # shell=False 更安全，直接传递参数列表
        result = subprocess.run(cmd, check=True)
        if result.returncode == 0:
            print("Ingestion completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running ingestor: {e}")
    except KeyboardInterrupt:
        print("Ingestor stopped by user.")


if __name__ == "__main__":
    main()
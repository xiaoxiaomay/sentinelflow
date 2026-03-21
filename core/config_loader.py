import os
import yaml
from pathlib import Path

def get_project_root() -> Path:
    """动态获取项目根目录"""
    return Path(__file__).parent.parent

def load_global_config():
    root = get_project_root()
    config_path = root / "config.yaml"
    with open(config_path, 'r', encoding="utf-8") as f:
        return yaml.safe_load(f)

def use_postgres() -> bool:
    """Check if PostgreSQL should be used. Defaults to False if USE_POSTGRES=false."""
    val = os.environ.get("USE_POSTGRES", "true").lower()
    return val not in ("false", "0", "no", "off")

def get_db_params():
    """获取数据库连接参数"""
    cfg = load_global_config()
    db = cfg.get("db", {})
    return {
        "host": os.environ.get("DB_HOST", db.get("host", "localhost")),
        "database": os.environ.get("DB_NAME", db.get("name", "sentinel_db")),
        "user": os.environ.get("DB_USER", db.get("user", "postgres")),
        "password": os.environ.get("DB_PASSWORD", db.get("password", "")),
        "port": int(os.environ.get("DB_PORT", db.get("port", 5432)))
    }

def get_engine_configs():
    """获取引擎所需的各种子配置"""
    cfg = load_global_config()
    return {
        "embedding": cfg.get("embedding", {}),
        "paths": cfg.get("paths", {}),
        "audit": cfg.get("audit", {})
    }
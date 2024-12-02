from pathlib import Path

import toml

from pydantic import BaseModel


def root_dir() -> Path:
    return Path(__file__).resolve().parent / ".." / ".."


def config_path() -> Path:
    return root_dir() / "config.toml"


class MISPEventConfig(BaseModel):
    include_report: bool
    use_vmray_tags: bool
    include_vtis: bool
    ioc_only: bool


class VMRayConfig(BaseModel):
    host: str
    api_key: str
    verify_cert: bool
    last_submission_id: int
    chunk_size: int


class Config(BaseModel):
    feed_path: str
    logging: str
    vmray: VMRayConfig
    misp_event: MISPEventConfig


def load_config() -> Config:
    cfg = config_path()
    with cfg.open("r", encoding="utf-8") as fobj:
        config = Config.model_validate(toml.load(fobj))

    return config


def save_config(config: Config):
    cfg = config_path()
    with cfg.open("w", encoding="utf-8") as fobj:
        toml.dump(config.model_dump(), fobj)

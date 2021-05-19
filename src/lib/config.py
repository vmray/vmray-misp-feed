from pathlib import Path

import toml

from pydantic import BaseSettings


def root_dir() -> Path:
    return Path(__file__).resolve().parent / ".." / ".."


def config_path() -> Path:
    return root_dir() / "config.toml"


class MISPEventConfig(BaseSettings):
    include_report: bool
    use_vmray_tags: bool
    include_vtis: bool
    ioc_only: bool


class VMRayConfig(BaseSettings):
    host: str
    api_key: str
    verify_cert: bool
    last_submission_id: int
    chunk_size: int


class Config(BaseSettings):
    feed_path: str
    logging: str
    vmray: VMRayConfig
    misp_event: MISPEventConfig


def load_config() -> Config:
    cfg = config_path()
    with open(cfg, "r") as fobj:
        config = Config(**toml.load(fobj))

    return config


def save_config(config: Config):
    cfg = config_path()
    with open(cfg, "w") as fobj:
        toml.dump(config.dict(), fobj)

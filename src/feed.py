import json
import logging

from pathlib import Path
from typing import List

from lib.config import load_config, save_config
from lib.vmray.parser import VMRayParser, VMRayParserError


logging.getLogger("urllib3").setLevel(logging.WARNING)


LOG_LEVEL_MAPPING = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def setup_logging(log_level_str: str):
    log_level = LOG_LEVEL_MAPPING[log_level_str]
    logger = logging.getLogger("vmray_feed")
    logger.setLevel(log_level)

    file_logger = logging.FileHandler("feed.log")
    file_logger.setLevel(log_level)

    stream_logger = logging.StreamHandler()
    stream_logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(filename)-12s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_logger.setFormatter(formatter)
    stream_logger.setFormatter(formatter)

    logger.addHandler(file_logger)
    logger.addHandler(stream_logger)

    return logger


class VMRayFeed:
    """a local feed for MISP"""

    def __init__(self):
        self.config = load_config()

        self.logger = setup_logging(self.config.logging)

        self.feed_path = Path(self.config.feed_path)
        if not self.feed_path.is_dir():
            self.feed_path.mkdir(parents=True)

    def _save_event(self, event: dict):
        event_uuid = event["Event"]["uuid"]
        with (self.feed_path / f"{event_uuid}.json").open(
            "w", encoding="utf-8"
        ) as fobj:
            json.dump(event, fobj, indent=2)

    def _save_hashes(self, hashes: List[str]):
        with (self.feed_path / "hashes.csv").open("a", encoding="utf-8") as fobj:
            for hsh in hashes:
                fobj.write(f"{hsh[0]},{hsh[1]}\n")

    def _save_manifest(self, new_manifest: dict):
        """
        Save the manifest.json file.
        Try to read and update/extend it if the file already exists.
        Create a new one otherwise.
        """
        manifest_file = self.feed_path / "manifest.json"
        try:
            with manifest_file.open("r", encoding="utf-8") as fobj:
                manifest = json.load(fobj)
                if manifest:
                    manifest.update(new_manifest)
                else:
                    manifest = new_manifest
        except (FileNotFoundError, json.JSONDecodeError):
            self.logger.warning("Manifest file could not be read. Creating a new one.")
            manifest = new_manifest

        with manifest_file.open("w", encoding="utf-8") as fobj:
            json.dump(manifest, fobj, indent=2)

    def update_feed(self):
        """update the feed based on the last submission id"""

        manifest = {}
        hashes = []

        parser = VMRayParser(self.config)
        submission_id = None
        for submission in parser.last_submissions():
            submission_id = submission["submission_id"]
            self.logger.info("Processing submission %d", submission_id)

            try:
                event = parser.parse(submission_id)
            except VMRayParserError:
                self.logger.exception(
                    "Error while parsing reports from submission %d", submission_id
                )
                continue

            event_feed = event.to_feed(with_meta=True)

            hashes += [[h, event.uuid] for h in event_feed["Event"].pop("_hashes")]
            manifest.update(event_feed["Event"].pop("_manifest"))

            self._save_event(event_feed)

        if not submission_id:
            self.logger.info("No new submissions found.")
            return

        self._save_manifest(manifest)
        self._save_hashes(hashes)

        # update last submission id
        self.config.vmray.last_submission_id = submission_id
        save_config(self.config)


def main():
    vmray_feed = VMRayFeed()
    vmray_feed.update_feed()


if __name__ == "__main__":
    main()

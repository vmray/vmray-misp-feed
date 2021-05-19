# VMRay Feed

The **vmray-feed** is a convenient way of converting analysis results from the VMRay Platform to MISP events. This script is meant to run periodically as a background task.

## config.toml

The `config.toml` configuration file provides options for configuring the **vmray-feed** to output MISP events with the information you choose:

* `feed_path` is, by default, set to `/var/www/MISP/app/tmp/vmray-feed`. But you can modify this setting to save files to whichever folder you prefer. However, MISP needs at least read access to this path in order to import the feed. If you would like to automatically delete event files from this folder, MISP also needs write access.
* `logging` is, by default, set to `INFO`. You can change it to `CRITICAL`, `ERROR`, `WARNING` or`DEBUG`.

### VMRay Settings

**CAUTION**: `last_submission_id` will be overwritten, every time the script runs.

* `host`: The VMRay Platform host.
* `api_key`: The API Key for that host.
* `verify_cert`: Should the certificate be validated or not (use false for self-signed certificates).
* `last_submission_id`: Defines the last ID used by the script. If you leave it set to 0 for the first start, all analyses are converted to MISP Objects.
* `chunk_size`: Defines the number of items to fetch during a single run.

### MISP Event Settings

* `include_report`: If set to true, the report of analyses is attached to the MISP event.
* `use_vmray_tags`: Use VMRay taxonomies for events and attributes. VMRay taxonomies have to be activated.
* `include_vtis`: Include VMRay Threat Identifiers (VTIs) in MISP events.
* `ioc_only`: Only include artifacts that are Indicators of Compromise (IOCs).

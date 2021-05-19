# vmray-misp-feed

Automatically import VMRay Platform analyses into MISP as a feed.

![Screenshot](./docs/assets/screenshot.png)

## Getting Started

There are two ways to get started:

1. Using the [install script](./install.sh), which automates most of the process.
2. Manually installing vmray-misp-feed; see [Installation](./docs/install.md) for instructions applicable to most use cases

If you choose to use the install script, please inspect the script before execution.
To install, run:

```bash
curl https://raw.githubusercontent.com/vmray/vmray-misp-feed/main/install.sh | sh
```

When done, the install script prints out instructions for running and starting **vmray-misp-feed**.

You can also find the instructions for setting up a MISP feed in the [docs](./docs/misp-feeds.md).

For a more detailed description on how to configure **vmray-misp-feed**, see [vmray-misp-feed](./docs/vmray-misp-feed.md)

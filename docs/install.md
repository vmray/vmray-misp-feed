# Installation

- [Upgrading](#upgrading)
- [Requirements](#requirements)
- [install.sh](#install.sh)

This document explains how to install the **vmray-misp-feed** for MISP.

# Upgrading
If you are upgrading from a previous version of the **vmray-misp-feed**, you can just install the new version over the old one by executing:
```bash
git pull
```
in the **vmray-misp-feed** directory.

# Requirements
To run the **vmray-misp-feed**, you need the following installed on your system:
* git  - to download/upgrade this repository
* python3
* pip
* a MISP instance installed on the same machine
* venv - recommended, but not required

# install.sh

Install the **vmray-misp-feed** using either `curl` or `wget` or another similar tool.

For example, if you use `wget`, execute:

```bash
curl https://raw.githubusercontent.com/vmray/vmray-misp-feed/main/install.sh | sh
```

The script outputs how to run and start the **vmray-misp-feed**.

If the script fails to install the **vmray-misp-feed**, you are probably missing some requirements, so ensure that you have installed all requirements listed in the [Requirements](#requirements) section and try again.

If the script still fails, install the **vmray-misp-feed** [manually](#manual-installation), as described below.

## Manual Inspection
It's a good idea to inspect the install script from projects you don't yet know.
You can do this by downloading the install script first, looking through it to verify that everything looks normal, and then running it:

```bash
wget https://raw.githubusercontent.com/vmray/vmray-misp-feed/main/install.sh -O /tmp/install.sh
sh /tmp/install.sh
```

## Manual Installation
Execute the following commands to install the **vmray-misp-feed** on your system:
```bash
git clone https://github.com/vmray/vmray-misp-feed.git /opt/vmray-misp-feed
cd /opt/vmray-misp-feed
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools
pip install -r requirements.txt
cp config.toml.template config.toml
vi config.toml  # add your VMRay host and api_key to this configuration file
```

Next, create a cronjob for the **vmray-misp-feed**:
```bash
sudo crontab -e
```
and paste `0 * * * * /opt/vmray-misp-feed/.venv/bin/python /opt/vmray-misp-feed/src/feed.py` inside it.

See [MISP Feeds](../misp-feeds.md), for information about how to set up the feed in MISP.

If you don't already have a cronjob for fetching MISP feeds, create one as well. Use the feed id from **vmray-misp-feed** from within MISP, or if you want to update all feeds, use `all` instead of `feed-id`:
```
15 * * * * /var/www/MISP/app/Console/cake Server fetchFeed <user-id> <feed-id>
```

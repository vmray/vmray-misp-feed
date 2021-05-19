#!/bin/sh
set -eu

# VMRay MISP auto import installation script
# See <github>/docs/install.md

# Default settings
REMOTE=${REMOTE:-https://github.com/vmray/vmray-misp-feed.git}
TARGET=${TARGET:-/opt/vmray-misp-feed}

command_exists() {
	command -v "$@" >/dev/null 2>&1
}

venv_exists() {
    python3 - << EOF
try:
    import venv
    exit(0)
except ModuleNotFoundError:
    exit(1)
EOF
}

fmt_error() {
  echo ${RED}"Error: $@"${RESET} >&2
}

setup_colors() {
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    BLUE=$(printf '\033[34m')
    BOLD=$(printf '\033[1m')
    RESET=$(printf '\033[m')
}

usage() {
    arg0="$0"
    cat << EOF
Installs a feed for MISP that uses VMRay Platform Analysis Reports.
It tries to use the system package manager if possible.
After a successful installation, it explains how to start using vmray-misp-feed.

    $arg0 [--help] [--target target_dir]

    --target
        Set a target directory to install vmray-misp-feed (default is: ${TARGET})

More installation documentation is available at https://github.com/vmray/vmray-misp-feed/blob/main/docs/install.md
EOF
}

echo_postinstall() {
    cat << EOF
In order to successfully import VMRay reports into MISP, you need to change some values
in ${BLUE}`config.toml`${RESET}. At least, provide the VMRay host and API key.

In addition, you need to create a new feed in MISP. See ${BLUE}docs/misp-feeds.md${RESET} for more details.

To periodically update the feed and import it into MISP, you need to create two cronjobs:
    1. for the VMRay MISP feed
    2. for MISP to poll feeds regulary

    Copy/paste both lines into `sudo crontab -e`:
    0 * * * * sudo -u www-data /opt/vmray-misp-feed/.venv/bin/python /opt/vmray-misp-feed/src/feed.py
    15 * * * * /var/www/MISP/app/Console/cake Server fetchFeed 1 <vmray-misp-feed-id>
EOF
}

download_repo() {
    echo "${BLUE} Cloning vmray-misp-feed${RESET}"

    command_exists git || {
        fmt_error "git is not installed"
        exit 1
    }

    git clone -c core.eol=lf -c core.autocrlf=false "$REMOTE" "$TARGET" || {
        fmt_error "git clone of vmray-misp-feed failed"
        exit 1
    }

    cd $TARGET

    echo
}

setup_venv() {
    echo "${BLUE} Creating python enviroment${RESET}"

    command_exists python3 || {
        fmt_error "python3 is not installed"
        exit 1
    }

    venv_exists || {
        fmt_error "venv is not installed"
        exit 1
    }

    python3 -m venv .venv

    command_exists pip3 || {
        fmt_error "pip is not installed"
        exit 1
    }

    ${TARGET}/.venv/bin/pip install -U pip setuptools --isolated
    ${TARGET}/.venv/bin/pip install -r requirements.txt
}

main() {
    # parse arguments
    while [ $# -gt 0 ]; do
        case $1 in
            -t | --target) TARGET="$2"; shift; ;;
            -h | --h | -help | --help) usage; exit 0 ;;
        esac
        shift
    done

    setup_colors

    download_repo
    setup_venv

    cp ${TARGET}/config.toml.template ${TARGET}/config.toml
    chown www-data:www-data -R ${TARGET}

    echo_postinstall
}

main "$@"

#!/bin/sh
# Installs the Inwire capture agent on macOS or Linux.
#
# This script ships *inside* the agent tarball, next to the sources it
# installs, which is the whole point of it. What it replaces were two
# bootstrap scripts with a copy of agent.py pasted into them - a copy that
# stopped being updated somewhere around version 2.1 and then quietly spoke a
# protocol the app had stopped understanding: no `hello`, no typed messages, no
# origin check, sniffing every interface from the moment it started. The app
# parsed zero packets and showed the "Update" pill for ever. A copy that can go
# stale will, so there is no copy.
#
#   sudo ./install.sh              install and start
#   sudo ./install.sh uninstall    stop, remove, and leave nothing behind
#
# Elevation is required for the same reason it is on Windows: raw packet
# capture is a privileged operation on every OS.
set -eu

APP_NAME="Inwire Agent"
PREFIX="/opt/inwire-agent"
CONFIG_DIR="/etc/inwire"
LOG_DIR="/var/log/inwire"
SERVICE_LINUX="/etc/systemd/system/inwire-agent.service"
SERVICE_MACOS="/Library/LaunchDaemons/com.inwire.agent.plist"

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

die() {
    echo "error: $*" >&2
    exit 1
}

require_root() {
    [ "$(id -u)" = "0" ] || die "run this with sudo: sudo $0 $*"
}

detect_os() {
    case "$(uname -s)" in
        Darwin) echo macos ;;
        Linux)  echo linux ;;
        *)      die "unsupported system: $(uname -s). The agent runs on Windows, macOS and Linux." ;;
    esac
}

find_python() {
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            # 3.9 is the floor: the agent uses asyncio.to_thread and the
            # websockets releases that dropped the legacy client API.
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    die "Python 3.9 or newer is required and was not found on PATH."
}

install_agent() {
    os=$1
    python=$(find_python)
    echo "==> installing $APP_NAME into $PREFIX"

    mkdir -p "$PREFIX" "$CONFIG_DIR" "$LOG_DIR"
    cp "$SOURCE_DIR"/*.py "$PREFIX/"
    cp "$SOURCE_DIR/requirements-runtime.txt" "$PREFIX/"

    # A virtualenv owned by root, not `pip --user` as the invoking user. The
    # old scripts installed the dependencies for whoever ran sudo and then ran
    # the agent as root, which is a different site-packages: the agent started
    # and immediately failed to import scapy.
    echo "==> creating a virtual environment (root-owned)"
    "$python" -m venv "$PREFIX/venv"
    "$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip
    "$PREFIX/venv/bin/python" -m pip install --quiet -r "$PREFIX/requirements-runtime.txt"

    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        echo "==> writing $CONFIG_DIR/config.json with a fresh pairing token"
        token=$("$PREFIX/venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))')
        cat > "$CONFIG_DIR/config.json" <<CONFIG
{
  "allowedOrigins": [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173"
  ],
  "token": "$token"
}
CONFIG
        # Readable only by root: the token is what separates the user's browser
        # from every other process running as that user, and a world-readable
        # copy would separate nothing.
        chmod 600 "$CONFIG_DIR/config.json"
        echo
        echo "    Pairing token (paste this into Inwire once, under Settings -> Driver Info):"
        echo
        echo "      $token"
        echo
    else
        echo "==> keeping the existing $CONFIG_DIR/config.json"
    fi

    if [ "$os" = macos ]; then
        install_launchd
    else
        install_systemd
    fi
}

install_systemd() {
    command -v systemctl >/dev/null 2>&1 || die "systemd is required on Linux; systemctl was not found."
    echo "==> registering the systemd unit"
    sed "s|@PREFIX@|$PREFIX|g; s|@LOG_DIR@|$LOG_DIR|g" \
        "$SOURCE_DIR/inwire-agent.service" > "$SERVICE_LINUX"
    systemctl daemon-reload
    systemctl enable --now inwire-agent.service
    echo "==> running. systemctl status inwire-agent"
}

install_launchd() {
    echo "==> registering the LaunchDaemon"
    sed "s|@PREFIX@|$PREFIX|g; s|@LOG_DIR@|$LOG_DIR|g" \
        "$SOURCE_DIR/com.inwire.agent.plist" > "$SERVICE_MACOS"
    chown root:wheel "$SERVICE_MACOS"
    chmod 644 "$SERVICE_MACOS"
    # bootout first so a reinstall replaces the running daemon rather than
    # failing with "service already loaded".
    launchctl bootout system "$SERVICE_MACOS" 2>/dev/null || true
    launchctl bootstrap system "$SERVICE_MACOS"
    echo "==> running. sudo launchctl print system/com.inwire.agent"
    echo
    echo "    macOS may ask you to allow the agent to monitor network traffic."
}

uninstall_agent() {
    os=$1
    echo "==> removing $APP_NAME"
    if [ "$os" = macos ]; then
        launchctl bootout system "$SERVICE_MACOS" 2>/dev/null || true
        rm -f "$SERVICE_MACOS"
    else
        systemctl disable --now inwire-agent.service 2>/dev/null || true
        rm -f "$SERVICE_LINUX"
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -rf "$PREFIX"
    rm -rf "$LOG_DIR"
    # The config is left behind deliberately, exactly as the Windows
    # uninstaller leaves it: it holds an origin allowlist somebody may have
    # edited and a token they may have pasted into a browser, and removing it
    # silently is not the uninstaller's call.
    echo "==> removed. $CONFIG_DIR was left in place; delete it if you are done with it."
}

os=$(detect_os)
case "${1:-install}" in
    install)
        require_root "$@"
        install_agent "$os"
        ;;
    uninstall)
        require_root "$@"
        uninstall_agent "$os"
        ;;
    *)
        die "usage: $0 [install|uninstall]"
        ;;
esac

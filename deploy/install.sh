#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONF_DIR="/etc/fload-balancer"
SYSTEMD_DIR="/etc/systemd/system"

usage() {
    echo "Usage: $0 {install|uninstall}"
    exit 1
}

do_install() {
    echo "==> Installing fload-balancer"

    # Build if binaries don't exist
    if [[ ! -f bin/lbserver || ! -f bin/lbctl ]]; then
        echo "    Building binaries..."
        make generate build
    fi

    echo "    Copying binaries to ${PREFIX}/bin/"
    install -Dm755 bin/lbserver "${PREFIX}/bin/lbserver"
    install -Dm755 bin/lbctl   "${PREFIX}/bin/lbctl"

    echo "    Installing config to ${CONF_DIR}/"
    install -dm755 "${CONF_DIR}"
    if [[ ! -f "${CONF_DIR}/config.yaml" ]]; then
        install -Dm644 config.example.yaml "${CONF_DIR}/config.yaml"
        echo "    Installed example config — edit ${CONF_DIR}/config.yaml before starting."
    else
        echo "    Config already exists, skipping (example at config.example.yaml)."
    fi

    echo "    Installing systemd unit"
    install -Dm644 deploy/fload-balancer.service "${SYSTEMD_DIR}/fload-balancer.service"
    systemctl daemon-reload

    echo ""
    echo "==> Installed. Next steps:"
    echo "    1. Edit ${CONF_DIR}/config.yaml"
    echo "    2. sudo systemctl enable --now fload-balancer"
    echo "    3. sudo journalctl -u fload-balancer -f"
}

do_uninstall() {
    echo "==> Uninstalling fload-balancer"

    echo "    Stopping service"
    systemctl stop fload-balancer 2>/dev/null || true
    systemctl disable fload-balancer 2>/dev/null || true

    echo "    Removing files"
    rm -f "${SYSTEMD_DIR}/fload-balancer.service"
    rm -f "${PREFIX}/bin/lbserver"
    rm -f "${PREFIX}/bin/lbctl"
    systemctl daemon-reload

    echo "    Config left in place at ${CONF_DIR}/"
    echo "==> Uninstalled."
}

case "${1:-}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *)         usage ;;
esac

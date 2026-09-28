#!/usr/bin/env python3
"""
ARP Detection System - Web Console Launcher
Start the web dashboard on http://localhost:5000
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from arp_detection_system.web.app import app, socketio

if __name__ == "__main__":
    print()
    print("  ============================================")
    print("    ARP Detection System - Web Console")
    print("  ============================================")
    print()
    print("  Dashboard:   http://localhost:5000")
    print("  Monitor:     http://localhost:5000/monitor")
    print("  Servers:     http://localhost:5000/servers")
    print("  Detection:   http://localhost:5000/detect")
    print("  Remediate:   http://localhost:5000/remediate")
    print("  Settings:    http://localhost:5000/settings")
    print()
    print("  Press Ctrl+C to stop")
    print()

    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)

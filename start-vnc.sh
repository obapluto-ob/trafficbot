#!/usr/bin/env bash
# Start the full VNC stack (Xvfb + x11vnc + websockify)
# Run this once before `npm start` if the VNC screen share stops working.

pkill -f "Xvfb :1" 2>/dev/null
pkill x11vnc 2>/dev/null
pkill -f "websockify.*5999" 2>/dev/null
sleep 1

Xvfb :1 -screen 0 1280x800x24 &
sleep 1

# Unset WAYLAND_DISPLAY so x11vnc uses Xvfb, not the Wayland compositor
unset WAYLAND_DISPLAY
x11vnc -display :1 -nopw -listen localhost -forever -shared -bg -o /tmp/x11vnc.log
sleep 1

websockify --daemon --web=/usr/share/novnc 5999 localhost:5900
echo "VNC stack running — open /vnc to watch"

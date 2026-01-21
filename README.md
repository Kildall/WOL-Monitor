# Wake-on-LAN Packet Monitor

A simple desktop application that monitors and displays incoming Wake-on-LAN (WOL) magic packets on your network.

## What is Wake-on-LAN?

Wake-on-LAN is a networking standard that allows computers to be turned on or "woken up" from a low-power state (like sleep or hibernation) by sending a special network packet called a "magic packet."

## How It Works

The application listens for UDP packets on a configurable network port (default: port 9, which is the standard port for WOL). When it receives a packet, it checks if the data matches the Wake-on-LAN magic packet format:

1. **Magic Header**: 6 bytes of 0xFF (255 in decimal)
2. **Target MAC Address**: The MAC address of the computer to wake up, repeated 16 times
3. **Optional Password**: Some systems support a 4 or 6-byte password

The minimum packet size is 102 bytes, but packets can be larger and the magic pattern can appear anywhere within the data.

## Features

- **Real-time Monitoring**: Continuously listens for WOL packets and displays them as they arrive
- **Packet Validation**: Distinguishes between valid WOL packets and other network traffic
- **Source Information**: Shows the IP address and port of the sender
- **Target MAC Address**: Extracts and displays the target computer's MAC address from valid packets
- **Statistics**: Tracks total packets, valid WOL packets, and invalid packets
- **Debug Mode**: Optional hex dump view for troubleshooting
- **Configurable Port**: Change the listening port if needed (standard is port 9)
- **Clean Interface**: Simple GUI with packet log and statistics

## Usage

1. Run the application (`wol_monitor.py` or the compiled executable)
2. Click "Start Monitoring" to begin listening
3. The application will show incoming packets in real-time
4. Use "Clear Log" to reset the display and statistics
5. Click "Stop Monitoring" to stop listening

## Building

The project includes a PyInstaller spec file for creating a standalone executable:

```bash
pyinstaller --onefile --windowed --name "WOL Monitor" --icon=NONE wol_monitor.py
```

The executable will be created in the `dist/` folder.

## Requirements

- Python 3.11+
- tkinter (usually included with Python)
- PyInstaller (for building standalone executable)

## Technical Details

- Uses UDP sockets to listen for broadcast packets
- Can receive packets up to 2048 bytes
- Runs in a separate thread to keep the GUI responsive
- Supports both IPv4 broadcast and unicast WOL packets
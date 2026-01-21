#!/usr/bin/env python3
"""
Wake-on-LAN Packet Monitor

A GUI application that monitors incoming Wake-on-LAN magic packets on a network port.
WOL packets are used to wake computers from sleep/standby mode remotely.

How it works:
- Listens for UDP packets on a configurable port (default: 9, the standard WOL port)
- Validates incoming data against the WOL magic packet format
- Displays packet details including source IP, timestamp, and target MAC address
- Provides real-time statistics and optional hex dump for debugging
"""

import socket
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Constants
DEFAULT_WOL_PORT = 9
WOL_MAGIC_HEADER = b'\xFF' * 6  # 6 bytes of 0xFF
WOL_MAC_REPETITIONS = 16  # MAC address repeated 16 times
WOL_MIN_SIZE = 102  # Minimum packet size (6 + 16*6 bytes)
MAX_UDP_PAYLOAD = 2048  # Maximum UDP packet size to receive
SOCKET_TIMEOUT = 1.0  # Socket timeout in seconds for responsiveness
HEX_DUMP_MAX_BYTES = 128  # Max bytes to show in hex dump


class WOLMonitor:
    """Main application class for monitoring Wake-on-LAN packets."""

    def __init__(self):
        self.sock = None
        self.listening = False
        self.listen_thread = None

        # Packet statistics
        self.total_packets = 0
        self.valid_packets = 0
        self.invalid_packets = 0

        # Setup GUI
        self.setup_gui()

    def setup_gui(self):
        """Setup the main GUI window."""
        self.root = tk.Tk()
        self.root.title("Wake-on-LAN Packet Monitor")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Port configuration section
        port_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="5")
        port_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(port_frame, text="Listen Port:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.port_var = tk.StringVar(value=str(DEFAULT_WOL_PORT))
        self.port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # Start/Stop buttons
        self.start_button = ttk.Button(port_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=2, padx=(10, 5))

        self.stop_button = ttk.Button(port_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=(0, 10))

        # Clear button
        self.clear_button = ttk.Button(port_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.grid(row=0, column=4)

        # Debug mode checkbox
        self.debug_var = tk.BooleanVar(value=False)
        self.debug_checkbox = ttk.Checkbutton(port_frame, text="Show Hex Dump", variable=self.debug_var)
        self.debug_checkbox.grid(row=0, column=5, padx=(10, 0))

        # Status label
        self.status_var = tk.StringVar(value="Not listening")
        self.status_label = ttk.Label(port_frame, textvariable=self.status_var, foreground="red")
        self.status_label.grid(row=1, column=0, columnspan=5, sticky=tk.W, pady=(5, 0))

        # Packet display section
        display_frame = ttk.LabelFrame(main_frame, text="WOL Packets", padding="5")
        display_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)

        # Create scrolled text widget for packet log
        self.log_text = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD, height=25)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Packet statistics section
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        self.total_packets_var = tk.StringVar(value="Total Packets: 0")
        ttk.Label(stats_frame, textvariable=self.total_packets_var).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))

        self.valid_packets_var = tk.StringVar(value="Valid WOL: 0")
        ttk.Label(stats_frame, textvariable=self.valid_packets_var).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))

        self.invalid_packets_var = tk.StringVar(value="Invalid: 0")
        ttk.Label(stats_frame, textvariable=self.invalid_packets_var).grid(row=0, column=2, sticky=tk.W)

        # Set up keyboard shortcuts
        self.root.bind('<Control-c>', lambda e: self.root.quit())
        self.root.bind('<Control-q>', lambda e: self.root.quit())

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def validate_port(self, port_str):
        """Validate port number."""
        try:
            port = int(port_str)
            return 1 <= port <= 65535
        except ValueError:
            return False

    def is_wol_packet(self, data):
        """
        Check if the received data is a valid WOL magic packet.

        WOL magic packet format:
        - 6 bytes of 0xFF (magic header)
        - 16 repetitions of the target MAC address (6 bytes each = 96 bytes)
        - Optional: 4 or 6 byte password
        - Minimum: 102 bytes, can be embedded within larger packets
        """
        if len(data) < WOL_MIN_SIZE:
            return False, None

        # Search for the magic header in the packet
        offset = 0
        while True:
            offset = data.find(WOL_MAGIC_HEADER, offset)
            if offset == -1:
                return False, None

            # Check if we have enough data after the magic header
            if offset + WOL_MIN_SIZE > len(data):
                offset += 1
                continue

            # Extract potential MAC address (first 6 bytes after magic header)
            mac_bytes = data[offset + len(WOL_MAGIC_HEADER):offset + len(WOL_MAGIC_HEADER) + 6]

            # Verify that the MAC is repeated 16 times
            is_valid = True
            for i in range(WOL_MAC_REPETITIONS):
                start = offset + 6 + (i * 6)
                if data[start:start + 6] != mac_bytes:
                    is_valid = False
                    break
            
            if is_valid:
                # Convert MAC bytes to readable format
                mac_address = ':'.join(f'{b:02X}' for b in mac_bytes)
                return True, mac_address
            
            offset += 1

        return False, None

    def format_hex_dump(self, data, max_bytes=HEX_DUMP_MAX_BYTES):
        """Format binary data as a hex dump for debugging."""
        result = []
        data_to_show = data[:max_bytes]
        for i in range(0, len(data_to_show), 16):
            chunk = data_to_show[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(f"    {i:04X}: {hex_part:<48} {ascii_part}")
        if len(data) > max_bytes:
            result.append(f"    ... ({len(data) - max_bytes} more bytes)")
        return '\n'.join(result)

    def log_packet(self, timestamp, source_ip, source_port, data_length, is_valid, mac_address=None, raw_data=None):
        """Log a packet to the GUI."""
        time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        if is_valid:
            status = "VALID WOL"
            color = "green"
            mac_info = f" | Target MAC: {mac_address}"
        else:
            status = "INVALID"
            color = "red"
            mac_info = ""

        log_entry = f"[{time_str}] {status} | From: {source_ip}:{source_port} | Size: {data_length} bytes{mac_info}\n"
        
        # Add hex dump if debug mode is enabled
        if self.debug_var.get() and raw_data:
            log_entry += self.format_hex_dump(raw_data) + "\n"

        # Add to log with color
        self.log_text.insert(tk.END, log_entry)

        # Color the text
        start_idx = self.log_text.index("end-1c linestart")
        end_idx = self.log_text.index("end-1c")
        self.log_text.tag_add(status.lower(), start_idx, end_idx)
        self.log_text.tag_config("valid wol", foreground="green")
        self.log_text.tag_config("invalid", foreground="red")

        # Auto scroll to bottom
        self.log_text.see(tk.END)

        # Update counters
        self.total_packets += 1
        if is_valid:
            self.valid_packets += 1
        else:
            self.invalid_packets += 1

        self.update_statistics()

    def update_statistics(self):
        """Update the statistics display."""
        self.total_packets_var.set(f"Total Packets: {self.total_packets}")
        self.valid_packets_var.set(f"Valid WOL: {self.valid_packets}")
        self.invalid_packets_var.set(f"Invalid: {self.invalid_packets}")

    def listen_for_packets(self, port):
        """Listen for incoming UDP packets."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', port))
            self.sock.settimeout(SOCKET_TIMEOUT)  # Timeout for responsiveness

            self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Started listening on port {port}\n")
            self.log_text.see(tk.END)

            while self.listening:
                try:
                    data, addr = self.sock.recvfrom(MAX_UDP_PAYLOAD)
                    timestamp = datetime.now()
                    source_ip, source_port = addr

                    # Check if it's a WOL packet
                    is_valid, mac_address = self.is_wol_packet(data)

                    # Log the packet
                    self.log_packet(timestamp, source_ip, source_port, len(data), is_valid, mac_address, data)

                except socket.timeout:
                    # Timeout is expected, just continue
                    continue
                except OSError:
                    # Socket was closed
                    break

        except Exception as e:
            error_msg = f"Error listening on port {port}: {str(e)}"
            self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {error_msg}\n")
            self.log_text.see(tk.END)
            messagebox.showerror("Error", error_msg)

        finally:
            if self.sock:
                self.sock.close()
                self.sock = None

    def start_monitoring(self):
        """Start monitoring for WOL packets."""
        if self.listening:
            return

        port_str = self.port_var.get().strip()
        if not self.validate_port(port_str):
            messagebox.showerror("Invalid Port", "Please enter a valid port number (1-65535)")
            return

        port = int(port_str)

        try:
            self.listening = True
            self.listen_thread = threading.Thread(target=self.listen_for_packets, args=(port,), daemon=True)
            self.listen_thread.start()

            # Update GUI
            self.status_var.set(f"Listening on port {port}")
            self.status_label.config(foreground="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
            self.listening = False

    def stop_monitoring(self):
        """Stop monitoring for WOL packets."""
        if not self.listening:
            return

        self.listening = False

        # Wait for thread to finish
        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join(timeout=2.0)

        # Close socket if still open
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

        # Update GUI
        self.status_var.set("Not listening")
        self.status_label.config(foreground="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.NORMAL)

        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Stopped listening\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        """Clear the packet log."""
        self.log_text.delete(1.0, tk.END)
        self.total_packets = 0
        self.valid_packets = 0
        self.invalid_packets = 0
        self.update_statistics()

    def on_closing(self):
        """Handle window close event."""
        self.stop_monitoring()
        self.root.quit()

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point."""
    try:
        app = WOLMonitor()
        app.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
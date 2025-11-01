import psutil
import socket
import json
import asyncio
import win32evtlog
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static, Input
from textual.containers import Vertical, Horizontal
from textual.screen import Screen

EVENT_IDS = [4624, 4625, 4634, 4647, 4648, 4672, 4662, 4741, 4742, 5136, 4688, 4105, 4698]

# Main Menu
class MenuScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("  MiniSOC Dashboard", classes="title")
        yield Vertical(
            Button("  Connections", id="connections"),
            Button("  Event Monitor", id="events"),
            Button("  Processes", id="processes"),
            Button("  SIEM Ingest", id="siem"),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "connections":
                self.app.push_screen(ConnectionsScreen())
            case "events":
                self.app.push_screen(EventMonitorScreen())
            case "processes":
                self.app.push_screen(ProcessScreen())
            case "siem":
                self.app.push_screen(SIEMScreen())

# Connections View
class ConnectionsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        self.output = Static(" Active Network Connections\n", expand=True)
        yield self.output
        yield Button(" Back", id="back")
        yield Footer()

    async def on_mount(self) -> None:
        self.running = True
        asyncio.create_task(self.update_connections())

    async def update_connections(self):
        while self.running:
            lines = ["🔌 Active Network Connections\n"]
            for conn in psutil.net_connections(kind='inet')[:30]:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                lines.append(f"{conn.status} | {laddr} → {raddr}")
            self.output.update("\n".join(lines))
            await asyncio.sleep(5)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.running = False
            self.app.pop_screen()

# Event Monitor View
class EventMonitorScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        self.output = Static(" Event ID Monitor\n", expand=True)
        yield self.output
        yield Button(" Back", id="back")
        yield Footer()

    async def on_mount(self) -> None:
        self.running = True
        asyncio.create_task(self.monitor_events())

    async def monitor_events(self):
        while self.running:
            lines = ["📜 Event ID Monitor\n"]
            try:
                log_handle = win32evtlog.OpenEventLog(None, "Application")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                for event in events:
                    if event.EventID in EVENT_IDS:
                        lines.append(f"ID {event.EventID} | {event.SourceName} | {event.TimeGenerated}")
                win32evtlog.CloseEventLog(log_handle)
            except Exception as e:
                lines.append(f"Error: {e}")
            self.output.update("\n".join(lines))
            await asyncio.sleep(10)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.running = False
            self.app.pop_screen()

# Process Monitor View
class ProcessScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        self.output = Static(" Running Processes\n", expand=True)
        yield self.output
        yield Button(" Back", id="back")
        yield Footer()

    async def on_mount(self) -> None:
        self.running = True
        asyncio.create_task(self.monitor_processes())

    async def monitor_processes(self):
        while self.running:
            lines = [" Running Processes\n"]
            for proc in psutil.process_iter(['name']):
                lines.append(f" {proc.info['name']}")
            self.output.update("\n".join(lines))
            await asyncio.sleep(5)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.running = False
            self.app.pop_screen()

# SIEM Ingest View
class SIEMScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("📡 SIEM Ingestion")
        yield Horizontal(
            Input(placeholder="Host IP", id="host"),
            Input(placeholder="Port", id="port")
        )
        self.output = Static("Waiting to start ingestion...", expand=True)
        yield self.output
        yield Button(" Start Ingest", id="start")
        yield Button(" Back", id="back")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            host = self.query_one("#host", Input).value
            port = self.query_one("#port", Input).value
            if host and port.isdigit():
                asyncio.create_task(self.send_siem_data(host, int(port)))
        elif event.button.id == "back":
            self.app.pop_screen()

    async def send_siem_data(self, host: str, port: int):
        self.output.update("Starting SIEM ingestion...")
        try:
            while True:
                payload = json.dumps(self.collect_data())
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(payload.encode('utf-8'), (host, port))
                self.output.update(" SIEM data sent.")
                await asyncio.sleep(5)
        except Exception as e:
            self.output.update(f" Failed: {e}")

    def collect_data(self):
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            connections.append({
                "type": conn.type,
                "status": conn.status,
                "local_address": laddr,
                "remote_address": raddr
            })

        events = []
        try:
            log_handle = win32evtlog.OpenEventLog(None, "Application")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            for event in raw_events:
                if event.EventID in EVENT_IDS:
                    events.append({
                        "event_id": event.EventID,
                        "source": event.SourceName,
                        "time": str(event.TimeGenerated)
                    })
            win32evtlog.CloseEventLog(log_handle)
        except Exception as e:
            events.append({"error": str(e)})

        return {"connections": connections, "events": events}

# App Entry Point
class MiniSOCApp(App):
    CSS_PATH = None
    BINDINGS = [("q", "quit", "Quit")]

    def on_mount(self) -> None:
        self.push_screen(MenuScreen())

if __name__ == "__main__":
    MiniSOCApp().run()

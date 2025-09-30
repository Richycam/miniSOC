import psutil
import time
import os
import win32evtlog  # Requires pywin32
import socket
import json

# Event IDs to monitor
event_id_array = [4624, 4625, 4634, 4647, 4648, 4672, 4662, 4741, 4742, 5136, 4688, 4105, 4698]


class Data:
    @staticmethod
    def json_all():
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
            while raw_events:
                for event in raw_events:
                    if event.EventID in event_id_array:
                        events.append({
                            "event_id": event.EventID,
                            "source": event.SourceName,
                            "time": str(event.TimeGenerated)
                        })
            win32evtlog.CloseEventLog(log_handle)
        except Exception as e:
            events.append({"error": str(e)})

        return {
            "connections": connections,
            "events": events
        }

# Menu display
menu_main = """
################################################################################################

            .   , , .  . ,  ,-.   ,-.   ,-.                  
            |\\ /| | |\\ | | (   ` /   \\ /   
            | V | | | \\| |  `-.  |   | |   
            |   | | |  | | .   ) \\   / \\   
            '   ' ' '  ' '  `-'   `-'   `-'                                             
                                1.0.0                  

1.          Connections
2.          Event ID Monitor
3.          Processes 
4.          SIEM Ingest 

################################################################################################
"""

# Terminal clear
def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")



# Case 1: Network connections
class One:
    @staticmethod
    def get_all_connections():
        connections = psutil.net_connections(kind='inet')
        try:
            for conn in connections:
                while connections:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    print(f"Type: {conn.type}, Status: {conn.status}, Local: {laddr}, Remote: {raddr}")
        except KeyboardInterrupt:
            print("\n Monitoring stopped.")




# Case 2: Event log monitor
class Two:
    @staticmethod
    def monitor_event_logs(server=None, log_type="Application"):
        print(f"Monitoring {log_type} logs... Press Ctrl+C to stop.")
        try:
            while True:
                log_handle = win32evtlog.OpenEventLog(server, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                while events:
                    for event in events:
                        if event.EventID in event_id_array:
                            print(f" Event ID: {event.EventID}, Source: {event.SourceName}, Time: {event.TimeGenerated}")
                win32evtlog.CloseEventLog(log_handle)
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n Monitoring stopped.")
        except Exception as e:
            print(f"Error: {e}")




# Case 3: Process list
class Three:
    def list_processes():
        try:
            while True:
                process_list = [proc.name() for proc in psutil.process_iter()]
                for process_name in process_list:
                    print(f" Process: {process_name}")
                time.sleep(5)  # Optional delay between refreshes
        except KeyboardInterrupt:
            print(" Process monitoring stopped.")


# Case 4: SIEM ingestion


class Connection:
    @staticmethod
    def send_json_udp(host: str, port: int):
        try:
            json_payload = json.dumps(Data.json_all())
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(json_payload.encode('utf-8'), (host, port))
                print(" SIEM data sent.")
        except Exception as e:
            print(f" Failed to send SIEM data: {e}")



class Four:
    @staticmethod
    def siem_inter():
        host = input("Host IP for SIEM: ")
        port = int(input("Port to send to: "))
        print("Press Ctrl+C to stop sending data.\n")
        try:
            while True:
                Connection.send_json_udp(host, port)
                time.sleep(5)
        except KeyboardInterrupt:
            print(" SIEM ingestion stopped.")




# Main loop
def main():
    choice = input("minisoc > ")
    match choice:
        case "1":
            One.get_all_connections()
        case "2":
            Two.monitor_event_logs()
        case "3":
            Three.list_processes()
        case "4":
            Four.siem_inter()

# Runtime loop
while True:
    print(menu_main)
    main()
    clear_terminal()


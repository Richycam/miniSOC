#                                   minisoc 




#                                   Imports

import psutil
import time
import os 
import win32evtlog #needs pywin32
import pprint

#                                Aux data (arrays etc)


event_id_arry = [4624,4625,4634,4647,4648,4672,4662,4741,4742,5136,4688,4105,4698]

# 4624 - Successful logon
# 4625 - Failed logon
# 4634 - Logoff
# 4647 - User initiated logoff
# 4648 - Explicit credential logon
# 4672 - Special privileges assigned

# 4662 - An operation was performed on an object
# 4741 - A computer account was created
# 4742 - A computer account was changed
# 4743 - A computer account was deleted
# 5136 - A directory service object was modified
# 4688 - Process creation
# 4105 - Command start
# 4698 - Scheduled task creation

   
#                          Consts/classes


class menu:
    def __init__(self,main):
        self.main = main

class Notes:
    def __init__(self,all_notes):
        self.all_notes = all_notes
       
       
       
Notes.all_notes = []

menu.main = """

################################################################################################

                .   , , .  . ,  ,-.   ,-.   ,-.                 
                |\ /| | |\ | | (   ` /   \ /   
                | V | | | \| |  `-.  |   | |   
                |   | | |  | | .   ) \   / \   
                '   ' ' '  ' '  `-'   `-'   `-'                                             
                                        1.0.0                  


1.          Connections
2.          Event id monitor
3.          Processes 



################################################################################################

"""



#                                    FUNCTIONS



##################                  CASE 1            ##########################

def get_all_connections():
    connections = psutil.net_connections(kind='inet')  # 'inet' includes IPv4 and IPv6
    for conn in connections:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        print(f"Type: {conn.type}, Status: {conn.status}, Local Address: {laddr}, Remote Address: {raddr}")
    
##################                  CASE 2             ##########################
def monitor_event_logs(server=None, log_type="Application"):
    print(f"Monitoring {log_type} logs...")
    while True:
        try:
            # Open the event log
            log_handle = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if events:
                for event in events:
                    print(f"Event ID: {event.EventID}, Source: {event.SourceName}, Time: {event.TimeGenerated}")
            
            if event.EventID == event_id_arry:   # event id array checks
                print("WARNING EVENT")

            # Close the log handle
            win32evtlog.CloseEventLog(log_handle)
            
            # Wait before checking again
            time.sleep(5)
        except KeyboardInterrupt:
            print("Monitoring stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

##################                  CASE 3           ##########################

def prccess():
    processlist=list()
    for process in psutil.process_iter():
        processlist.append(process.name())
    pprint.pprint(processlist)



##################         clear function           ########################### 

def clear():
  "cls" if os.name == "nt" else "clear"


#                       Match case (input as string)
def main():
    start = input("minisoc > ")

    match start:
        case"1":
            get_all_connections()   # connections 
            clear()
        case"2":
            monitor_event_logs()   # event id logs
            clear()
        case"3":
            prccess()               # process list 


#                            MAIN LOOP

runtime = True

while runtime:
    print(menu.main)
    main()


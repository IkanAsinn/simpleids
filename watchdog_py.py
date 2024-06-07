from time import ctime
from os import path, makedirs
from configuration import get_value

from threading import Lock
from threading import Event
from yara_py import Yara_Py

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

YARA_SKENER = None
LOG_PATH = ""

class Watchdog_Py:
    def __init__(self, watchdog_active: Event) -> None:
        global YARA_SKENER

        YARA_SKENER = Yara_Py(get_value("YARA_RULES_FOR_WATCHDOG_PATH"), get_value("YARA_LOGS_FOR_WATCHDOG_PATH"), 'Watchdog')

        self.observer = Observer()
        self.event_handler = Handler()

        self.watchdog_active = watchdog_active
        self.watchdog_path = ""
        self.logs_path = ""

        self.set_watchdog_path(get_value("WATCHDOGDIR_PATH"))
        self.set_logs_path(get_value("WATCHDOG_LOGS_PATH"))

    def set_watchdog_path (self, watchdog_path) -> None:
        self.watchdog_path = watchdog_path

    def set_logs_path(self, logs_path) -> None:
        global LOG_PATH
        LOG_PATH = logs_path

        self.logs_path = logs_path
        self.check_and_create_paths(logs_path)

    def check_and_create_paths(self, file_path) -> None:
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def check_configurations(self) -> None:
        if get_value("WATCHDOGDIR_PATH") != self.watchdog_path:
            self.set_watchdog_path(get_value("WATCHDOGDIR_PATH"))
        
        if get_value("WATCHDOG_LOGS_PATH") != self.logs_path:
            self.set_logs_path(get_value("WATCHDOG_LOGS_PATH"))
        
        if get_value("YARA_RULES_FOR_WATCHDOG_PATH") != YARA_SKENER.yara_rules_path:
            YARA_SKENER.set_yara_rules_path(get_value("YARA_RULES_FOR_WATCHDOG_PATH"))

        if get_value("YARA_LOGS_FOR_WATCHDOG_PATH") != YARA_SKENER.logs_path:
            YARA_SKENER.set_yara_logs_path(get_value("YARA_LOGS_FOR_WATCHDOG_PATH"))

    def start_watchdog(self) -> None:
        self.check_configurations()
        self.watchdog_active.set()
        self.observer.schedule(self.event_handler, self.watchdog_path, recursive=True)
        self.observer.start()
        
    def stop_watchdog(self) -> None:
        if not self.watchdog_active.is_set():
            return
        
        self.watchdog_active.clear()
        self.observer.stop()

        # check if the observer is still running
        if self.observer.is_alive():
            print("Waiting for the watchdog to stop...")
            self.observer.join()

        del self.observer
        self.observer = Observer()
        

    def is_watchdog_active(self) -> bool:
        return self.watchdog_active.is_set()

class Handler(FileSystemEventHandler):
    global YARA_SKENER
    global LOG_PATH

    lock = Lock()
    
    @staticmethod
    def on_any_event(event) -> None:
        '''
        This method is called when an event is detected by the observer.
        The file will be scanned by the Yara_Py object when and only when the file is created.
        The modified or deleted files will not be scanned.
        After the scanning process, the file path will be written to the logs.
        '''
        with Handler.lock:
            if event.is_directory:
                return None
            elif event.event_type == 'created':
                with open(LOG_PATH, 'a') as logs:
                    logs.write(f"{ctime()} - {event.src_path} Created\n")
                YARA_SKENER.set_file_path(event.src_path)
                YARA_SKENER.scan()
import yara
import os
import time
from os import path, makedirs
from colorama import Fore, Style
from configuration import set_value, get_value

class Yara_Py:
    def __init__ (self, yara_rules_path='./libs/yara-rules.yar', logs_path='./new_logs/yara_logs.log', process=''):
        self.yara_rules_path = ""
        self.file_path = ""
        self.rules = None
        self.logs_path = ""
        self.process=process

        yara.set_config(max_strings_per_rule=1000000, stack_size=99999999)
        self.set_yara_rules_path(yara_rules_path)
        self.set_yara_logs_path(logs_path)

    def set_yara_rules_path(self, yara_rules_path):
        self.yara_rules_path = yara_rules_path
        self.set_rules()

    def set_yara_logs_path(self, logs_path):
        self.logs_path = logs_path
        self.check_and_create_paths(logs_path)

    def check_and_create_paths(self, file_path):
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def set_file_path(self, file_path):
        self.file_path = file_path

    def set_rules(self):
        timeout = 60  # Adjust as needed
        compiling = False

        start_time = time.time()

        while True:
            try:
                # Compile YARA rules with error_on_warning=True
                if compiling == False:
                    self.rules = yara.compile(filepath=self.yara_rules_path)
                    compiling = True
                if self.rules is not None:
                    print(f"{Fore.GREEN}{Style.BRIGHT}YARA rules for {self.process} compiled successfully.{Style.RESET_ALL}")
                    break  # Exit loop if compilation is successful
                else:
                    print(Fore.YELLOW + Style.BRIGHT + "YARA rules still compiled with warnings. Retrying..." + Style.RESET_ALL)
                
            except yara.Error as e:
                print(f"{Fore.RED}{Style.BRIGHT}Terjadi kesalahan dalam aturan YARA untuk {self.process}: {e}{Style.RESET_ALL}")
                print("apakah ingin mengatur ulang lokasi file yara rules? (y/n): ", end="")
                answer = input()
                if answer == "y":
                    print("Masukkan alamat file aturan YARA: ", end="")
                    self.yara_rules_path = input()
                    self.set_rules()
                    print(Fore.GREEN + Style.BRIGHT + "Lokasi file aturan YARA telah diatur ulang!" + Style.RESET_ALL)
                    input("Press enter to continue...")
                    if self.process == "Watchdog":
                        set_value("YARA_RULES_FOR_WATCHDOG_PATH", self.yara_rules_path)
                    elif self.process == "Web App":
                        set_value("YARA_RULES_FOR_APPLICATION_PATH", self.yara_rules_path)
                else:
                    exit(1)
                
            # Check if timeout has been reached
            if time.time() - start_time >= timeout:
                print(Fore.RED + Style.BRIGHT + "Timeout reached. Failed to compile YARA rules within specified time." + Style.RESET_ALL)
                break  # Exit loop if timeout is reached
                
            # Wait before checking again
            time.sleep(1)  # Adjust sleep time as needed

    def scan(self, data):
        if os.path.isfile(self.file_path):
            try:
                if self.rules is not None:
                    matches = self.rules.match(self.file_path, timeout=3600)
                    with open(self.logs_path, 'a') as logs:
                        if matches:
                            logs.write(f"{time.ctime()} - {self.file_path} | {matches}\n")
                        else:
                            logs.write(f"{time.ctime()} - {self.file_path} | No Match\n")
                else:
                    print(Fore.RED + Style.BRIGHT + "Tidak ada aturan YARA yang ditemukan." + Style.RESET_ALL)
            except yara.Error as e:
                print(f"{Fore.RED}{Style.BRIGHT}Error saat memindai {self.file_path}: {e}{Style.RESET_ALL}")
        else:
            try:
                if data is not None and len(data) > 0:
                    for packet in data:
                        matches = self.rules.match(data=packet['Data'], timeout=3600)
                        with open(self.logs_path, 'a') as logs:
                            if matches:
                                logs.write(f"{time.ctime()} - From: {packet['IP Address']} | Match: {matches} | request: {packet['Data']}\n")
            except yara.Error as e:
                print(f"{Fore.RED}{Style.BRIGHT}Error saat memindai data paket: {e}{Style.RESET_ALL}")
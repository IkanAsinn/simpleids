from dotenv import set_key, get_key, find_dotenv, dotenv_values
from colorama import Fore, Style

def get_value(key) -> str:
    dotenv_path = check_file()
    return get_key(dotenv_path, key)

def set_value(key, value) -> None:
    dotenv_path = check_file()
    set_key(dotenv_path, key, value)
    
def get_all_values() -> dict:
    dotenv_path = check_file()
    return dotenv_values(dotenv_path)

def check_file() -> str:
    dotenv_path = find_dotenv()
    if dotenv_path == "":
        print(Fore.YELLOW + Style.BRIGHT + ".env file not found, generating default file (please re-configure based on your environment)" + Style.RESET_ALL)
        write_default_values()
        check_file()
    
    return dotenv_path

def write_default_values() -> None:
    with open(".env", "w") as file:
        file.write("YARA_RULES_FOR_APPLICATION_PATH='./libs/yara-app-rules.yar'\n")
        file.write("YARA_LOGS_FOR_APPLICATION_PATH='./new_logs/yara_logs_app.log'\n")
        file.write("YARA_RULES_FOR_WATCHDOG_PATH='./libs/yara-rules-full.yar'\n")
        file.write("YARA_LOGS_FOR_WATCHDOG_PATH='./new_logs/yara_logs_watchdog.log'\n")
        file.write("WATCHDOGDIR_PATH='./uploads'\n")
        file.write("WATCHDOG_LOGS_PATH='./new_logs/watchdog_logs.log'\n")
        file.write("PORT_SCAN_PCAP_DIR='./pcap/port_scan/'\n")
        file.write("PORT_SCAN_LOG_DIR='./logs/port_scan/'\n")
        file.write("PCAP_DIR='./pcap/'\n")
        file.write("LOG_DIR='./logs/'\n")
        file.write("# Please use ; delimiter for each ip to be excluded.\n")
        file.write("ADDITIONAL_EXCLUDED_IPS=''\n")
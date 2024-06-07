from colorama import Fore, Style
from configuration import get_all_values, set_value
from threading import Event
from sniffer import Sniffer
from watchdog_py import Watchdog_Py

class Menu:
    def __init__(self, sniffer: Sniffer,watchdog: Watchdog_Py, sniffing_active: Event, watchdog_active: Event) -> None:
        self.sniffer = sniffer
        self.watchdog = watchdog
        self.sniffing_active = sniffing_active
        self.watchdog_active = watchdog_active

    def print_menu(self, title, options) -> None:
        print("\033c")
        print(Fore.GREEN + Style.BRIGHT + f"=== {title} ===" + Style.RESET_ALL)
        for i, option in enumerate(options, start=1):
            if i == 1:
                if self.sniffer.is_sniffing_active():
                    checkmark_color = Fore.GREEN
                    checkmark = "\u2713"
                else:
                    checkmark_color = Fore.RED
                    checkmark = "X"

            elif i == 2:
                if self.watchdog.is_watchdog_active():
                    checkmark_color = Fore.GREEN
                    checkmark = "\u2713"
                else:
                    checkmark_color = Fore.RED
                    checkmark = "X"
            else:
                checkmark_color = ""
                checkmark = ""
            print(f"{Fore.YELLOW}{i}. {option}{checkmark_color} {checkmark}{Style.RESET_ALL}")
        
    def get_user_choice(self, length) -> int:
        try:
            while True:
                try:
                    choice = int(input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL))
                    if 1 <= choice <= length:
                        return choice
                    else:
                        print(Fore.RED + "Invalid choice. Please enter a valid option." + Style.RESET_ALL)
                except ValueError:
                    print(Fore.RED + "Invalid input. Please enter a number." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print(f"{Fore.RED}\n\nKeyboard Interrupt Detected!{Style.RESET_ALL}")
            raise SystemExit
        

    def main_menu(self) -> None:
        title = "System Control"
        options = ["Toggle Packet Sniffing", "Toggle Watchdog Scanning", "Configuration", "Exit"]

        try:
            while True:
                self.print_menu(title, options)
                choice = self.get_user_choice(len(options))
            
                if choice == 1:
                    if self.sniffer.is_sniffing_active():
                        self.sniffer.stop_sniffing()
                    else:
                        self.sniffer.start_sniffing()
                elif choice == 2:
                    print("You choose Option 2.")
                    if self.watchdog.is_watchdog_active():
                        self.watchdog.stop_watchdog()
                    else:
                        self.watchdog.start_watchdog()
                elif choice == 3:
                    self.show_config_menu()
                elif choice == 4:
                    self.sniffer.stop_sniffing()
                    print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                    break
        except KeyboardInterrupt:
            print(Fore.RED + Style.BRIGHT + "keyboard interrupt dari main_menu" + Style.RESET_ALL)
            exit(0)

    def show_config_menu(self) -> None:
        configs = get_all_values()

        print("\033c")
        print(f"{Fore.YELLOW}=== Configuration ==={Style.RESET_ALL}")
        for i, (key, value) in enumerate(configs.items(), start=1):
            print(f"{Fore.YELLOW}{i}. {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")

        print(f"{Fore.YELLOW}{len(configs) + 1}. Back")
        print(f"====================={Style.RESET_ALL}")

        choice = self.get_user_choice(len(configs) + 1)

        if 1 <= choice <= len(configs):
            key = list(configs.keys())[choice - 1]

            print(f"{Fore.YELLOW}Enter new value for {key} ('-' to back): {Style.RESET_ALL}", end="")
            new_value = input()

            if new_value != "-":
                if key == 'YARA_RULES_FOR_APPLICATION_PATH':
                    if self.sniffer.is_sniffing_active():
                        print(f"{Fore.RED}Please stop the packet sniffing before changing the value of {key}.{Style.RESET_ALL}")
                        input("Press Enter to continue...")
                        return
                    else:
                        set_value(key, new_value)
                        print(f"{Fore.LIGHTGREEN_EX}{key} has been updated to {new_value}.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Recompiling YARA rules...{Style.RESET_ALL}")
                        self.sniffer = Sniffer(self.sniffing_active)
            
                if key == 'YARA_RULES_FOR_WATCHDOG_PATH':
                    if self.watchdog.is_watchdog_active():
                        print(f"{Fore.RED}Please stop the watchdog scanning before changing the value of {key}.{Style.RESET_ALL}")
                        input("Press Enter to continue...")
                        return
                    else:
                        set_value(key, new_value)
                        print(f"{Fore.LIGHTGREEN_EX}{key} has been updated to {new_value}.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Recompiling YARA rules...{Style.RESET_ALL}")
                        self.watchdog = Watchdog_Py(self.watchdog_active)
                
                else:
                    set_value(key, new_value)
                    print(f"{Fore.LIGHTGREEN_EX}{key} has been updated to {new_value}.{Style.RESET_ALL}")
                
                input("Press Enter to continue...")
        elif choice == len(configs) + 1:
            return
        else:
            print(Fore.RED + Style.BRIGHT + "Invalid choice. Please enter a valid option." + Style.RESET_ALL)
            return
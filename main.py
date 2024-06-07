#!/usr/bin/python3

import argparse
from colorama import Fore, Style

from menu import Menu
from sniffer import Sniffer
from threading import Event
from multiprocessing import Event as MEvent
from watchdog_py import Watchdog_Py
from sys import exit
from os import geteuid, environ
from configuration import check_file

if __name__ == "__main__":
    try:
        sniffer = None
        if not environ.get('SUDO_UID') and geteuid != 0:
            raise PermissionError
        
        parser = argparse.ArgumentParser(description="A simple network sniffer and watchdog program.")
        parser.add_argument('--iface', type=str, help="The network interface to sniff on.", required=True)

        args = parser.parse_args()
        iface = args.iface

        check_file()

        # Event for signaling the shutdown of the program
        sniffing_active = MEvent()
        watchdog_active = Event()

        # Initialize the Sniffer and Watchdog
        sniffer = Sniffer(sniffing_active, iface)
        watchdog = Watchdog_Py(watchdog_active)

        # Start the main menu
        menu = Menu(sniffer, watchdog, sniffing_active, watchdog_active)
        input("Press enter to continue...")
        menu.main_menu()
    except ValueError:
        print("Value Error Occured")
        raise SystemExit
    except argparse.ArgumentError:
        print("Argument Error Occured")
        raise SystemExit
    except SystemExit:
        if sniffer is not None:
            print(Fore.RED + "\nExiting the program." + Style.RESET_ALL)
            if sniffer.is_sniffing_active():
                print(f"\n{Fore.RED}Sniffer still running, shutting down. Please wait...{Style.RESET_ALL}")
                sniffer.stop_sniffing()
            if watchdog.is_watchdog_active():
                print(f"\n{Fore.RED}Watchdog still running, shutting down. Please wait...{Style.RESET_ALL}")
                watchdog.stop_watchdog()
        exit(0)
    except PermissionError as e:
        print(Fore.RED + Style.BRIGHT + "Please run with sudo or as root!" + Style.RESET_ALL)
        exit(1)
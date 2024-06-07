import logging
import pyshark
import pyshark.config
import pyshark.tshark
import pyshark.tshark.tshark
import urllib

from time import sleep
from os import path, makedirs, listdir, system, remove

from scapy.all import *
from scapy.utils import PcapWriter

from yara_py import Yara_Py
from datetime import datetime
from collections import Counter
from threading import Event, Thread
from multiprocessing import Process
from configuration import get_value
from colorama import Fore, Style

class Sniffer:
    def __init__(self, sniffing_active: Event, iface: str) -> None:
        self.sniffing_active = sniffing_active

        self.pcap_path = ""
        self.log_path = ""
        self.temp_log_path = ""
        self.current_pcap_dir = ""
        self.root_pcap_dir = ""

        self.port_pcap_path = ""
        self.port_scan_log_path = ""
        self.temp_port_scan_log_path = ""
        self.current_port_pcap_dir = ""
        self.root_port_pcap_dir = ""

        self.iface = iface
        self.interfaces = get_if_list()
        self.all_interfaces_ip = []

        additional_excluded_ips = get_value("ADDITIONAL_EXCLUDED_IPS")
        if additional_excluded_ips:
            additional_excluded_ips = additional_excluded_ips.split(';')

        for interface in self.interfaces:
            self.all_interfaces_ip.append(get_if_addr(interface))

        for ip in additional_excluded_ips:
            if ip != "":
                self.all_interfaces_ip.append(ip)

        self.sniffing_thread = None
        self.port_sniffing_thread = None

        self.has_port_scan = False
            
        self.yara_skener = Yara_Py(get_value("YARA_RULES_FOR_APPLICATION_PATH"), get_value("YARA_LOGS_FOR_APPLICATION_PATH"), 'Web App')

        self.set_pcap_path(get_value("PCAP_DIR"))
        self.set_port_pcap_path(get_value("PORT_SCAN_PCAP_DIR"))
        self.set_log_path(get_value("LOG_DIR"))
        self.set_port_log_path(get_value("PORT_SCAN_LOG_DIR"))

    def set_log_path(self, log_dir) -> None:
        # log_dir = path.dirname(log_dir)
        log_dir = self.check_valid_dir_path(log_dir)
        log_path = log_dir + datetime.now().strftime("%Y-%m-%d") + ".log"
        self.log_path = log_path
        self.temp_log_path = log_dir + 'temporary_packets.log'
        self.check_and_create_paths(log_path)

    def set_port_log_path(self, log_dir) -> None:
        # log_dir = path.dirname(log_dir)
        log_dir = self.check_valid_dir_path(log_dir)
        log_path = log_dir + datetime.now().strftime("%Y-%m-%d") + ".log"
        self.port_scan_log_path = log_path
        self.temp_port_scan_log_path = log_dir + 'temporary_packets.log'
        self.check_and_create_paths(log_path)

    def set_pcap_path(self, pcap_dir) -> None:
        # pcap_dir = path.dirname(pcap_dir)
        pcap_dir = self.check_valid_dir_path(pcap_dir)
        
        self.root_pcap_dir = pcap_dir
        pcap_dir += datetime.now().strftime("%Y%m%d") + "/"
        pcap_path = pcap_dir + datetime.now().strftime("%H%M%S") + ".pcap"
        self.pcap_path = pcap_path
        self.current_pcap_dir = pcap_dir
        self.check_and_create_paths(pcap_dir)

    def set_port_pcap_path(self, pcap_dir) -> None:
        # pcap_dir = path.dirname(pcap_dir)
        pcap_dir = self.check_valid_dir_path(pcap_dir)
        pcap_dir += datetime.now().strftime("%Y%m%d") + "/"
        pcap_path = pcap_dir + datetime.now().strftime("%H%M%S") + ".pcap"
        self.port_pcap_path = pcap_path
        self.current_port_pcap_dir = pcap_dir
        self.check_and_create_paths(pcap_dir)

    def check_valid_dir_path(self, dir_path) -> str:
        if not dir_path.endswith("/"):
            dir_path += "/"
        return dir_path

    def check_and_create_paths(self, file_path) -> None:
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def check_configurations(self) -> None:
        if get_value("PCAP_DIR") != self.root_pcap_dir:
            self.set_pcap_path(get_value("PCAP_DIR"))

        if get_value("PORT_SCAN_PCAP_DIR") != self.root_port_pcap_dir:
            self.set_port_pcap_path(get_value("PORT_SCAN_PCAP_DIR"))
        
        if get_value("LOG_DIR") + datetime.now().strftime("%Y-%m-%d") + ".log" != self.log_path:
            self.set_log_path(get_value("LOG_DIR"))

        if get_value("PORT_SCAN_LOG_DIR") + datetime.now().strftime("%Y-%m-%d") + ".log" != self.port_scan_log_path:
            self.set_port_log_path(get_value("PORT_SCAN_LOG_DIR"))
        
        if get_value("YARA_RULES_FOR_APPLICATION_PATH") != self.yara_skener.yara_rules_path:
            self.yara_skener.set_yara_rules_path(get_value("YARA_RULES_FOR_APPLICATION_PATH"))

        if get_value("YARA_LOGS_FOR_APPLICATION_PATH") != self.yara_skener.logs_path:
            self.yara_skener.set_yara_logs_path(get_value("YARA_LOGS_FOR_APPLICATION_PATH"))

    def start_sniffing(self) -> None:
        self.check_configurations()
        self.sniffing_active.set()
        self.sniffing_thread = Process(target=self.sniff_packets)
        self.port_sniffing_thread = Process(target=self.scan_port_scanning)

        self.sniffing_thread.start()
        self.port_sniffing_thread.start()

    def stop_sniffing(self) -> None:
        self.sniffing_active.clear()
        if self.sniffing_thread and self.sniffing_thread.is_alive() and self.port_sniffing_thread.is_alive():
            print(Fore.YELLOW + "Waiting for the sniffing thread to stop..." + Style.RESET_ALL)
            self.sniffing_thread.join()
            self.port_sniffing_thread.join()
            while self.sniffing_thread.is_alive() or self.port_sniffing_thread.is_alive():
                pass
            self.sniffing_thread = None
            print(Fore.GREEN + "Sniffing thread stopped." + Style.RESET_ALL)

        merge_pcap_thread = Thread(target=self.merge_pcap_files)
        print(Fore.YELLOW + "Merging pcap files..." + Style.RESET_ALL)
        merge_pcap_thread.start()
        merge_pcap_thread.join()
        print(Fore.GREEN + "Pcap files merged." + Style.RESET_ALL)
        input("All activities have been stopped. Press Enter to continue...")
    
    def check_day_change(self) -> None:
        if self.current_pcap_dir != self.root_pcap_dir + datetime.now().strftime("%Y%m%d") + "/":
            merge_pcap_thread = Thread(target=self.merge_pcap_files)
            merge_pcap_thread.start()
            merge_pcap_thread.join()
            self.set_pcap_path(get_value("PCAP_DIR"))

        if self.current_port_pcap_dir != path.dirname(get_value("PORT_SCAN_PCAP_DIR")) + datetime.now().strftime("%Y-%m-%d") + "/":
            self.set_port_pcap_path(get_value("PORT_SCAN_PCAP_DIR"))
        
        if self.log_path != path.dirname(get_value("LOG_DIR")) + datetime.now().strftime("%Y-%m-%d") + ".log":
            self.set_log_path(get_value("LOG_DIR"))

        if self.port_scan_log_path != path.dirname(get_value("PORT_SCAN_LOG_DIR")) + datetime.now().strftime("%Y-%m-%d") + ".log":
            self.set_port_log_path(get_value("PORT_SCAN_LOG_DIR"))

    def packet_callback(self, packet) -> None:
        with open(self.temp_log_path, 'a') as temp_log:
            temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

    def write_packet_to_pcap(self, packet, path) -> None:
        pkt_dump = PcapWriter(path, append=True)
        pkt_dump.write(packet)
        pkt_dump.close()

    def merge_pcap_files(self) -> None:
        '''
        This method will merge all pcap files in the current pcap directory into a single pcap file using mergecap executables when the program stopped or on day change.
        The merged pcap file will be saved as 'merged.pcap'.
        '''
        pcap_files_path = path.abspath(self.current_pcap_dir)
        merge_files_path = pcap_files_path + "/merged.pcap"

        isMergeFileExists = False
        
        if path.exists(merge_files_path):
            system(f'mv {merge_files_path} {merge_files_path}.bak')
            isMergeFileExists = True

        pcap_files = listdir(self.current_pcap_dir)

        if len(pcap_files) > 1:
            pcap_files_string = ""
            for pcap_file in pcap_files:
                pcap_files_string += f"{pcap_files_path}/{pcap_file} "

            system(f'mergecap -w {merge_files_path} {pcap_files_string}')

            for pcap_file in pcap_files:
                remove(f'{pcap_files_path}/{pcap_file}')
        else:
            if isMergeFileExists:
                system(f'mv {merge_files_path}.bak {merge_files_path}')
                
    def sniff_packets(self) -> None:
        '''
        This method will sniff packets from all interfaces with 5 seconds interval.
        The packet result will be written into a pcap file and log file.
        After 5 seconds, the pcap file will be scanned for potential attacks.
        '''
        while True:
            # self.temp_log_path = path.dirname(self.log_path) + '/temporary_packets.log'
            if not path.exists(self.temp_log_path):
                with open(self.temp_log_path, 'w'):
                    pass
            
            # self.set_pcap_path(self.root_pcap_dir)
            self.check_day_change()
            # sniff(timeout=5, prn=self.packet_callback, store=0, iface=self.iface)
            sniff_packet = AsyncSniffer(iface=self.iface, prn=self.packet_callback)
            sniff_packet.start()
            sleep(5)
            sniff_packet.stop()
            result = sniff_packet.results
            
            if len(result) != 0:
                self.pcap_path = self.current_pcap_dir + datetime.now().strftime("%H%M%S") + ".pcap"
                pkt_dump = Thread(target=self.write_packet_to_pcap, args=(result, self.pcap_path))
                pkt_dump.start()
                pkt_dump.join()

                detect_attack_thread = Thread(target=self.detect_attacks, args=(self.pcap_path,))
                detect_attack_thread.start()
                detect_attack_thread.join()

            with open(self.temp_log_path, 'r') as temp_log:
                logs = temp_log.read()

            if logs:
                with open(self.log_path, 'a') as final_log:
                    final_log.write(logs)

                open(self.temp_log_path, 'w').close()
            if not self.sniffing_active.is_set():
                break
    def check_packet(self, packet, excluded_ip) -> bool:
        try:
            return 'IP' in packet and packet.ip.src not in excluded_ip
        except AttributeError:
            return False

    def detect_attacks(self, pcap_file: str) -> None:
        '''
        This method will detect potential DDoS attacks from the pcap file.
        It will also scan the pcap file for potential attacks using Yara rules.
        '''
        cap = pyshark.FileCapture(pcap_file)
        cap.set_debug(log_level=logging.ERROR)

        # Threshold for identifying DDoS traffic
        ddos_threshold = 1000

        src_ips = (packet.ip.src for packet in cap if self.check_packet(packet, self.all_interfaces_ip))
        source_ips_count = Counter(src_ips)
            
        # check for potential DDoS attacks
        for ip, count in source_ips_count.items():
            if count > ddos_threshold:
                log_path = path.dirname(self.port_scan_log_path) + f'/ddos-{datetime.now().strftime("%Y%m%d")}.log'
                if not path.exists(log_path):
                    with open(log_path, 'w'):
                        pass

                with open(log_path, 'a') as ddos_log:
                    ddos_log.write(f"{datetime.now()} - potential DDoS attack detected from {ip} with {count} packets\n")

        # create temporary pcap for yara scan
        http_requests = []
    
        for packet in cap:
            if 'HTTP' in packet:
                http_layer = packet.http
                host = http_layer.get_field_value('host')
                if host is not None:
                    method = http_layer.get_field_value('request_method')
                    path = http_layer.get_field_value('request_uri')
                    ip_address = http_layer.get_field_value('x-forwarded-for')
                    if method == 'POST':
                        payload = http_layer.get_field_value('file_data')
                        if payload is not None:
                            payload = payload.split(':')
                            payload = urllib.parse.unquote("".join([chr(int(byte, 16)) for byte in payload]))
                        else:
                            payload = ""
                    else:
                        try:
                            payload = urllib.parse.unquote(http_layer.get_field_value('request_uri_query'))
                        except Exception:
                            payload = http_layer.get_field_value('request_uri_query')
                            
                        if payload is None:
                            payload = ""
                    
                    http_data = {
                        'Method': method,
                        'Host': host,
                        'Path': path,
                        'IP Address': ip_address,
                        'Full URL': f"http://{host}{path}",
                        'Payload': payload
                    }
                    
                    http_requests.append(http_data)
                    # print(http_data)
        cap.close()

        filtered_requests = []
    
        for request in http_requests:
            data = request['Payload']
            filtered_requests.append({'Method': request['Method'], 'URL': request['Full URL'], 'Data': data, 'IP Address': request['IP Address']})

        self.yara_skener.scan(filtered_requests)

    def extract_http_fields(self, packet):
        http_fields = {}
        if 'HTTP' in packet:
            http_layer = packet['HTTP']
            for field in http_layer.field_names:
                http_fields[field] = http_layer.get(field, None)
        return http_fields

    def detect_port_scan_attacks(self, packet) -> None:
        '''
        This method will detect potential port scanning attacks from the packet.
        It will write the result into a temporary log file.
        If the packet tries to access any port than the default port, it will be considered as a potential port scanning attack.
        If there are any, dump the packet to pcap file.
        '''
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            if packet['TCP'].dport not in [80, 443] and (packet['IP'].src not in self.all_interfaces_ip and packet['IP'].dst in self.all_interfaces_ip):
                with open(self.temp_port_scan_log_path, 'a') as temp_log:
                    temp_log.write(f"{datetime.now()} - potential port scanning attack from {packet['IP'].src} to port {packet['TCP'].dport} (TCP)\n")

                self.has_port_scan = True

        if packet.haslayer('IP') and packet.haslayer('UDP'):
            if packet['UDP'].dport not in [53, 67, 68, 69, 123, 161, 162, 500, 514, 520] and (packet['IP'].src not in self.all_interfaces_ip and packet['IP'].dst in self.all_interfaces_ip):
                with open(self.temp_port_scan_log_path, 'a') as temp_log:
                    temp_log.write(f"{datetime.now()} - potential port scanning attack from {packet['IP'].src} to port {packet['UDP'].dport} (UDP)\n")

                self.has_port_scan = True

    def scan_port_scanning(self) -> None:
        '''
        This method will scan for potential port scanning attacks with new sniffer.
        '''
        while True:
            # self.temp_port_scan_log_path = path.dirname(self.port_scan_log_path) + '/temporary_port_scan_packets.log'
            if not path.exists(self.temp_port_scan_log_path):
                with open(self.temp_port_scan_log_path, 'w'):
                    pass
            
            self.has_port_scan = False
            port_sniff = AsyncSniffer(prn=self.detect_port_scan_attacks, iface=self.interfaces)
            port_sniff.start()
            sleep(5)
            port_sniff.stop()
            result = port_sniff.results
            if self.has_port_scan:
                pkt_dump = Thread(target=self.write_packet_to_pcap, args=(result, self.port_pcap_path))
                pkt_dump.start()
                pkt_dump.join()
            
            with open(self.temp_port_scan_log_path, 'r') as temp_log:
                logs = temp_log.read()

            if logs:
                with open(self.port_scan_log_path, 'a') as final_log:
                    final_log.write(logs)

                open(self.temp_port_scan_log_path, 'w').close()
            
            if self.sniffing_active.is_set() != True:
                break


    def is_sniffing_active(self) -> bool:
        return self.sniffing_active.is_set()
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import pandas as pd
import random
import time
import socket
import json

class TreeTopo(Topo):
    def build(self):
        # Create the internal server
        server = self.addHost('service')

        # Add hosts (200 hosts)
        hosts = []
        for i in range(200):
            host = self.addHost(f'h{i+1}')
            hosts.append(host)

        # Create switches (2 switches)
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')

        # Connect switches to the server
        self.addLink(server, switch1)

        # Connect hosts to switches (split 200 hosts evenly between the two switches)
        for i in range(100):
            self.addLink(hosts[i], switch1)
        for i in range(100, 200):
            self.addLink(hosts[i], switch2)

        # Connect the switches
        self.addLink(switch1, switch2)

def generate_traffic(net):
    # Load dataset with attribute values
    df = pd.read_csv('experiment.csv', low_memory=False)
    host_attributes_map = {}  # Store attributes per host IP

    # Get the internal server host object
    internal_server = net.get('service')
    internal_server_ip = internal_server.IP()

    # Connect to the Ryu controllers on multiple ports
    controller_ips_ports = [
        ('127.0.0.1', 6553),
        ('127.0.0.1', 6554)
    ]

    # Create sockets for each controller
    sockets = []
    for ip, port in controller_ips_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sockets.append(sock)
        except Exception as e:
            print(f"Error connecting to controller at {ip}:{port} - {e}")

    print("\nTraffic Generation Started... (Press Ctrl+C to stop and return to Mininet CLI)\n")

    try:
        for _, row in df.iterrows():
            # Parse attribute values from the dataset
            proto = row['proto']
            login_times = row['login_times']
            power_consumption = row['power_consumption']
            network_reputation = row['network_reputation']
            traffic_patterns = row['traffic_patterns']
            requested_service_security = row['requested_service_security']
            session_duration = row['session_duration']
            hardware_security = row['hardware_security']
            data_security = row['data_security']

            # Choose random source host
            src_host = random.choice([h for h in net.hosts if h != internal_server])
            src_ip = src_host.IP()

            # Create host attributes dictionary
            host_attributes = {
                "device_ip": src_ip,
                "proto": proto,
                "login_times": login_times,
                "power_consumption": power_consumption,
                "network_reputation": network_reputation,
                "traffic_patterns": traffic_patterns,
                "requested_service_security": requested_service_security,
                "session_duration": session_duration,
                "hardware_security": hardware_security,
                "data_security": data_security
            }
            host_attributes_map[src_ip] = host_attributes

            # Send data to the controllers
            json_data = json.dumps(host_attributes)
            for sock in sockets:
                sock.sendall(json_data.encode('utf-8'))

            print(f"Packet sent from {src_ip} "
                  f"to {internal_server_ip} with attributes: {host_attributes}\n")

            # Simulate traffic delay
            time.sleep(random.uniform(0.01, 1.0))

    except KeyboardInterrupt:
        print("\nTraffic generation stopped by user (Ctrl+C). Returning to Mininet CLI.\n")
    except Exception as e:
        print(f"Error during traffic generation: {e}")
    finally:
        for sock in sockets:
            sock.close()

def run():
    setLogLevel('info')
    topo = TreeTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()

    # Start the controllers
    controller1 = net.addController('c1', controller=RemoteController, port=6553)
    controller2 = net.addController('c2', controller=RemoteController, port=6554)
    
    # Attach the generate_traffic function to net so it can be called in the CLI
    net.generate_traffic = lambda: generate_traffic(net)

    print("\nTopology and Routing Setup Complete\n")

    # Run the CLI
    CLI(net)

    # Stop the network
    net.stop()
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

###########################################################################################  controller1 

import csv
import math
import json
import socket
import threading
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
from ryu.ofproto import ofproto_v1_3


class TrustBasedAuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrustBasedAuthController, self).__init__(*args, **kwargs)
        self.trust_threshold = 0.8
        self.controller_ip = '127.0.0.1'
        self.port = 6553
        self.weights = {
            'login_times': 0.5,
            'power_consumption': 0.2,
            'network_reputation': 0.7,
            'traffic_pattern': 0.6,
            'requested_service_security': 0.9,
            'session_duration': 0.6,
            'hardware_security': 0.2,
            'data_security': 0.7
        }
        
        self.authorization_policies = {
            "device_policy": {
                "allowed_protocols": [2, 3],  # 2 for TCP, 3 for UDP
                "requested_service_security": 0.6,
                "data_security": 0.7
            }
        }
        self.device_rules = {}

        # Initialize CSV for logging
        self.csv_file = "trust_0.88.csv"
        with open(self.csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp", "device_ip", "login_times", "power_consumption",
                "network_reputation", "traffic_pattern", "requested_service_security",
                "session_duration", "hardware_security", "data_security",
                "trust_value", "status", "reason"
            ])

        # Start the server for traffic data
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.controller_ip, self.port))
        server_socket.listen(5)
        self.logger.info(f"Controller listening on {self.controller_ip}:{self.port}")
        while True:
            client_socket, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                json_data = json.loads(data)
                device_ip = json_data.get('device_ip', 'unknown')
                trust_value = self.calculate_trust(json_data)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                if trust_value < self.trust_threshold:
                    status = "Blocked"
                    reason = "Trust value below threshold"
                elif not self.match_attributes_to_policy(json_data):
                    status = "Blocked"
                    reason = self.get_policy_violation_reason(json_data)
                else:
                    status = "Allowed"
                    reason = "All checks passed"

                self.log_to_csv(timestamp, device_ip, json_data, trust_value, status, reason)

                if status == "Allowed":
                    self.allow_device(device_ip)
                else:
                    self.block_device(device_ip)
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def calculate_trust(self, data):
        try:
            factors = [
                {
                    'login_times': data.get('login_times', 0),
                    'power_consumption': data.get('power_consumption', 0)
                },
                {
                    'network_reputation': data.get('network_reputation', 0),
                    'traffic_pattern': data.get('traffic_pattern', 0)
                },
                {
                    'requested_service_security': data.get('requested_service_security', 0),
                    'session_duration': data.get('session_duration', 0)
                },
                {
                    'hardware_security': data.get('hardware_security', 0),
                    'data_security': data.get('data_security', 0)
                }
            ]
            final_trust_value = sum(
                self.calculate_category_trust(f) for f in factors
            )
            return 1 / (1 + math.exp(-final_trust_value))
        except Exception as e:
            self.logger.error(f"Error calculating trust: {e}")
            return 0

    def calculate_category_trust(self, factors):
        return sum(self.weights.get(k, 0) * v for k, v in factors.items())

    def match_attributes_to_policy(self, data):
        policy = self.authorization_policies["device_policy"]
        proto = data.get("proto")
        if proto not in policy["allowed_protocols"]:
            return False
        if data.get("requested_service_security", 0.0) < policy["requested_service_security"]:
            return False
        
        if data.get("data_security", 0.0) < policy["data_security"]:
            return False
        return True

    def get_policy_violation_reason(self, data):
        policy = self.authorization_policies["device_policy"]
        if data.get("proto") not in policy["allowed_protocols"]:
            return "Protocol not allowed"
        if data.get("requested_service_security", 0.0) < policy["requested_service_security"]:
            return "Requested service security too low"
      
        if data.get("data_security", 0.0) < policy["data_security"]:
            return "Data security inadequate"
        return "Unknown policy violation"

   
    def log_to_csv(self, timestamp, device_ip, data, trust_value, status, reason):
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp, device_ip,
                data.get('login_times', 0),
                data.get('power_consumption', 0),
                data.get('network_reputation', 0),
                data.get('traffic_pattern', 0),
                data.get('requested_service_security', 0),
                data.get('session_duration', 0),
                data.get('hardware_security', 0),
                data.get('data_security', 0),
                trust_value, status, reason
            ])

    def allow_device(self, ip):
        self.logger.info(f"[INFO] Device: {ip} Allowed.")
        for dp in self.device_rules:
            datapath = self.device_rules[dp]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip, eth_type=0x0800)
            self.remove_flow(datapath, match)

    def block_device(self, ip):
        self.logger.info(f"[WARNING] Device: {ip} Blocked | Authorization: Fail")
        for dp in self.device_rules:
            datapath = self.device_rules[dp]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip, eth_type=0x0800)
            actions = []
            self.add_flow(datapath, 100, match, actions)

    def remove_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Switch connected. Installing default allow rule.")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.device_rules[datapath.id] = datapath

        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)


----------------------------------------------------------------------------------------------------------------------------------
###########################################################################################  controller2
import csv
import math
import json
import socket
import threading
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
from ryu.ofproto import ofproto_v1_3


class TrustBasedAuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrustBasedAuthController, self).__init__(*args, **kwargs)
        self.trust_threshold = 0.8
        self.controller_ip = '127.0.0.1'
        self.port = 6554
        self.weights = {
            'login_times': 0.5,
            'power_consumption': 0.2,
            'network_reputation': 0.7,
            'traffic_pattern': 0.6,
            'requested_service_security': 0.9,
            'session_duration': 0.6,
            'hardware_security': 0.2,
            'data_security': 0.7
        }
        
        self.authorization_policies = {
            "device_policy": {
                "allowed_protocols": [2, 3],  # 2 for TCP, 3 for UDP
                "requested_service_security": 0.6,
                "data_security": 0.7
            }
        }
        self.device_rules = {}

        # Initialize CSV for logging
        self.csv_file = "trust_0.8_BU.csv"
        with open(self.csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp", "device_ip", "login_times", "power_consumption",
                "network_reputation", "traffic_pattern", "requested_service_security",
                "session_duration", "hardware_security", "data_security",
                "trust_value", "status", "reason"
            ])

        # Start the server for traffic data
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.controller_ip, self.port))
        server_socket.listen(5)
        self.logger.info(f"Controller listening on {self.controller_ip}:{self.port}")
        while True:
            client_socket, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                json_data = json.loads(data)
                device_ip = json_data.get('device_ip', 'unknown')
                trust_value = self.calculate_trust(json_data)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                if trust_value < self.trust_threshold:
                    status = "Blocked"
                    reason = "Trust value below threshold"
                elif not self.match_attributes_to_policy(json_data):
                    status = "Blocked"
                    reason = self.get_policy_violation_reason(json_data)
                else:
                    status = "Allowed"
                    reason = "All checks passed"

                self.log_to_csv(timestamp, device_ip, json_data, trust_value, status, reason)

                if status == "Allowed":
                    self.allow_device(device_ip)
                else:
                    self.block_device(device_ip)
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def calculate_trust(self, data):
        try:
            factors = [
                {
                    'login_times': data.get('login_times', 0),
                    'power_consumption': data.get('power_consumption', 0)
                },
                {
                    'network_reputation': data.get('network_reputation', 0),
                    'traffic_pattern': data.get('traffic_pattern', 0)
                },
                {
                    'requested_service_security': data.get('requested_service_security', 0),
                    'session_duration': data.get('session_duration', 0)
                },
                {
                    'hardware_security': data.get('hardware_security', 0),
                    'data_security': data.get('data_security', 0)
                }
            ]
            final_trust_value = sum(
                self.calculate_category_trust(f) for f in factors
            )
            return 1 / (1 + math.exp(-final_trust_value))
        except Exception as e:
            self.logger.error(f"Error calculating trust: {e}")
            return 0

    def calculate_category_trust(self, factors):
        return sum(self.weights.get(k, 0) * v for k, v in factors.items())

    def match_attributes_to_policy(self, data):
        policy = self.authorization_policies["device_policy"]
        proto = data.get("proto")
        if proto not in policy["allowed_protocols"]:
            return False
        if data.get("requested_service_security", 0.0) < policy["requested_service_security"]:
            return False
        
        if data.get("data_security", 0.0) < policy["data_security"]:
            return False
        return True

    def get_policy_violation_reason(self, data):
        policy = self.authorization_policies["device_policy"]
        if data.get("proto") not in policy["allowed_protocols"]:
            return "Protocol not allowed"
        if data.get("requested_service_security", 0.0) < policy["requested_service_security"]:
            return "Requested service security too low"
      
        if data.get("data_security", 0.0) < policy["data_security"]:
            return "Data security inadequate"
        return "Unknown policy violation"

   
    def log_to_csv(self, timestamp, device_ip, data, trust_value, status, reason):
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp, device_ip,
                data.get('login_times', 0),
                data.get('power_consumption', 0),
                data.get('network_reputation', 0),
                data.get('traffic_pattern', 0),
                data.get('requested_service_security', 0),
                data.get('session_duration', 0),
                data.get('hardware_security', 0),
                data.get('data_security', 0),
                trust_value, status, reason
            ])

    def allow_device(self, ip):
        self.logger.info(f"[INFO] Device: {ip} Allowed.")
        for dp in self.device_rules:
            datapath = self.device_rules[dp]
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip, eth_type=0x0800)
            self.remove_flow(datapath, match)

    def block_device(self, ip):
        self.logger.info(f"[WARNING] Device: {ip} Blocked | Authorization: Fail")
        for dp in self.device_rules:
            datapath = self.device_rules[dp]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip, eth_type=0x0800)
            actions = []
            self.add_flow(datapath, 100, match, actions)

    def remove_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Switch connected. Installing default allow rule.")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.device_rules[datapath.id] = datapath

        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

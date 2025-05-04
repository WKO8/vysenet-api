from flask import Flask, jsonify, request
from threading import Thread
import json
import os
import time
from datetime import datetime
from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr

AUTHORIZED_DEVICES_FILE = "authorized_devices.json"

app = Flask(__name__)
monitor = None
monitor_thread = None
monitoring = False


class NetworkMonitor:
    def __init__(self, interface=None, network=None):
        self.interface = interface
        self.network = network
        self.authorized_devices = self.load_authorized_devices()

    def load_authorized_devices(self):
        if os.path.exists(AUTHORIZED_DEVICES_FILE):
            with open(AUTHORIZED_DEVICES_FILE, 'r') as file:
                return json.load(file)
        else:
            with open(AUTHORIZED_DEVICES_FILE, 'w') as file:
                json.dump({}, file, indent=4)
            return {}

    def save_authorized_devices(self):
        with open(AUTHORIZED_DEVICES_FILE, 'w') as file:
            json.dump(self.authorized_devices, file, indent=4)

    def scan_network(self):
        arp = ARP(pdst=self.network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]

        discovered = {}
        for _, rcv in result:
            mac = rcv.hwsrc
            ip = rcv.psrc
            discovered[mac] = {
                "ip": ip,
                "last_seen": datetime.now().isoformat()
            }
        return discovered
    

    def add_authorized_device(self, mac, name):
        if mac not in self.authorized_devices:
            self.authorized_devices[mac] = {
                "name": name,
                "first_seen": datetime.now().isoformat()
            }
            self.save_authorized_devices()

    def check_unauthorized_devices(self, devices):
        return {
            mac: info
            for mac, info in devices.items()
            if mac not in self.authorized_devices
        }


@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            network = ip.rpartition('.')[0] + '.0/24'
            interfaces.append({"interface": iface, "ip": ip, "network": network})
        except Exception:
            continue
    return jsonify(interfaces)


@app.route("/select_interface", methods=["POST"])
def select_interface():
    global monitor
    data = request.get_json()
    interface = data.get("interface")
    network = data.get("network")
    if not interface or not network:
        return jsonify({"error": "interface e network são obrigatórios"}), 400
    monitor = NetworkMonitor(interface=interface, network=network)
    return jsonify({"message": "Interface e rede configuradas com sucesso"})


@app.route("/scan", methods=["GET"])
def scan_network():
    if not monitor:
        return jsonify({"error": "Monitor não inicializado"}), 400
    found = monitor.scan_network()
    return jsonify(found)


@app.route("/authorize", methods=["POST"])
def authorize_device():
    if not monitor:
        return jsonify({"error": "Monitor não inicializado"}), 400
    data = request.get_json()
    mac = data.get("mac")
    name = data.get("name")
    if not mac or not name:
        return jsonify({"error": "mac e name são obrigatórios"}), 400
    monitor.add_authorized_device(mac, name)
    return jsonify({"message": f"Dispositivo {mac} autorizado como '{name}'"})


@app.route("/authorized", methods=["GET"])
def get_authorized():
    if not monitor:
        return jsonify({"error": "Monitor não inicializado"}), 400
    return jsonify(monitor.authorized_devices)


@app.route("/unauthorized", methods=["GET"])
def get_unauthorized():
    if not monitor:
        return jsonify({"error": "Monitor não inicializado"}), 400
    found = monitor.scan_network()
    unauthorized = monitor.check_unauthorized_devices(found)
    return jsonify(unauthorized)


@app.route("/start_monitoring", methods=["POST"])
def start_monitoring():
    global monitor_thread, monitoring

    if not monitor:
        return jsonify({"error": "Monitor não inicializado"}), 400

    interval = request.json.get("interval", 60)
    if monitoring:
        return jsonify({"message": "Monitoramento já em execução."}), 200

    def monitor_loop():
        global monitoring
        monitoring = True
        try:
            while monitoring:
                found = monitor.scan_network()
                unauthorized = monitor.check_unauthorized_devices(found)
                if unauthorized:
                    print(f"[!] Dispositivos não autorizados: {unauthorized}")
                time.sleep(interval)
        except Exception as e:
            print(f"[!] Erro no monitoramento: {e}")
        finally:
            monitoring = False

    monitor_thread = Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    return jsonify({"message": "Monitoramento iniciado."})


@app.route("/status", methods=["GET"])
def get_status():
    return jsonify({"monitoring": monitoring})


@app.route("/")
def home():
    return jsonify({"message": "API de Monitoramento de Rede está ativa"})


if __name__ == "__main__":
    app.run(debug=True)

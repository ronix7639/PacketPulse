from flask import Flask, render_template, request, jsonify, send_file
import threading
import scapy.all as scapy
import pandas as pd
import os

app = Flask(__name__)

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.sniffing = False

    def packet_callback(self, packet):
        self.packets.append({
            'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
            'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
            'protocol': packet[scapy.IP].proto if packet.haslayer(scapy.IP) else None,
            'src_port': packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else None),
            'dst_port': packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else None),
        })

    def start_sniffing(self, interface):
        self.sniffing = True
        scapy.sniff(iface=interface, prn=self.packet_callback, stop_filter=lambda _: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False

sniffer = PacketSniffer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    if not sniffer.sniffing:
        interface = request.form['interface']
        thread = threading.Thread(target=sniffer.start_sniffing, args=(interface,))
        thread.start()
        return '', 204  # Return an empty response with status code 204 (No Content)
    else:
        return jsonify({'message': 'Packet sniffing is already running.'})

@app.route('/stop', methods=['POST'])
def stop():
    if sniffer.sniffing:
        sniffer.stop_sniffing()
        return jsonify({'message': 'Packet sniffing stopped.'})
    else:
        return jsonify({'message': 'Packet sniffing is not running.'})

@app.route('/packets')
def get_packets():
    return jsonify(sniffer.packets)

@app.route('/export', methods=['POST'])
def export():
    df = pd.DataFrame(sniffer.packets)
    file_path = os.path.join(os.getcwd(), 'packet_logs.xlsx')
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
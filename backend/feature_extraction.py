import statistics
import logging
from scapy.layers.inet import IP, TCP, UDP
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def get_local_ips():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname_ex(hostname)[2]
    except Exception as e:
        logger.error(f"Error getting local IPs: {e}")
        return []

def extract_features(packets):
    if not packets:
        return None

    logger.warning("Idle features are not computed from packet data. These are placeholder constants. If the model was trained on real idle times, prediction accuracy will be affected.")

    local_ips = get_local_ips()

    flow_durations = []
    packet_lengths = []
    flow_iat = []
    fwd_iat = []
    bwd_iat = []

    fwd_packet_lengths = []
    bwd_packet_lengths = []
    fwd_packet_count = 0
    bwd_packet_count = 0
    fwd_total_length = 0
    bwd_total_length = 0
    destination_port = 0

    for i in range(1, len(packets)):
        pkt = packets[i]
        flow_durations.append(pkt.time - packets[0].time)
        flow_iat.append(pkt.time - packets[i - 1].time)

        is_fwd = False
        if pkt.haslayer(IP):
            is_fwd = pkt[IP].src in local_ips

        if is_fwd:
            fwd_iat.append(pkt.time - packets[i - 1].time)
            fwd_packet_lengths.append(len(pkt.payload))
            fwd_packet_count += 1
            fwd_total_length += len(pkt.payload)
        else:
            bwd_iat.append(pkt.time - packets[i - 1].time)
            bwd_packet_lengths.append(len(pkt.payload))
            bwd_packet_count += 1
            bwd_total_length += len(pkt.payload)

        packet_lengths.append(len(pkt.payload))

        if pkt.haslayer(TCP):
            destination_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            destination_port = pkt[UDP].dport

    if not packet_lengths:
        packet_lengths = [0]

    feature_dict = {
        'Flow Duration': flow_durations[-1] if flow_durations else 0,
        'Bwd Packet Length Max': max(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Packet Length Min': min(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Packet Length Mean': statistics.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Packet Length Std': statistics.stdev(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0,
        'Flow IAT Mean': statistics.mean(flow_iat) if flow_iat else 0,
        'Flow IAT Std': statistics.stdev(flow_iat) if len(flow_iat) > 1 else 0,
        'Flow IAT Max': max(flow_iat) if flow_iat else 0,
        'Fwd IAT Total': sum(fwd_iat) if fwd_iat else 0,
        'Fwd IAT Std': statistics.stdev(fwd_iat) if len(fwd_iat) > 1 else 0,
        'Fwd IAT Max': max(fwd_iat) if fwd_iat else 0,
        'Max Packet Length': max(packet_lengths),
        'Packet Length Mean': statistics.mean(packet_lengths),
        'Packet Length Std': statistics.stdev(packet_lengths) if len(packet_lengths) > 1 else 0,
        'Packet Length Variance': statistics.variance(packet_lengths) if len(packet_lengths) > 1 else 0,
        'Average Packet Size': statistics.mean(packet_lengths),
        'Avg Bwd Segment Size': statistics.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
        # WARNING: Idle features are not computed from packet data.
        # These are placeholder constants. If the model was trained on
        # real idle times, prediction accuracy will be affected.
        'Idle Mean': 0,
        'Idle Max': 0,
        'Idle Min': 0,
        'Destination Port': destination_port,
        'Total Fwd Packets': fwd_packet_count,
        'Total Backward Packets': bwd_packet_count,
        'Total Length of Fwd Packets': fwd_total_length,
        'Total Length of Bwd Packets': bwd_total_length,
        'Fwd Packet Length Max': max(fwd_packet_lengths) if fwd_packet_lengths else 0,
        'Fwd Packet Length Min': min(fwd_packet_lengths) if fwd_packet_lengths else 0
    }

    return feature_dict

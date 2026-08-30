from scapy.all import IP, ICMP, sr1
import cesar

solicitudICMP = ICMP(
    type=8,  # Echo Request
    id=12345,  # Identifier
    seq=1  # Sequence Number
)

palabra_incriptada = cesar.cifrar_cesar("criptografia y seguridad en redes", 0)

for caracter in palabra_incriptada:
    try:
        print(f"caracter: {caracter}")
        paquete = IP(dst="8.8.8.8") / solicitudICMP / caracter
        respuesta = sr1(paquete, timeout=2)
    except Exception as e:
        print(f"No se recibió respuesta para el caracter: {caracter}")
        
        
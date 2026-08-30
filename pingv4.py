from scapy.all import IP, ICMP, sr1
import cesar

solicitudICMP = ICMP(
    type=8,  # Echo Request
    id=12345,  # Identifier
    seq=1  # Sequence Number
)

palabra_incriptada = cesar.cifrar_cesar("criptografia y seguridad en redes", 0)



paquete = IP(dst="192.168.18.12") / solicitudICMP / palabra_incriptada
paquete.show()

respuesta = sr1(paquete, timeout=2)

if respuesta and respuesta.haslayer(ICMP):
    if respuesta[ICMP].type == 0:  # Echo Reply
        print("Respuesta recibida:")
        texto_resultante = respuesta.load.decode("utf-8")
else:
    print("No se recibió respuesta o hubo un error en la comunicación.")
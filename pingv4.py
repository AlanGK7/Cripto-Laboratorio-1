from scapy.all import IP, ICMP, sr1
import cesar
import time
import struct

solicitudICMP = ICMP(
    type=8,  # Echo Request
    id=12345,  # Identifier
    seq=1  # Sequence Number
)

palabra_incriptada = cesar.cifrar_cesar("criptografia y seguridad en redes", 9)
print(f"palabra_incriptada: {palabra_incriptada}")

secuencia = bytes(range(16,56))

for caracter in palabra_incriptada:
    print(f"caracter: {caracter}")
    
    tiempo_actual= time.time()
    timestap_completo = struct.pack('d', tiempo_actual)  # Convertir el timestamp a bytes
    resto = timestap_completo[1:8]  # Tomar los bytes del 1 al 7 (7 bytes)
    
    caracter = caracter.encode('utf-8')  # Convertir el carácter a bytes
    
    palabra_48bytes = caracter + resto + secuencia
    paquete = IP(dst="8.8.8.8") / solicitudICMP / palabra_48bytes
    respuesta = sr1(paquete, timeout=2)
    solicitudICMP.seq += 1  # Incrementar el número de secuencia para el siguiente paquete
    time.sleep(1)  # esperar 1 segundo antes de enviar el siguiente paquete
    
        
        
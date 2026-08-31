import sys
from scapy.all import rdpcap, ICMP, IP, Raw

# Código ANSI para imprimir en verde
GREEN = '\033[92m'
RESET = '\033[0m'

def decrypt_caesar(ciphertext, shift):
    """Descifra un texto cifrado con César dado un corrimiento específico."""
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            plaintext += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            plaintext += char
    return plaintext

def score_text(text):
    """
    Evalúa la probabilidad de que el texto sea el mensaje en claro 
    buscando palabras comunes en español.
    """
    common_words = [" y ", " en ", " la ", " el ", " de ", " que ", " redes ", " seguridad "]
    score = 0
    for word in common_words:
        if word in text.lower():
            score += 1
    return score

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 readv2.py <archivo.pcapng>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error al leer el archivo de captura: {e}")
        sys.exit(1)

    ciphertext = ""

    # Extraer el carácter oculto del campo data de cada ICMP request
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Type 8 es Echo (ping) request
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                if len(payload) > 0:
                    # Se asume que el primer byte del payload contiene el carácter filtrado
                    char = chr(payload[0])
                    ciphertext += char

    if not ciphertext:
        print("No se encontraron datos en los paquetes ICMP Request.")
        sys.exit(1)

    best_shift = 0
    max_score = -1

    # Evaluar todas las combinaciones posibles (0 a 25)
    for shift in range(26):
        decrypted = decrypt_caesar(ciphertext, shift)
        score = score_text(decrypted)
        if score > max_score:
            max_score = score
            best_shift = shift

    # Imprimir todas las combinaciones, destacando la más probable en verde
    for shift in range(26):
        decrypted = decrypt_caesar(ciphertext, shift)
        if shift == best_shift:
            print(f"{shift}\n{GREEN}{decrypted}{RESET}\n")
        else:
            print(f"{shift}\n{decrypted}\n")

if __name__ == "__main__":
    main()
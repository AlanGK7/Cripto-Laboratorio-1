import sys

def cifrar_cesar(texto, corrimiento):
    resultado = ""
    
    for caracter in texto:
        # se verifica si es una letra
        if caracter.isalpha():
            # se determina base ascci para mayusculas y minusculas
            ascii_base = ord('A') if caracter.isupper() else ord('a')
            
            # aplicar la fórmula del cifrado cesar (x + n) mod 26
            nuevo_ascii = (ord(caracter) - ascii_base + corrimiento) % 26 + ascii_base
            resultado += chr(nuevo_ascii)
        else:
            # si no es letra se deja igual
            resultado += caracter
            
    return resultado

if __name__ == "__main__":
    # se valida que hay 2 argumentos al codigo
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"<texto_a_cifrar>\" <corrimiento>")
        sys.exit(1)
        
    texto_ingresado = sys.argv[1]
    
    try:
        corrimiento_ingresado = int(sys.argv[2])
    except ValueError:
        print("Error de corrimiento")
        sys.exit(1)
        
    texto_cifrado = cifrar_cesar(texto_ingresado, corrimiento_ingresado)
    print(texto_cifrado)
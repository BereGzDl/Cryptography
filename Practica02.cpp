#include <iostream>
#include <string>
#include <cctype>

using namespace std;

// Función para cifrar el texto
string cifrarVigenere(string texto, string clave) {
    string resultado = "";
    int indiceClave = 0;
    int longClave = clave.length();

    for (char c : texto) {
        if (isalpha(c)) {
            // Determinar si la letra es mayúscula o minúscula
            char base = isupper(c) ? 'A' : 'a';
            // Obtener el valor de desplazamiento de la clave (siempre en base a minúsculas)
            char despClave = tolower(clave[indiceClave % longClave]) - 'a';
            
            // Aplicar la fórmula: E = (P + K) mod 26
            char caracterCifrado = ((c - base + despClave) % 26) + base;
            resultado += caracterCifrado;
            
            // Solo avanzamos en la clave si ciframos una letra
            indiceClave++;
        } else {
            // Si no es letra (espacios, números, signos), se deja igual
            resultado += c;
        }
    }
    return resultado;
}

// Función para descifrar el texto
string descifrarVigenere(string texto, string clave) {
    string resultado = "";
    int indiceClave = 0;
    int longClave = clave.length();

    for (char c : texto) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            char despClave = tolower(clave[indiceClave % longClave]) - 'a';
            
            // Aplicar la fórmula: D = (E - K + 26) mod 26
            char caracterDescifrado = ((c - base - despClave + 26) % 26) + base;
            resultado += caracterDescifrado;
            
            indiceClave++;
        } else {
            resultado += c;
        }
    }
    return resultado;
}

int main() {
    string texto; 
    string clave;

    cout << "--- Cifrado Vigenere ---" << endl;
    
    cout << "Texto original: "; 
    getline(cin, texto); 
    
    cout << "Clave: "; 
    cin >> clave; 

    cout << endl;

    string textoCifrado = cifrarVigenere(texto, clave);
    cout << "Texto cifrado:    " << textoCifrado << endl;

    string textoDescifrado = descifrarVigenere(textoCifrado, clave);
    cout << "Texto descifrado: " << textoDescifrado << endl;

    return 0;
}
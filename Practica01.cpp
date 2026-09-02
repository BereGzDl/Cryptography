#include <iostream>
#include <string>

using namespace std;

string caesarCipher(string text, int shift) {
    string result = "";
    shift = shift % 26;
    
    for (size_t i = 0; i < text.length(); i++) {
        char c = text[i];
        
        if (isupper(c)) {
            result += char((c + shift - 65) % 26 + 65);
        }
        else if (islower(c)) {
            result += char((c + shift - 97) % 26 + 97);
        }
        else {
            result += c;
        }
    }
    return result;
}

int main() {
    string texto;
    int llave;
    
    cout << "Ingresa el texto: ";
    getline(cin, texto);
    
    cout << "Ingresa la llave (cualquier número natural): ";
    cin >> llave;
    
    string cifrado = caesarCipher(texto, llave);
    string descifrado = caesarCipher(cifrado, 26 - (llave % 26));
    
    cout << "\nTexto cifrado:  " << cifrado << endl;
    cout << "Descifrado:     " << descifrado << endl;
    
    return 0;
}
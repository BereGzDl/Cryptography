#include <iostream>
#include <string>
#include <vector>
#include <cctype>

using namespace std;

// 1. Formatear texto (mayúsculas, sin espacios, cambiar J por I, separar letras iguales con X)
string prepararTexto(string texto) {
    string textoLimpio = "";
    for (char c : texto) {
        if (isalpha(c)) {
            c = toupper(c);
            if (c == 'J') c = 'I'; 
            textoLimpio += c;
        }
    }
    
    string formateado = "";
    for (size_t i = 0; i < textoLimpio.length(); i += 2) {
        formateado += textoLimpio[i];
        if (i + 1 < textoLimpio.length()) {
            if (textoLimpio[i] == textoLimpio[i + 1]) {
                formateado += 'X'; 
                i--; 
            } else {
                formateado += textoLimpio[i + 1];
            }
        }
    }
    
    if (formateado.length() % 2 != 0) formateado += 'X'; 
    return formateado;
}

// 2. Generar la matriz 5x5 usando la palabra clave
void generarMatriz(string clave, char matriz[5][5]) {
    bool alfabeto[26] = {false};
    alfabeto['J' - 'A'] = true; 
    int fila = 0, col = 0;

    for (char c : clave) {
        if (isalpha(c)) {
            c = toupper(c);
            if (c == 'J') c = 'I';
            if (!alfabeto[c - 'A']) {
                alfabeto[c - 'A'] = true;
                matriz[fila][col++] = c;
                if (col == 5) { col = 0; fila++; }
            }
        }
    }
    
    // Llenar el resto de la matriz
    for (int i = 0; i < 26; i++) {
        if (!alfabeto[i]) {
            matriz[fila][col++] = (char)(i + 'A');
            if (col == 5) { col = 0; fila++; }
        }
    }
}

// 3. Buscar las coordenadas
void buscarPosicion(char matriz[5][5], char letra, int &f, int &c) {
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (matriz[i][j] == letra) {
                f = i; c = j; return;
            }
        }
    }
}

// 4. Aplicar las reglas de cifrado
string cifrar(string texto, char matriz[5][5]) {
    string cifrado = "";
    for (size_t i = 0; i < texto.length(); i += 2) {
        int f1, c1, f2, c2;
        buscarPosicion(matriz, texto[i], f1, c1);
        buscarPosicion(matriz, texto[i + 1], f2, c2);

        if (f1 == f2) { 
            cifrado += matriz[f1][(c1 + 1) % 5];
            cifrado += matriz[f2][(c2 + 1) % 5];
        } else if (c1 == c2) { 
            cifrado += matriz[(f1 + 1) % 5][c1];
            cifrado += matriz[(f2 + 1) % 5][c2];
        } else { 
            cifrado += matriz[f1][c2];
            cifrado += matriz[f2][c1];
        }
    }
    return cifrado;
}

int main() {
    string clave, textoOriginal;
    char matriz[5][5];

    cout << "=== CIFRADO DE WHEATSTONE / PLAYFAIR ===\n\n";

    // Recibir entradas del usuario
    cout << "Ingresa la palabra clave: ";
    getline(cin, clave);

    cout << "Ingresa el texto a cifrar: ";
    getline(cin, textoOriginal);

    // Procesamiento
    generarMatriz(clave, matriz);
    string textoPreparado = prepararTexto(textoOriginal);
    string textoCifrado = cifrar(textoPreparado, matriz);

    // Mostrar resultados
    cout << "\n----------------------------------------\n";
    cout << "Matriz generada (5x5):\n";
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            cout << matriz[i][j] << " ";
        }
        cout << "\n";
    }
    
    cout << "----------------------------------------\n";
    cout << "Texto original:   " << textoOriginal << "\n";
    cout << "Texto preparado:  " << textoPreparado << "\n";
    cout << "Texto cifrado:    " << textoCifrado << "\n";
    cout << "========================================\n";

    return 0;
}
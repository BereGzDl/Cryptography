#include <iostream>
#include <string>
#include <cctype> 

using namespace std;

int main() {
    string exterior = "ABCDEFGILMNOPQRSTVXZ1234";
    string interior = "gklnprtuz&xysomqihfdbace";

    string mensaje;
    string cifrado = "";
    int rotacion;

    // 1. Pedir la cantidad de rotación al usuario
    cout << "¿Cuantas posiciones quieres rotar el disco interior? ";
    cin >> rotacion;
    
    // IMPORTANTE: Limpiar el "Enter" que se quedó en la memoria tras escribir el número
    cin.ignore(); 

    // 2. Girar el disco interior
    int longitud = interior.length();
    
    // Esta fórmula matemática asegura que la rotación funcione bien 
    // incluso si el usuario pone un número negativo o mayor a 24.
    rotacion = (rotacion % longitud + longitud) % longitud;
    
    // Cortamos la cadena en dos partes y las unimos al revés para simular el giro
    interior = interior.substr(rotacion) + interior.substr(0, rotacion);

    cout << "\n--- Posición de los discos ---" << endl;
    cout << "Exterior: " << exterior << endl;
    cout << "Interior: " << interior << "\n\n";

    // 3. Pedir el mensaje al usuario
    cout << "Escribe el mensaje a cifrar: ";
    getline(cin, mensaje); 

    // Convertir el mensaje a mayúsculas
    for (int i = 0; i < mensaje.length(); i++) {
        mensaje[i] = toupper(mensaje[i]);
    }

    // --- PROCESO DE CIFRADO ---
    for (int i = 0; i < mensaje.length(); i++) {
        char letra = mensaje[i];
        int posicion = exterior.find(letra);
        
        if (posicion != string::npos) {
            cifrado += interior[posicion];
        } else {
            cifrado += letra; 
        }
    }

    cout << "\nMensaje cifrado:  " << cifrado << endl;

    // --- PROCESO DE DESCIFRADO ---
    string descifrado = "";
    for (int i = 0; i < cifrado.length(); i++) {
        char letra = cifrado[i];
        int posicion = interior.find(letra);
        
        if (posicion != string::npos) {
            descifrado += exterior[posicion];
        } else {
            descifrado += letra;
        }
    }

    cout << "Mensaje descifrado: " << descifrado << endl;

    return 0;
}
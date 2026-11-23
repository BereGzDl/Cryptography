/* ============================================================================
 *  Implementación del algoritmo DES (Data Encryption Standard)
 *  Materia: Criptografía
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Si es 1, el programa imprime los pasos intermedios. */
static int modoDetallado = 1;

/* Cuando una función falla devuelve 1 y deja aquí el motivo.
 * Si todo sale bien devuelve 0. (Es el reemplazo de las excepciones.) */
static const char *mensajeError = "";

static int fallar(const char *mensaje) {
    mensajeError = mensaje;
    return 1;
}

/* ============================================================================
 *  TABLAS DEL ESTÁNDAR (FIPS 46-3)
 * ============================================================================ */

/* Permutación inicial (IP): se aplica al bloque de 64 bits antes de las rondas. */
static const int PERMUTACION_INICIAL[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

/* Permutación final (IP^-1): es la inversa de la inicial. */
static const int PERMUTACION_FINAL[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

/* Expansión (E): convierte la mitad derecha de 32 bits en 48 bits,
 * repitiendo algunos bits. */
static const int EXPANSION[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

/* Permutación P: se aplica a los 32 bits que salen de las cajas S. */
static const int PERMUTACION_P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

/* Permuted Choice 1 (PC-1): de la clave de 64 bits saca 56 bits
 * (descarta los 8 bits de paridad, que son las posiciones 8, 16, 24, ...). */
static const int PERMUTACION_PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

/* Permuted Choice 2 (PC-2): de los 56 bits (C y D juntos) saca los 48 bits
 * de cada subclave. */
static const int PERMUTACION_PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

/* Cuántas posiciones se rota a la izquierda cada mitad de la clave en cada ronda. */
static const int DESPLAZAMIENTOS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/* Las 8 cajas de sustitución (cajas S). Cada una recibe 6 bits y devuelve 4.
 * Se indexan como CAJAS_S[caja][fila][columna]. */
static const int CAJAS_S[8][4][16] = {
    { /* S1 */
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    { /* S2 */
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    { /* S3 */
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    { /* S4 */
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    { /* S5 */
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    { /* S6 */
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    { /* S7 */
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    { /* S8 */
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

/* ============================================================================
 *  FUNCIONES AUXILIARES: conversiones entre bytes, bits y hexadecimal
 * ============================================================================ */

/* Convierte 'cantidad' bytes en bits (8 bits por byte, el más significativo
 * primero). 'bits' debe tener espacio para cantidad * 8 enteros. */
static void bytesABits(const unsigned char *bytes, size_t cantidad, int *bits) {
    for (size_t i = 0; i < cantidad; i++) {
        for (int j = 7; j >= 0; j--) {
            bits[i * 8 + (7 - j)] = (bytes[i] >> j) & 1;
        }
    }
}

/* Hace lo contrario: agrupa los bits de 8 en 8 para formar bytes. */
static void bitsABytes(const int *bits, size_t cantidadBits, unsigned char *bytes) {
    for (size_t i = 0; i + 7 < cantidadBits; i += 8) {
        unsigned char valor = 0;
        for (int j = 0; j < 8; j++) {
            valor = (unsigned char)((valor << 1) | bits[i + j]);
        }
        bytes[i / 8] = valor;
    }
}

/* Convierte bytes a una cadena hexadecimal en mayúsculas (ej. "85E81354").
 * 'salida' debe tener espacio para cantidad * 2 + 1 caracteres. */
static void bytesAHex(const unsigned char *bytes, size_t cantidad, char *salida) {
    const char *digitos = "0123456789ABCDEF";
    for (size_t i = 0; i < cantidad; i++) {
        salida[i * 2]     = digitos[bytes[i] >> 4];
        salida[i * 2 + 1] = digitos[bytes[i] & 15];
    }
    salida[cantidad * 2] = '\0';
}

/* Convierte un dígito hexadecimal en su valor. Devuelve -1 si no es válido. */
static int valorHex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convierte una cadena hexadecimal en bytes. 'bytes' debe tener espacio para
 * strlen(hex) / 2 bytes. Devuelve 1 (con mensaje) si la cadena es inválida. */
static int hexABytes(const char *hex, unsigned char *bytes, size_t *cantidad) {
    size_t largo = strlen(hex);
    if (largo % 2 != 0) {
        return fallar("El hexadecimal debe tener una cantidad par de digitos.");
    }
    for (size_t i = 0; i < largo; i += 2) {
        int alto = valorHex(hex[i]);
        int bajo = valorHex(hex[i + 1]);
        if (alto < 0 || bajo < 0) {
            return fallar("Hay caracteres que no son hexadecimales.");
        }
        bytes[i / 2] = (unsigned char)(alto * 16 + bajo);
    }
    *cantidad = largo / 2;
    return 0;
}

/* Convierte bits a texto "0101..." agrupado de a 'grupo' bits, solo para
 * mostrar. 'salida' debe tener espacio de sobra (n + n / grupo + 1). */
static void bitsATexto(const int *bits, int n, int grupo, char *salida) {
    int pos = 0;
    for (int i = 0; i < n; i++) {
        if (i > 0 && i % grupo == 0) salida[pos++] = ' ';
        salida[pos++] = bits[i] ? '1' : '0';
    }
    salida[pos] = '\0';
}

/* Convierte bits a hexadecimal, solo para mostrar (requiere múltiplo de 4).
 * 'salida' debe tener espacio para n / 4 + 1 caracteres. */
static void bitsAHex(const int *bits, int n, char *salida) {
    const char *digitos = "0123456789ABCDEF";
    int pos = 0;
    for (int i = 0; i + 3 < n; i += 4) {
        int valor = bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3];
        salida[pos++] = digitos[valor];
    }
    salida[pos] = '\0';
}

/* ============================================================================
 *  OPERACIONES BÁSICAS SOBRE BITS
 * ============================================================================ */

/* Aplica una tabla de permutación (o de selección/expansión) a un conjunto de
 * bits. El resultado tiene tantos bits como números tenga la tabla.
 * La posición i del resultado es el bit "tabla[i]" de la entrada. */
static void permutar(const int *entrada, const int *tabla, int tamanoTabla, int *salida) {
    for (int i = 0; i < tamanoTabla; i++) {
        salida[i] = entrada[tabla[i] - 1];   /* -1 porque las tablas cuentan desde 1 */
    }
}

/* Rota los bits 'cantidad' posiciones a la izquierda (los que salen por la
 * izquierda vuelven a entrar por la derecha). Se hace en el mismo arreglo. */
static void rotarIzquierda(int *bits, int n, int cantidad) {
    int copia[64];   /* el arreglo más grande que se rota tiene 28 bits */
    for (int i = 0; i < n; i++) {
        copia[i] = bits[(i + cantidad) % n];
    }
    for (int i = 0; i < n; i++) {
        bits[i] = copia[i];
    }
}

/* XOR bit a bit entre dos arreglos del mismo tamaño. */
static void xorBits(const int *a, const int *b, int n, int *resultado) {
    for (int i = 0; i < n; i++) {
        resultado[i] = a[i] ^ b[i];
    }
}

/* ============================================================================
 *  GENERACIÓN DE LAS 16 SUBCLAVES
 * ============================================================================ */

/* A partir de la clave de 64 bits genera las 16 subclaves de 48 bits,
 * una para cada ronda. */
static void generarSubclaves(const int *clave64, int subclaves[16][48]) {
    char texto[128];
    char hex[16];
    int clave56[56];
    int C[28], D[28], CyD[56];

    /* Paso 1: PC-1 deja la clave en 56 bits (quita los bits de paridad). */
    permutar(clave64, PERMUTACION_PC1, 56, clave56);

    /* Paso 2: se parte en dos mitades de 28 bits, C (izquierda) y D (derecha). */
    memcpy(C, clave56, 28 * sizeof(int));
    memcpy(D, clave56 + 28, 28 * sizeof(int));

    if (modoDetallado) {
        bitsATexto(clave56, 56, 7, texto);
        printf("  Clave de 56 bits tras PC-1: %s\n", texto);
        bitsATexto(C, 28, 7, texto);
        printf("  C0 = %s\n", texto);
        bitsATexto(D, 28, 7, texto);
        printf("  D0 = %s\n", texto);
    }

    /* Paso 3: en cada ronda se rotan C y D, se juntan y se aplica PC-2. */
    for (int ronda = 0; ronda < 16; ronda++) {
        rotarIzquierda(C, 28, DESPLAZAMIENTOS[ronda]);
        rotarIzquierda(D, 28, DESPLAZAMIENTOS[ronda]);

        memcpy(CyD, C, 28 * sizeof(int));
        memcpy(CyD + 28, D, 28 * sizeof(int));
        permutar(CyD, PERMUTACION_PC2, 48, subclaves[ronda]);

        if (modoDetallado) {
            bitsATexto(subclaves[ronda], 48, 6, texto);
            bitsAHex(subclaves[ronda], 48, hex);
            printf("  K%d%s = %s  (hex %s)\n", ronda + 1, ronda + 1 < 10 ? " " : "", texto, hex);
        }
    }
}

/* ============================================================================
 *  FUNCIÓN DE FEISTEL f(R, K)
 * ============================================================================ */

 * Entra R de 32 bits y K de 48 bits; sale un resultado de 32 bits. */
static void funcionF(const int *R, const int *subclave, int *resultado) {
    int expandido[48];
    int mezclado[48];
    int salidaCajas[32];

    /* 1. Expansión: de 32 a 48 bits. */
    permutar(R, EXPANSION, 48, expandido);

    /* 2. XOR con la subclave de la ronda. */
    xorBits(expandido, subclave, 48, mezclado);

    /* 3. Cajas S: los 48 bits se parten en 8 grupos de 6 bits.
     *    En cada grupo, el primer y el último bit dan la FILA (0 a 3)
     *    y los 4 bits del medio dan la COLUMNA (0 a 15). */
    for (int caja = 0; caja < 8; caja++) {
        int inicio = caja * 6;
        int fila = mezclado[inicio] * 2 + mezclado[inicio + 5];
        int columna = mezclado[inicio + 1] * 8 + mezclado[inicio + 2] * 4
                    + mezclado[inicio + 3] * 2 + mezclado[inicio + 4];

        int valor = CAJAS_S[caja][fila][columna];   /* número de 0 a 15 */

        /* El valor se escribe en 4 bits. */
        salidaCajas[caja * 4]     = (valor >> 3) & 1;
        salidaCajas[caja * 4 + 1] = (valor >> 2) & 1;
        salidaCajas[caja * 4 + 2] = (valor >> 1) & 1;
        salidaCajas[caja * 4 + 3] = valor & 1;
    }

    /* 4. Permutación P sobre los 32 bits resultantes. */
    permutar(salidaCajas, PERMUTACION_P, 32, resultado);
}

/* ============================================================================
 *  PROCESAR UN BLOQUE DE 64 BITS (cifrar o descifrar)
 * ============================================================================ */

/* Cifrar y descifrar usan EXACTAMENTE el mismo procedimiento; la única
 * diferencia es el orden de las subclaves (descifrar usa K16, K15, ..., K1). */
static void procesarBloque(const int *bloque, int subclaves[16][48], int descifrar,
                           int *resultado) {
    int despuesDeIP[64];
    int L[32], R[32], nuevoR[32], f[32];
    int alReves[64];
    char hex1[32], hex2[32];

    /* Permutación inicial. */
    permutar(bloque, PERMUTACION_INICIAL, 64, despuesDeIP);

    /* Se parte en mitad izquierda (L) y derecha (R) de 32 bits. */
    memcpy(L, despuesDeIP, 32 * sizeof(int));
    memcpy(R, despuesDeIP + 32, 32 * sizeof(int));

    if (modoDetallado) {
        bitsAHex(despuesDeIP, 64, hex1);
        printf("  Despues de IP: %s\n", hex1);
        bitsAHex(L, 32, hex1);
        bitsAHex(R, 32, hex2);
        printf("  L0 = %s   R0 = %s\n", hex1, hex2);
    }

    /* 16 rondas de Feistel. */
    for (int ronda = 0; ronda < 16; ronda++) {
        /* Si se descifra, se recorren las subclaves al revés. */
        const int *subclave = descifrar ? subclaves[15 - ronda] : subclaves[ronda];

        /* R(i) = L(i-1) XOR f(R(i-1), K(i)) */
        funcionF(R, subclave, f);
        xorBits(L, f, 32, nuevoR);

        /* L(i) = R(i-1) */
        memcpy(L, R, 32 * sizeof(int));
        memcpy(R, nuevoR, 32 * sizeof(int));

        if (modoDetallado) {
            bitsAHex(L, 32, hex1);
            bitsAHex(R, 32, hex2);
            printf("  Ronda %d%s:  L = %s   R = %s\n", ronda + 1,
                   ronda + 1 < 10 ? " " : "", hex1, hex2);
        }
    }

    /* Después de la ronda 16 las mitades se intercambian: se une R16 con L16
     * (en ese orden) y se aplica la permutación final. */
    memcpy(alReves, R, 32 * sizeof(int));
    memcpy(alReves + 32, L, 32 * sizeof(int));
    permutar(alReves, PERMUTACION_FINAL, 64, resultado);

    if (modoDetallado) {
        bitsAHex(resultado, 64, hex1);
        printf("  Despues de IP^-1: %s\n", hex1);
    }
}

/* ============================================================================
 *  RELLENO (PADDING) Y MODO ECB PARA MENSAJES LARGOS
 * ============================================================================ */

/* DES trabaja con bloques de 8 bytes. Si el mensaje no es múltiplo de 8 se
 * rellena con el esquema PKCS#7: se agregan N bytes, cada uno con el valor N.
 * Si ya es múltiplo de 8 se agrega un bloque completo de relleno (valor 8).
 * 'datos' debe tener espacio para 8 bytes más. Devuelve el nuevo tamaño. */
static size_t agregarRelleno(unsigned char *datos, size_t cantidad) {
    int faltan = 8 - (int)(cantidad % 8);
    for (int i = 0; i < faltan; i++) {
        datos[cantidad + i] = (unsigned char)faltan;
    }
    return cantidad + faltan;
}

/* Calcula cuántos bytes quedan al quitar el relleno. Devuelve 1 (con mensaje)
 * si el relleno no es válido (por ejemplo, si la clave era incorrecta). */
static int quitarRelleno(const unsigned char *datos, size_t cantidad, size_t *nuevoTamano) {
    if (cantidad == 0 || cantidad % 8 != 0) {
        return fallar("El tamano de los datos no es multiplo de 8.");
    }
    int relleno = datos[cantidad - 1];
    if (relleno < 1 || relleno > 8 || (size_t)relleno > cantidad) {
        return fallar("Relleno invalido: probablemente la clave es incorrecta.");
    }
    for (int i = 0; i < relleno; i++) {
        if (datos[cantidad - 1 - i] != relleno) {
            return fallar("Relleno invalido: probablemente la clave es incorrecta.");
        }
    }
    *nuevoTamano = cantidad - relleno;
    return 0;
}

/* Cifra o descifra una lista de bytes completa en modo ECB: cada bloque de
 * 8 bytes se procesa por separado con la misma clave.
 * (La entrada debe ser múltiplo de 8 bytes; 'resultado' mide lo mismo.) */
static void procesarECB(const unsigned char *datos, size_t cantidad,
                        int subclaves[16][48], int descifrar, unsigned char *resultado) {
    int bloque[64], procesado[64];
    char hex[32];

    for (size_t i = 0; i < cantidad; i += 8) {
        bytesABits(datos + i, 8, bloque);

        if (modoDetallado) {
            bytesAHex(datos + i, 8, hex);
            printf("\n--- Bloque %zu (entrada: %s) ---\n", i / 8 + 1, hex);
        }

        procesarBloque(bloque, subclaves, descifrar, procesado);
        bitsABytes(procesado, 64, resultado + i);
    }
}

/* Prepara las subclaves a partir de la clave dada como 16 dígitos hexadecimales.
 * Devuelve 1 (con mensaje) si la clave no es válida. */
static int prepararClave(const char *claveHex, int subclaves[16][48]) {
    unsigned char bytesClave[8];
    size_t cantidad = 0;
    int clave64[64];

    if (strlen(claveHex) != 16) {
        return fallar("La clave debe tener exactamente 16 digitos hexadecimales (64 bits).");
    }
    if (hexABytes(claveHex, bytesClave, &cantidad)) return 1;
    bytesABits(bytesClave, 8, clave64);

    if (modoDetallado) {
        char texto[128];
        bitsATexto(clave64, 64, 8, texto);
        printf("\n=== Generacion de subclaves ===\n");
        printf("  Clave de 64 bits: %s\n", texto);
    }
    generarSubclaves(clave64, subclaves);
    return 0;
}

/* Cifra un texto. Si todo sale bien, 'salidaHex' apunta a una cadena nueva
 * (reservada con malloc) con el cifrado en hexadecimal; hay que liberarla
 * con free(). Devuelve 1 (con mensaje) si algo falla. */
static int cifrarTexto(const char *texto, const char *claveHex, char **salidaHex) {
    int subclaves[16][48];
    if (prepararClave(claveHex, subclaves)) return 1;

    size_t largo = strlen(texto);
    unsigned char *bytes = malloc(largo + 8);
    unsigned char *cifrado = malloc(largo + 8);
    char *hex = malloc((largo + 8) * 2 + 1);
    if (!bytes || !cifrado || !hex) {
        free(bytes); free(cifrado); free(hex);
        return fallar("No hay memoria suficiente.");
    }

    memcpy(bytes, texto, largo);
    size_t total = agregarRelleno(bytes, largo);
    procesarECB(bytes, total, subclaves, 0, cifrado);
    bytesAHex(cifrado, total, hex);

    free(bytes);
    free(cifrado);
    *salidaHex = hex;
    return 0;
}

/* Descifra un texto dado en hexadecimal. Si todo sale bien, 'salida' apunta a
 * una cadena nueva (malloc) con el mensaje original; hay que liberarla con
 * free(). Devuelve 1 (con mensaje) si algo falla. */
static int descifrarTexto(const char *cifradoHex, const char *claveHex, char **salida) {
    int subclaves[16][48];
    if (prepararClave(claveHex, subclaves)) return 1;

    size_t largoHex = strlen(cifradoHex);
    unsigned char *bytes = malloc(largoHex / 2 + 1);
    unsigned char *claro = malloc(largoHex / 2 + 1);
    if (!bytes || !claro) {
        free(bytes); free(claro);
        return fallar("No hay memoria suficiente.");
    }

    size_t cantidad = 0;
    if (hexABytes(cifradoHex, bytes, &cantidad)) {
        free(bytes); free(claro);
        return 1;
    }
    if (cantidad == 0 || cantidad % 8 != 0) {
        free(bytes); free(claro);
        return fallar("El texto cifrado debe ser multiplo de 16 digitos hexadecimales.");
    }

    procesarECB(bytes, cantidad, subclaves, 1, claro);

    size_t tamanoFinal = 0;
    if (quitarRelleno(claro, cantidad, &tamanoFinal)) {
        free(bytes); free(claro);
        return 1;
    }
    claro[tamanoFinal] = '\0';   /* cabe: tamanoFinal < cantidad */

    free(bytes);
    *salida = (char *)claro;
    return 0;
}

/* ============================================================================
 *  PRUEBA CON VECTORES CONOCIDOS
 * ============================================================================ */

/* Cifra o descifra un bloque suelto (sin relleno) dado en hexadecimal.
 * El resultado (16 dígitos hex + '\0') se escribe en 'salidaHex'. */
static int cifrarBloqueHex(const char *bloqueHex, const char *claveHex, int descifrar,
                           char *salidaHex) {
    int subclaves[16][48];
    unsigned char bytes[8];
    size_t cantidad = 0;
    int bloque[64], resultado[64];

    if (prepararClave(claveHex, subclaves)) return 1;
    if (hexABytes(bloqueHex, bytes, &cantidad)) return 1;
    bytesABits(bytes, 8, bloque);
    procesarBloque(bloque, subclaves, descifrar, resultado);
    bitsAHex(resultado, 64, salidaHex);
    return 0;
}

/* Comprueba la implementación con el ejemplo clásico de DES:
 *   clave   = 133457799BBCDFF1
 *   claro   = 0123456789ABCDEF
 *   cifrado = 85E813540F0AB405
 * Y con los vectores de los ejemplos NIST. Devuelve 1 si todo salió bien. */
static int ejecutarPruebas(void) {
    int detalleOriginal = modoDetallado;
    modoDetallado = 0;
    int todoBien = 1;

    static const char *casos[3][3] = {
        /* clave,              claro,              cifrado */
        {"133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"},
        {"0101010101010101", "8000000000000000", "95F8A5E5DD31D900"},
        {"0E329232EA6D0D73", "8787878787878787", "0000000000000000"}
    };

    for (int i = 0; i < 3; i++) {
        char obtenido[32] = "", vuelta[32] = "";
        cifrarBloqueHex(casos[i][1], casos[i][0], 0, obtenido);
        cifrarBloqueHex(casos[i][2], casos[i][0], 1, vuelta);
        int cifraOk = (strcmp(obtenido, casos[i][2]) == 0);
        int descifraOk = (strcmp(vuelta, casos[i][1]) == 0);

        printf("Prueba %d: clave %s, claro %s\n", i + 1, casos[i][0], casos[i][1]);
        printf("   esperado %s, obtenido %s%s\n", casos[i][2], obtenido,
               cifraOk ? "  [OK]" : "  [FALLO]");
        printf("   descifrado %s%s\n", vuelta, descifraOk ? "  [OK]" : "  [FALLO]");
        if (!cifraOk || !descifraOk) todoBien = 0;
    }

    modoDetallado = detalleOriginal;
    return todoBien;
}

/* ============================================================================
 *  PROGRAMA PRINCIPAL
 * ============================================================================ */

/* Lee una línea completa de la entrada, de cualquier largo, sin el salto de
 * línea final. Devuelve una cadena nueva (malloc) o NULL si no hay más
 * entrada (Ctrl+D). */
static char *leerLinea(void) {
    size_t capacidad = 128, largo = 0;
    char *linea = malloc(capacidad);
    if (!linea) return NULL;

    int c;
    while ((c = getchar()) != EOF && c != '\n') {
        if (largo + 1 >= capacidad) {
            capacidad *= 2;
            char *nueva = realloc(linea, capacidad);
            if (!nueva) { free(linea); return NULL; }
            linea = nueva;
        }
        linea[largo++] = (char)c;
    }
    if (c == EOF && largo == 0) {
        free(linea);
        return NULL;
    }
    linea[largo] = '\0';
    return linea;
}

/* Muestra una pregunta y devuelve lo que escribió el usuario (hay que
 * liberarlo con free). Devuelve NULL si se acabó la entrada. */
static char *preguntar(const char *pregunta) {
    printf("%s", pregunta);
    fflush(stdout);
    return leerLinea();
}

static void mostrarMenu(void) {
    printf("\n=========== DES - Criptografia ===========\n");
    printf(" 1. Cifrar un texto\n");
    printf(" 2. Descifrar un texto (hexadecimal)\n");
    printf(" 3. Verificar con vectores de prueba\n");
    printf(" 4. Modo detallado: %s (pulsa 4 para cambiar)\n",
           modoDetallado ? "ACTIVADO" : "DESACTIVADO");
    printf(" 5. Salir\n");
    printf("Opcion: ");
    fflush(stdout);
}

int main(void) {
    int opcion = 0;

    while (opcion != 5) {
        mostrarMenu();
        char *linea = leerLinea();
        if (!linea) break;                    /* fin de la entrada (Ctrl+D) */

        char *fin = NULL;
        opcion = (int)strtol(linea, &fin, 10);
        if (fin == linea) {                   /* no empezaba con un número */
            printf("Opcion no valida.\n");
            opcion = 0;
            free(linea);
            continue;
        }
        free(linea);

        if (opcion == 1) {
            char *texto = preguntar("Texto a cifrar: ");
            char *clave = texto ? preguntar("Clave (16 digitos hexadecimales): ") : NULL;
            if (texto && clave) {
                char *cifrado = NULL;
                if (cifrarTexto(texto, clave, &cifrado)) {
                    printf("Error: %s\n", mensajeError);
                } else {
                    printf("\nTexto cifrado (hex): %s\n", cifrado);
                    free(cifrado);
                }
            }
            free(texto);
            free(clave);

        } else if (opcion == 2) {
            char *cifrado = preguntar("Texto cifrado (hex): ");
            char *clave = cifrado ? preguntar("Clave (16 digitos hexadecimales): ") : NULL;
            if (cifrado && clave) {
                char *claro = NULL;
                if (descifrarTexto(cifrado, clave, &claro)) {
                    printf("Error: %s\n", mensajeError);
                } else {
                    printf("\nTexto descifrado: %s\n", claro);
                    free(claro);
                }
            }
            free(cifrado);
            free(clave);

        } else if (opcion == 3) {
            printf("\n");
            int bien = ejecutarPruebas();
            printf("%s\n", bien ? "\nTodas las pruebas pasaron." : "\nHAY PRUEBAS FALLIDAS.");

        } else if (opcion == 4) {
            modoDetallado = !modoDetallado;

        } else if (opcion != 5) {
            printf("Opcion no valida.\n");
        }
    }

    printf("Hasta luego.\n");
    return 0;
}

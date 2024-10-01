#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <string>
#include <algorithm>  // For reverse()

using namespace std;

// Function to convert __int128 to string
string int128_to_string(__int128 num) {
    if (num == 0) return "0";  // Edge case for zero
    bool is_negative = false;
    if (num < 0) {
        is_negative = true;
        num = -num;  // Make the number positive for easier handling
    }

    string result;
    while (num > 0) {
        result += (num % 10) + '0';  // Append the last digit to the string
        num /= 10;  // Remove the last digit
    }

    if (is_negative) {
        result += '-';  // Add negative sign if the number was negative
    }

    reverse(result.begin(), result.end());  // Reverse the string to get the correct order
    return result;
}

// Function to convert string to __int128
__int128 string_to_int128(const string& str) {
    __int128 result = 0;
    bool is_negative = false;
    size_t start = 0;

    if (str[0] == '-') {
        is_negative = true;
        start = 1;  // Skip the negative sign
    }

    for (size_t i = start; i < str.size(); ++i) {
        result = result * 10 + (str[i] - '0');  // Accumulate each digit
    }

    if (is_negative) {
        result = -result;  // Apply the negative sign if necessary
    }

    return result;
}

// RSA Class using __int128
class RSA {
public:
    __int128 publicKey;  // Public key (e)
    __int128 privateKey; // Private key (d)
    __int128 modulus;    // Modulus (n)

    RSA(__int128 p, __int128 q, __int128 e) {
        modulus = p * q;
        __int128 phi = (p - 1) * (q - 1);
        publicKey = e;
        privateKey = modInverse(e, phi);
    }

    // Encrypt Function
    __int128 encrypt(__int128 message) {
        return modExp(message, publicKey, modulus);
    }

    // Decrypt Function
    __int128 decrypt(__int128 ciphertext) {
        return modExp(ciphertext, privateKey, modulus);
    }

private:
    // Function to compute base^exp % mod efficiently
    __int128 modExp(__int128 base, __int128 exp, __int128 mod) {
        __int128 result = 1;
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = (result * base) % mod;
            }
            base = (base * base) % mod;
            exp /= 2;
        }
        return result;
    }

    // Extended Euclidean Algorithm to find modular inverse
    __int128 modInverse(__int128 a, __int128 m) {
        __int128 m0 = m, t, q;
        __int128 x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m, a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }
};

// Paillier Functions using __int128
bool is_prime(__int128 x) {
    if (x <= 1) return false;
    for (__int128 i = 2; i * i <= x; i++) {
        if (x % i == 0) return false;
    }
    return true;
}

// Computes the greatest common divisor
__int128 gcd(__int128 a, __int128 b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

// Modular exponentiation function
__int128 modExp(__int128 base, __int128 exp, __int128 mod) {
    __int128 result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

// Modular inverse using Extended Euclidean Algorithm
__int128 modInverse(__int128 a, __int128 mod) {
    __int128 m0 = mod, t, q;
    __int128 x0 = 0, x1 = 1;

    if (mod == 1)
        return 0;

    while (a > 1) {
        q = a / mod;
        t = mod;

        mod = a % mod, a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Perform L function: L(x) = (x - 1) / n
__int128 L(__int128 x, __int128 n) {
    return (x - 1) / n;
}

// Function to generate a random number coprime with n
__int128 generate_coprime(__int128 n) {
    random_device rd;
    mt19937_64 gen(rd());  // Use 64-bit generator for large numbers
    uniform_int_distribution<__int128> dist(1, n - 1);
    __int128 r;
    do {
        r = dist(gen);
    } while (gcd(r, n) != 1);
    return r;
}

// Encryption function
__int128 encrypt(__int128 m, __int128 r, __int128 n, __int128 g) {
    return (modExp(g, m, n * n) * modExp(r, n, n * n)) % (n * n);
}

// Decryption function
__int128 decrypt(__int128 c, __int128 n, __int128 lambda, __int128 mu) {
    __int128 L_val = L(modExp(c, lambda, n * n), n);
    return (L_val * mu) % n;
}

// Encode a message to handle negative values
__int128 encode_message(__int128 m, __int128 n) {
    if (m < 0) {
        return n + m;  // Convert negative to positive mod n
    }
    return m;
}

// Decode a decrypted value to handle negative values
__int128 decode_message(__int128 m, __int128 n) {
    if (m > n / 2) {
        return m - n;  // Convert back to negative
    }
    return m;
}

int main(int argc, char const *argv[]) {

    // Use __int128 for large numbers
    __int128 p = 10007;  // First prime
    __int128 q = 10009;  // Second prime
    int choice;
    
    while (choice != 3) {
        cout << "Choose an operation:" << endl;
        cout << "1. Homomorphic Addition (Paillier)" << endl;
        cout << "2. Homomorphic Multiplication (RSA)" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
        case 1: {
            // Paillier Homomorphic Addition
            __int128 n = p * q;
            __int128 lambda = (p - 1) * (q - 1);
            __int128 g = n + 1;  // Choose g = n + 1 for simplicity

            // Compute L(g^lambda mod n^2)
            __int128 L_val = L(modExp(g, lambda, n * n), n);
            __int128 mu = modInverse(L_val, n);

            if (mu == 0) {
                cerr << "Error: Modular inverse does not exist." << endl;
                return 1;
            }

            // Get input from user
            cout << "Enter the number of messages: ";
            int num_messages;
            cin >> num_messages;

            vector<__int128> messages;
            cout << "Enter " << num_messages << " messages (can be negative):" << endl;
            for (int i = 0; i < num_messages; ++i) {
                string input;
                cin >> input;
                messages.push_back(encode_message(string_to_int128(input), n));  // Encode and store
            }

            // Encrypt messages
            vector<__int128> encrypted_messages;
            for (size_t i = 0; i < messages.size(); ++i) {
                __int128 r = generate_coprime(n);
                encrypted_messages.push_back(encrypt(messages[i], r, n, g));
            }

            // Sum encrypted messages
            __int128 summed_ciphertext = 1;
            __int128 expected_sum = 0;
            if(n==1){
                summed_ciphertext = encrypted_messages[0];
                expected_sum += messages[0];
            }
            else{
                for (size_t i = 0; i < encrypted_messages.size(); i++) {
                    summed_ciphertext = (summed_ciphertext * encrypted_messages[i]) % (n * n);
                    expected_sum += messages[i];
                }
            }

            // Decrypt sum
            __int128 decrypted_sums = decode_message(decrypt(summed_ciphertext, n, lambda, mu),n);  // Decode the sum to handle negative

            for (int i = 0; i < messages.size() ; i++){
                cout << "Encrypted Data " << i << ": " << int128_to_string(encrypted_messages[i]) << endl;
            }
            cout << "Encrypted Result (Addition of ciphertexts): " << int128_to_string(summed_ciphertext) << endl;
            cout << "Decrypted Result (Addition of ciphertexts are decryption): " << int128_to_string(decrypted_sums) << endl;
            cout << "Expected Result: " << int128_to_string(expected_sum) << endl;

            // Verify results
            if (decrypted_sums != expected_sum) {
                cout << "Error in sum" << endl;
            } else {
                cout << "Homomorphic additions verified correctly!" << endl;
            }
            break;
        }
        case 2: {
            // RSA Homomorphic Multiplication
            __int128 p1 = 10000019;  // First prime
            __int128 q1 = 10000079;  // Second prime
            __int128 e = 10000103; // Public exponent
            RSA rsa(p1, q1, e);

            // Input original data
            string input1, input2;
            cout << "Enter the first plaintext (data1): ";
            cin >> input1;
            cout << "Enter the second plaintext (data2): ";
            cin >> input2;

            __int128 data1 = string_to_int128(input1);
            __int128 data2 = string_to_int128(input2);

            // Encrypt data
            vector<__int128> encryptedData;
            encryptedData.push_back(rsa.encrypt(data1));
            encryptedData.push_back(rsa.encrypt(data2));

            // Homomorphic multiplication
            __int128 encryptedResult = (encryptedData[0] * encryptedData[1]) % rsa.modulus;

            // Decrypt result
            __int128 decryptedResult = rsa.decrypt(encryptedResult);
            __int128 expectedResult = data1 * data2;

            cout << "Encrypted Data 1: " << int128_to_string(encryptedData[0]) << endl;
            cout << "Encrypted Data 2: " << int128_to_string(encryptedData[1]) << endl;
            cout << "Encrypted Result (Multiplication of ciphertexts): " << int128_to_string(encryptedResult) << endl;
            cout << "Decrypted Result (Multiplication of original data): " << int128_to_string(decryptedResult) << endl;
            cout << "Expected Result: " << int128_to_string(expectedResult) << endl;
            // Verify result
            if (decryptedResult == expectedResult) {

                cout << "Homomorphic property holds! Encrypted computation successful." << endl;
            } else {
                cout << "Error in homomorphic computation." << endl;
            }
            break;
        }
        case 3: {
            cout << "Thanks for using Homomorphic Encryption. Have a nice day!" << endl;
            break;
        }
        default: {
            cout << "Invalid choice! Please choose 1 or 2." << endl;
            break;
        }
        }
    }
    return 0;
}

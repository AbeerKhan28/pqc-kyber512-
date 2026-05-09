//in alice main.c
// ======================================================================
// ======================================================================
// SCIENTIFIC DFA SIMULATION (HAMMING DISTANCE)
// ======================================================================
// Helper to count differing bits between two 256-bit arrays
int calculate_hamming_distance(uint8_t *key_a, uint8_t *key_b) {
    int distance = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t xor_val = key_a[i] ^ key_b[i];
        while (xor_val > 0) {
            distance += xor_val & 1;
            xor_val >>= 1;
        }
    }
    return distance;
}

void run_dfa_test(uint8_t *ct) {
    uint8_t real_key[32];
    uint8_t faulty_key[32];

    printf("\n[*] Extracting Baseline (Real) Shared Secret...\n");
    decapsulate(&alice, ct, real_key); // Get the true key first

    printf("\n--- DFA HAMMING DISTANCE CSV START ---\n");
    printf("Fault_Index,Hamming_Distance\n");

    // Inject 100 different single-bit faults into the polynomial
    for (int i = 0; i < 100; i++) {
        int16_t original_val = alice.s[0][i];
        
        // Inject a 1-bit fault at coefficient 'i'
        alice.s[0][i] ^= 0x01; 

        // Run decapsulation with broken key
        decapsulate(&alice, ct, faulty_key);

        // Calculate bit difference
        int hd = calculate_hamming_distance(real_key, faulty_key);
        printf("%d,%d\n", i, hd);

        // Restore the key coefficient
        alice.s[0][i] = original_val;
    }
    printf("--- DFA HAMMING DISTANCE CSV END ---\n\n");
}

// in server recieve function
// 1. RUN THE DFA SIMULATION FIRST (For paper results)
        run_dfa_test(ct_buffer);

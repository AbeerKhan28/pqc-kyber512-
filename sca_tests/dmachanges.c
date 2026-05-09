//in alice main.c file

// ======================================================================
// DMA POWER MASKING SIMULATION (HAMMING WEIGHT MODEL)
// ======================================================================

// Helper: Calculate Hamming Weight (simulated power draw of 16-bit CPU math)
int get_hw_16(int16_t val) {
    int hw = 0;
    uint16_t uval = (uint16_t)val;
    while (uval > 0) { hw += uval & 1; uval >>= 1; }
    return hw;
}

// Helper: Calculate Hamming Weight of DMA traffic (32-bit random noise)
int get_hw_32(uint32_t val) {
    int hw = 0;
    while (val > 0) { hw += val & 1; val >>= 1; }
    return hw;
}

// Pseudo-random generator for the DMA noise simulation
uint32_t get_random_dma_word() {
    static uint32_t seed = 0x12345678;
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

void run_dma_power_masking_test() {
    printf("\n--- DMA POWER TRACE CSV START ---\n");
    printf("Clock_Cycle,Unmasked_Power,DMA_Noise,Masked_Power\n");

    // Simulate 256 clock cycles of the CPU processing the key polynomial
    for (int i = 0; i < 256; i++) {
        // 1. Base CPU Power (Signal: processing the secret key)
        int cpu_power = get_hw_16(alice.s[0][i]);

        // 2. DMA Power (Noise: moving random 32-bit words across the bus)
        int dma_power = get_hw_32(get_random_dma_word());

        // 3. Total Power Measured by the Attacker's Oscilloscope
        // Masked power is the CPU signal + the DMA noise
        int masked_power = cpu_power + dma_power;

        printf("%d,%d,%d,%d\n", i, cpu_power, dma_power, masked_power);
    }
    printf("--- DMA POWER TRACE CSV END ---\n\n");
}


//before dma power masking add
 run_dma_power_masking_test();

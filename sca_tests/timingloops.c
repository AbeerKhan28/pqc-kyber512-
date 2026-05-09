// Replace in alice main file for keygen and decapsulation
// 2. Generate the Kyber Matrices (Benchmarking Loop)
    int NUM_TESTS = 10000;
    printf("\n[*] Generating Kyber512 Matrices & Running %d loops...\n", NUM_TESTS);
    printf("--- KEYGEN TIME DATA (us) ---\n");
    
    for(int i = 0; i < NUM_TESTS; i++) {
        absolute_time_t kg_start = get_absolute_time(); 
        
        keygen(&alice);
        
        absolute_time_t kg_end = get_absolute_time();
        int64_t keygen_time = absolute_time_diff_us(kg_start, kg_end);
        
        // Print directly to serial monitor, avoiding array RAM limits
        printf("%lld\n", keygen_time);
    }
    printf("------------------------------------\n");

    pack_public_key();
    printf("[+] Keygen complete. Packed size: %d bytes\n", sizeof(pk_buffer));




// START OF 100-LOOP TIMING TEST 
            // ==========================================================
            int NUM_TESTS = 10000;
            uint8_t temp_recovered_key[32]; // Temp buffer to not ruin the real key
            
            printf("\n[+] Full Ciphertext received!\n");
            printf("[*] Running %d Decapsulation loops for performance plotting...\n", NUM_TESTS);

            dma_start_power_masking(); // Keep SCA defense on for accurate timings

            for(int i = 0; i < NUM_TESTS; i++) {
                absolute_time_t loop_start = get_absolute_time(); 
                
                // Math isolated from Wi-Fi lag
                decapsulate(&alice, ct_buffer, temp_recovered_key);      
                
                absolute_time_t loop_end = get_absolute_time();
                int64_t decap_time =absolute_time_diff_us(loop_start, loop_end);
                // Print directly to serial monitor
                printf("%lld\n", decap_time);

            }
            dma_stop_power_masking();
   
// replace in bob main file for encapsulation
 //   ==========================================================
        // START OF 100-LOOP TIMING TEST FOR REPORT
        // ==========================================================
        int NUM_TESTS = 10000;
        uint8_t temp_ct_buffer[768];      // Temp buffer to not ruin the real packet
        uint8_t temp_shared_secret[32];   // Temp buffer to not ruin the real key
        
        printf("[*] Running %d Encapsulation loops for performance plotting...\n", NUM_TESTS);

        // Turn on hardware masking during test for accurate real-world SCA latency
        dma_start_power_masking(); 

        for(int i = 0; i < NUM_TESTS; i++) {
            absolute_time_t loop_start = get_absolute_time();
            
            // Math isolated from Wi-Fi lag
            encapsulate(&alice_public, temp_ct_buffer, temp_shared_secret);
            
            absolute_time_t loop_end = get_absolute_time();
            int64_t encap_time = absolute_time_diff_us(loop_start, loop_end);

            // Print directly to serial monitor
            printf("%lld\n", encap_time);
        }

          dma_stop_power_masking();
        printf("------------------------------------\n");

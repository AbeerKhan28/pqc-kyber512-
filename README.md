# pqc-kyber512-
Resource-Efficient ML-KEM-512 (Kyber-512) implementation on Raspberry Pi Pico 2 W 
This repository contains a high-performance, bare-metal implementation of the ML-KEM-512 (Kyber-512) Post-Quantum Cryptographic (PQC) algorithm, specifically optimized for the Raspberry Pi Pico 2 W (ARM Cortex-M33).The project demonstrates a secure, quantum-resistant key exchange between two networked IoT nodes (Alice and Bob) over Wi-Fi, utilizing a custom DMA-based power masking defense to mitigate Side-Channel Attacks (SCA).

🚀 Key Features

Quantum-Resistant: Full implementation of ML-KEM-512 (Standardized by NIST FIPS 203).
Networked IoT: Real-time key exchange via TCP/IP using the lwIP stack and cyw43 Wi-Fi firmware.
Physical Security: Integrated DMA-based noise generation to mask CPU power signatures during sensitive polynomial operations.

📂 File Structure

main(alice).c : TCP Server role. Handles KeyGen, sends Public Key, and receives Ciphertext.
main(bob).c :TCP Client role. Receives Public Key, performs Encapsulation, and sends Ciphertext.
kyber.c /.h :Core ML-KEM-512 logic (KeyGen, Encaps, Decaps).
aes.c /.h : AES-256 implementation for post-handshake secure data streaming.
ntt.c /.h : Optimized Number Theoretic Transform (NTT) for fast polynomial multiplication.
dmautils.c /.h : Hardware-level DMA configurations for power masking.
mathutils.c /.h : Mathematical helper functions.
fips202.c /.h : SHA-3 and SHAKE functions required for Kyber hashing and pseudorandomness.
lwipopts.h : Optimized configuration for the LwIP network stack on the RP2350.


🛠️ Hardware: 2x Raspberry Pi Pico 2 W.
🛠️ Software: Raspberry Pi Pico SDK.
              ARM GCC Toolchain
Build Instructions: 
Initialize the Pico SDK environment.
Update WIFI_SSID and WIFI_PASSWORD in the main files.
Build the project:
      Bash : mkdir build && cd build
             cmake  
             mingw32-make
Flash alice.uf2 to the Server Pico and bob.uf2 to the Client Pico.

📊 Results:
Our implementation was profiled over 10,000 iterations to ensure statistical precision.
              Operation Execution Time (ms)  CPU Clock Cycles
Key Generation         8.10 ms                  1,215,225
Encapsulation          7.40 ms                  1,111,740
Decapsulation          10.10 ms                 1,522,170

🛡️ Advanced Security Testing
For researchers interested in verifying the Side-Channel resistance, we have provided separate Testing Files ,the code is not enabled by default to keep the production code clean.

1. Side-Channel Power Masking (dmachanges.c)
This module simulates Power Analysis protection using DMA-based noise injection.
Purpose: Evaluates how background DMA bus traffic can mask the CPU's power signature during secret key processing.
How to enable:
     1.  Copy the helper functions from dmachanges.c into main.c
     2.  Call run_dma_power_masking_test() inside the main loop after keygen.
  
2. Differential Fault Analysis (DFA) (dfaa.c)
This test simulates hardware "glitching" or bit-flips in the secret key stored in RAM.
Purpose: Measures the Hamming Distance between a legitimate shared secret and a secret generated while the private key is under a fault attack.
How to enable:
     1.  Paste the DFA logic into Alice's main.c
     2.  Invoke run_dfa_test(ct_buffer) after the ciphertext has been received but before the final decapsulation.

3. TVLA (Test Vector Leakage Assessment)
This follows the "Welch’s T-Test" methodology to determine if the device's power consumption leaks information about the secret key.
Bob:  Configured as a remote attacker utilizing the Wi-Fi TCP/IP layer.  An automated high-speed loop of attacks was run by the remote adversary. This included 100 valid Class A ciphertexts and 100 corrupted Class B ciphertexts transmitted to the RP2350 server. The adversary records the Round-Trip Time (RTT) of each interaction using the onboard hardware timer.
How to enable:
   1.Replace main files of both client and server with the given files.


Stability Benchmarking (timeloopscode.txt)
Used to generate the data for the 10,000-iteration stability graphs.
Purpose: Records high-resolution timing data to verify the constant-time nature of the implementation.
How to enable: 
    1.  Replace the standard keygen or decapsulate calls in main.c with these timed loops.
    2.  The output is formatted as a raw CSV-ready stream for Serial Plotters.

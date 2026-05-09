#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "kyber.h"
#include "dma_utils.h"
#include "math_utils.h"
#include "aes.h"
#include "ntt.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "fips202.h"

// ======================================================================
// 1. WI-FI & ALICE'S CREDENTIALS
// ======================================================================
#define WIFI_SSID "----"
#define WIFI_PASSWORD "----" 
#define ALICE_IP "192.168.1.17"
#define TCP_PORT 4444

// ======================================================================
// 2. GLOBAL VARIABLES
// ======================================================================
uint8_t pk_buffer[3072]; // Holds Alice's Matrix A (2048) + Vector t (1024)
uint8_t ct_buffer[1536]; // Holds Bob's Vector u (1024) + Vector v (512)
int pk_bytes_received = 0;

uint8_t shared_key_bob[32]; // The final quantum-proof key
kyber_keypair alice_public; // We only fill the A and t parts!

 // --- NEW TVLA ATTACK VARIABLES ---
#define NUM_NETWORK_TRACES 100
int64_t rtt_valid[NUM_NETWORK_TRACES];
int64_t rtt_corrupt[NUM_NETWORK_TRACES];

volatile bool ready_for_attack = false;
volatile bool alice_responded = false;
struct tcp_pcb *global_tpcb = NULL; // We need this to send data from main()
// ---------------------------------

// ======================================================================
// 3. TCP CALLBACKS (Event-Driven Networking)
// ======================================================================


// ======================================================================
// TVLA REMOTE NETWORK TIMING ATTACK
// ======================================================================
void run_remote_network_timing_attack() {
    printf("\n======================================================\n");
    printf("[*] INITIATING TVLA REMOTE NETWORK TIMING ATTACK...\n");
    printf("======================================================\n");

    // ---------------------------------------------------------
    // 1. Collect Valid Traces
    // ---------------------------------------------------------
    printf("[*] Sending %d Valid Ciphertexts...\n", NUM_NETWORK_TRACES);
    for(int i = 0; i < NUM_NETWORK_TRACES; i++) {
        // Generate a mathematically perfect key/ciphertext pair
        encapsulate(&alice_public, ct_buffer, shared_key_bob);
        
        alice_responded = false; // Reset the flag
        absolute_time_t t_start = get_absolute_time(); // START STOPWATCH
        
        // Fire it over Wi-Fi
        tcp_write(global_tpcb, ct_buffer, 1536, TCP_WRITE_FLAG_COPY);
        tcp_output(global_tpcb);
        
        // Block and wait for Alice's network response
        while(!alice_responded) {
            cyw43_arch_poll(); // Keep the Wi-Fi chip breathing while we wait
            sleep_us(50); 
        }
        
        absolute_time_t t_end = get_absolute_time(); // STOP STOPWATCH
        rtt_valid[i] = absolute_time_diff_us(t_start, t_end);
        
        // Give the network a millisecond to breathe before the next attack
        sleep_ms(2); 
    }

    // ---------------------------------------------------------
    // 2. Collect Corrupt Traces
    // ---------------------------------------------------------
    printf("[*] Sending %d Corrupted Ciphertexts...\n", NUM_NETWORK_TRACES);
    for(int i = 0; i < NUM_NETWORK_TRACES; i++) {
        // Generate a valid key/ciphertext pair...
        encapsulate(&alice_public, ct_buffer, shared_key_bob);
        
        // ...then intentionally break the first byte to trigger Alice's Implicit Rejection!
        ct_buffer[0] ^= 0x01; 
        
        alice_responded = false;
        absolute_time_t t_start = get_absolute_time(); // START STOPWATCH
        
        tcp_write(global_tpcb, ct_buffer, 1536, TCP_WRITE_FLAG_COPY);
        tcp_output(global_tpcb);
        
        while(!alice_responded) {
            cyw43_arch_poll();
            sleep_us(50); 
        }
        
        absolute_time_t t_end = get_absolute_time(); // STOP STOPWATCH
        rtt_corrupt[i] = absolute_time_diff_us(t_start, t_end);
        
        sleep_ms(2);
    }

    // ---------------------------------------------------------
    // 3. Exporting Data
    // ---------------------------------------------------------
    printf("\n[+] ATTACK COMPLETE!\n");
    printf("VALID_RTT_US,CORRUPT_RTT_US\n");
    for(int i = 0; i < NUM_NETWORK_TRACES; i++) {
        // We print them side-by-side
        printf("%lld,%lld\n", rtt_valid[i], rtt_corrupt[i]); 
    }
    printf("\n======================================================\n");
}


// This runs when Alice sends us her Public Key
// ======================================================================
// 3. TCP CLIENT CALLBACKS
// ======================================================================
// ======================================================================
// HELPER: UNPACK ALICE'S PUBLIC KEY
// ======================================================================
void unpack_public_key() {
    // Matrix A is 2048 bytes, Vector t is 1024 bytes (Total 3072)
    memcpy(alice_public.A, pk_buffer, 2048);
    memcpy(alice_public.t, pk_buffer + 2048, 1024);
    printf("[+] Public Key successfully loaded into memory!\n");
}

err_t client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (!p) {
        printf("[-] Alice closed the connection.\n");
        return ERR_OK;
    }

    if (pk_bytes_received < 3072) {
        memcpy(pk_buffer + pk_bytes_received, p->payload, p->len);
        pk_bytes_received += p->len;
        tcp_recved(tpcb, p->len);

        if (pk_bytes_received == 3072) {
            printf("[*] Received Public Key from Alice! Unpacking...\n");
            unpack_public_key();
            
            // Tell main() to launch the attack!
            ready_for_attack = true; 
            
            // Increment to prevent this block from running again
            pk_bytes_received++; 
        }
    } else if (pk_bytes_received > 3072) {
        // This catches Alice's ACK replies during the attack loop
        // It tells the microsecond stopwatch in main() to stop!
        alice_responded = true; 
        tcp_recved(tpcb, p->len);
    }

    pbuf_free(p);
    return ERR_OK;
}
        
// This runs when we successfully connect to Alice
err_t client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    if (err == ERR_OK) {
        printf("[+] Connected to Alice! Waiting for her Public Key...\n");
        tcp_recv(tpcb, client_recv);
    } else {
        printf("[-] Failed to connect to Alice.\n");
    }
    global_tpcb = tpcb;
    return err;
}

// ======================================================================
// 4. MAIN SETUP
// ======================================================================
// ======================================================================
// 4. MAIN SETUP
// ======================================================================
int main() {
    stdio_init_all();
    sleep_ms(3000); 
    printf("\n=== Bob (Kyber512 TVLA Attacker) Booting ===\n");

    dma_copy_init();
    init_ntt();

    // 1. Connect to Wi-Fi
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_WORLDWIDE)) {
        printf("[-] Wi-Fi init failed\n");
        return -1;
    }
    cyw43_arch_enable_sta_mode();
    printf("[*] Connecting to %s...\n", WIFI_SSID);
    
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("[-] Failed to connect.\n");
        return -1;
    }
    printf("[+] Connected! Bob's IP: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

    // 2. Connect to Alice
    ip_addr_t alice_ipaddr;
    ipaddr_aton(ALICE_IP, &alice_ipaddr);

    struct tcp_pcb *pcb = tcp_new();
    global_tpcb = pcb; // Catch the connection block for the attack loop!
    
    printf("[*] Reaching out to Alice at %s:%d...\n", ALICE_IP, TCP_PORT);
    tcp_connect(pcb, &alice_ipaddr, TCP_PORT, client_connected);

    printf("[*] Waiting for Alice to send her Public Key...\n");

    // 3. Block safely until the public key is received and unpacked
    while (!ready_for_attack) {
        cyw43_arch_poll();
        sleep_ms(10);
    }

    // 4. Launch the Standardized TVLA Attack!
    run_remote_network_timing_attack();

    // 5. Attack complete. Enter an empty idle loop.
    printf("[+] TVLA Network Attack finished. Idling...\n");
    while (1) {
        cyw43_arch_poll();
        sleep_ms(1000);
    }
}

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
#include "power_spy.h"

// ======================================================================
// 1. WI-FI CREDENTIALS
// ======================================================================
#define WIFI_SSID "----"
#define WIFI_PASSWORD "----"
#define TCP_PORT 4444

// ======================================================================
// 2. GLOBAL VARIABLES
// ======================================================================
int session_state = 0; // 0 = Kyber Handshake, 1 = Secure AES Stream
kyber_keypair alice;

uint8_t pk_buffer[3072]; // Holds Matrix A (2048) + Vector t (1024)
uint8_t ct_buffer[2000]; // Holds Bob's Vector u (1024) + Vector v (512)
int ct_bytes_received = 0;

uint8_t shared_key_alice[32]; // The final quantum-proof key

// ======================================================================
// 3. PACKING / UNPACKING HELPERS
// ======================================================================
// Flattens Alice's arrays into a single byte buffer to send over Wi-Fi
void pack_public_key() {
    int offset = 0;
    // Pack Matrix A (2x2x256 * 2 bytes = 2048 bytes)
    memcpy(&pk_buffer[offset], alice.A, sizeof(alice.A));
    offset += sizeof(alice.A);
    // Pack Vector t (2x256 * 2 bytes = 1024 bytes)
    memcpy(&pk_buffer[offset], alice.t, sizeof(alice.t));
}

// ======================================================================
// 4. TCP CALLBACKS (Event-Driven Networking)
// ======================================================================

// This runs when Bob sends us data
// ======================================================================
// 3. TCP SERVER CALLBACKS (MODIFIED FOR TVLA ORACLE MODE)
// ======================================================================
err_t server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (!p) {
        printf("[-] Bob disconnected.\n");
        return ERR_OK;
    }

    if (session_state == 0) {
        // We are in the Kyber Handshake Phase (Acting as a TVLA Oracle)
        memcpy(ct_buffer + ct_bytes_received, p->payload, p->len);
        ct_bytes_received += p->len;
        tcp_recved(tpcb, p->len);

        if (ct_bytes_received >= 1536) { // FULL CIPHERTEXT RECEIVED!
            printf("\n[*] Received 1536-byte Ciphertext from Bob!\n");
            printf("[*] Decapsulating...\n");

            // 1. Run Decapsulation!
            absolute_time_t start_time = get_absolute_time();
            decapsulate(&alice, ct_buffer, shared_key_alice);
            absolute_time_t end_time = get_absolute_time();
            
            uint64_t decaps_time = absolute_time_diff_us(start_time, end_time);
            printf("[+] Decapsulation complete in %llu us!\n", decaps_time);

            // 2. Send Reply (Bob needs this to stop his microsecond timer)
            char reply_buffer[128];
            sprintf(reply_buffer, "[ALICE-ACK] Kyber Handshake Complete! Key established in %llu us.\n", decaps_time);
            uint16_t reply_len = strlen(reply_buffer);

            tcp_write(tpcb, reply_buffer, reply_len, TCP_WRITE_FLAG_COPY);
            tcp_output(tpcb);

        }
    } else if (session_state == 1) {
        // We are in AES Secure Chat mode
        // (This block will be ignored during the TVLA testing phase)
        printf("\n[AES-CHAT] Bob says: %s\n", (char *)p->payload);
        tcp_recved(tpcb, p->len);
    }

    pbuf_free(p);
    return ERR_OK;
}

// This runs when Bob initially connects to us
err_t server_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    printf("\n[+] Bob connected! Sending Kyber512 Public Key...\n");
    
    // Set up the receive callback
    tcp_recv(newpcb, server_recv);
    
    // Send the 3,072 bytes (Matrix A + Vector t)
    err_t write_err = tcp_write(newpcb, pk_buffer, sizeof(pk_buffer), 0);
    tcp_output(newpcb); // Push the data out immediately
    
    if(write_err == ERR_OK) {
        printf("[+] Public Key sent over Wi-Fi successfully!\n");
    } else {
        printf("[-] Error sending public key.\n");
    }
    return ERR_OK;
}

// ======================================================================
// 5. MAIN SETUP
// ======================================================================
int main() {
    stdio_init_all();
    sleep_ms(3000); // Wait for serial
    printf("\n=== Alice (Kyber512 TCP Server) Booting ===\n");

    // Initialize DMA and NTT Math Arrays
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
    
    // Print Alice's IP Address
    printf("[+] Connected! Alice's IP: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

    // 2. Generate the Kyber Matrices (Only need to do this once for the server demo)
    printf("[*] Generating Kyber512 Matrices...\n");
    keygen(&alice);

    pack_public_key();
    printf("[+] Keygen complete. Packed size: %d bytes\n", sizeof(pk_buffer));
   

    // 3. Setup TCP Server on Port 4444
    struct tcp_pcb *pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, TCP_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, server_accept);
    
    printf("[+] Alice is listening on port %d... Waiting for Bob.\n", TCP_PORT);

    // 4. Background Wi-Fi loop
    while (1) {
        cyw43_arch_poll(); // Keep Wi-Fi alive
        sleep_ms(1);
    }

    return 0;
}


// Inclusione di header per funzionalità BPF
#include <uapi/linux/bpf.h>

// Inclusione di header per le strutture Ethernet
#include <uapi/linux/if_ether.h>

// Inclusione di header per le strutture dei pacchetti
#include <uapi/linux/if_packet.h>

// Inclusione di header per le strutture IP
#include <uapi/linux/ip.h>

// Inclusione di header per le funzioni di byte order di rete
#include <linux/in.h>

// Inclusione di funzioni di supporto per programmi BPF
#include <bcc/helpers.h>

// Definizione di una mappa per memorizzare il conteggio dei pacchetti (1 elemento)
BPF_ARRAY(packet_count_map, __u64, 1);

static int drop_packet_to_destination(struct xdp_md *ctx, __be32 blocked_ip) {
  // Estrazione dei limiti dei dati del pacchetto
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Accesso all'header Ethernet
  struct ethhdr *eth = data;

  // Validazione dell'header Ethernet
  if ((void *)(eth + 1) > data_end) {
    // L'header si estende oltre i dati del pacchetto, passa
    return XDP_PASS;
  }

  // Controllo per pacchetti IP
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // Non è un pacchetto IP, passa
    return XDP_PASS;
  }

  // Accesso all'header IP
  struct iphdr *iph = (struct iphdr *)(data + ETH_HLEN);

  // Validazione dell'header IP
  if ((void *)(iph + 1) > data_end) {
    // L'header si estende oltre i dati del pacchetto, passa
    return XDP_PASS;
  }

  // Controllo se l'IP di destinazione coincide con l'IP bloccato
  if (iph->saddr == blocked_ip) {
    // Droppa il pacchetto
    return XDP_DROP;
  }

  // In caso contrario, passa il pacchetto
  return XDP_PASS;
}

int xdp_packet_counter(struct xdp_md *ctx) {
  // Accesso alla mappa del conteggio pacchetti
  __u32 key = 0;
  __u64 *counter;

  // Ricerca del valore del contatore
  counter = packet_count_map.lookup(&key);
  if (!counter) {
    // Lookup della mappa fallito, aborto
    return XDP_ABORTED;
  }

  // Incremento atomico del contatore
  __sync_fetch_and_add(counter, 1);

  // Droppa i pacchetti destinati all'IP 8.8.8.8
  __be32 blocked_ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
  return drop_packet_to_destination(ctx, blocked_ip);
}

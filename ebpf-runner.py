# Importa librerie necessarie
from bcc import BPF  # Importa BPF per caricare e gestire programmi eBPF
from time import sleep  # Importa la funzione sleep per attendere tra le letture
from pathlib import Path  # Importa Path per manipolare percorsi file
import signal  # Importa il modulo per la gestione dei segnali


class TerminateSignal(Exception):
    """
    Classe di eccezione utilizzata per gestire il segnale SIGTERM
    """
    pass


# Gestore del segnale per SIGTERM
def handle_sigterm(signum, frame):
    """
    Funzione eseguita alla ricezione del segnale SIGTERM.
    Solleva un'eccezione TerminateSignal per terminare lo script.
    """
    raise TerminateSignal("Ricevuto SIGTERM, terminazione in corso...")


# Carica e compila il programma eBPF dal file sorgente
def load_bpf_program():
    """
    Carica il codice sorgente eBPF dal file specificato e lo compila
    utilizzando BPF. Restituisce l'oggetto BPF compilato.
    """
    bpf_source = Path('ebpf-probe.c').read_text()  # Legge il codice sorgente eBPF
    bpf = BPF(text=bpf_source)  # Compila il codice sorgente in un oggetto BPF
    return bpf


# Associa il programma eBPF all'interfaccia di rete specificata
def attach_xdp_program(bpf, interface):
    """
    Associa la funzione xdp_packet_counter del programma eBPF all'interfaccia
    di rete specificata utilizzando la funzione attach_xdp di BPF. Restituisce
    l'oggetto BPF modificato.
    """
    xdp_fn = bpf.load_func("xdp_packet_counter", BPF.XDP)  # Carica la funzione xdp_packet_counter
    bpf.attach_xdp(interface, xdp_fn, 0)  # Associa la funzione all'interfaccia
    return bpf


# Rimuove il programma eBPF dall'interfaccia di rete specificata
def detach_xdp_program(bpf, interface):
    """
    Rimuovela la funzione eBPF associata all'interfaccia utilizzando la funzione
    remove_xdp di BPF.
    """
    bpf.remove_xdp(interface, 0)


# Funzione principale dello script
def main():
    """
    Funzione principale che esegue lo script.
    """
    # Registra il gestore del segnale per SIGTERM
    signal.signal(signal.SIGTERM, handle_sigterm)

    # Definisce l'interfaccia di rete da monitorare
    INTERFACE = "ens18"

    # Carica il programma eBPF e lo associa all'interfaccia
    bpf = load_bpf_program()
    attach_xdp_program(bpf, INTERFACE)

    # Recupera la mappa packet_count_map definita nel programma eBPF
    packet_count_map = bpf.get_table("packet_count_map")  # Recupera la mappa

    try:
        print("Conteggio pacchetti in corso, premi Ctrl+C per interrompere...")
        prev_total_packets = 0  # Conteggio pacchetti precedente
        while True:
            # Attendi 1 secondo prima di ricontrollare il conteggio dei pacchetti
            sleep(1)
            total_packets = 0  # Conteggio pacchetti attuale

            # Itera sulle chiavi della mappa e somma i valori dei contatori
            for key in packet_count_map.keys():
                counter = packet_count_map[key]
                if counter:
                    total_packets += counter.value  # Somma il valore del contatore

            # Calcola il numero di pacchetti ricevuti al secondo
            packets_per_second = total_packets - prev_total_packets
            prev_total_packets = total_packets
            print(f"Pacchetti per secondo: {packets_per_second}")

    except (KeyboardInterrupt, TerminateSignal) as e:
        print(f"{e}. Interruzione esecuzione eBPF.")

    finally:
        print("Rimozione programma eBPF e chiusura script.")
        # Rimuove il programma eBPF dall'interfaccia e pulisce le risorse
        detach_xdp_program(bpf, INTERFACE)


# Esegue la funzione principale quando lo script viene eseguito direttamente
if __name__ == "__main__":
    main()

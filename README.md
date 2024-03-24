# eBPF-XDP
Implementazione di un mini basico Firewall in eBPF XDR

Come prima operazione del Firewall è quella di bloccare un indirizzo IP specifico, nel nostro esempio useremo l'indirizzo IP 8.8.8.8 . Successivamente nei prossimi articoli faremo in modo che si passi una lista di indirizzi IP da bloccare in tempo reale.
ATTENZIONE!! Per riprodurre quanto andrò a spiegare , dovete avere un sistema operativo aggiornato, dove siete amministratori quindi collegarsi con i poteri di "root" . Molti punti verranno saltati per scelta di praticità dell'articolo, qualora vi occorre ulteriori informazioni, basta commentare e spiegare cosa non vi è chiaro.

Ecosistema su cui sto eseguendo il codice :

Distributor ID: Ubuntu
Description: Ubuntu 22.04.4 LTS
Release: 22.04
Codename: jammy

Comandi eseguiti dopo una pulita installazione di Ubuntu 22.04 : 

sudo apt-get update
sudo apt-get upgrade
sudo reboot
sudo apt --purge autoremove
sudo apt-get dist-upgrade

Ora passiamo a installare l'ecosistema eBPF e BCC 
sudo apt-get install bpfcc-tools libbpfcc-dev
sudo apt-get install python3-venv

Eseguiamo i seguenti comandi 
python3 -m venv venv
source venv/bin/activate

Continuiamo a installare i seguenti pacchetti
sudo apt install build-essential libncurses5-dev bison flex libssl-dev libelf-dev bin86

sudo apt install clang llvm libcap-dev binutils-dev libreadline-dev gcc-multilib 

sudo apt install linux-source
sudo apt install linux-tools-common
sudo apt install linux-tools-generic linux-cloud-tools-generic 

Creiamo una cartella e scarichiamo i seguenti due file, che servirannno più avanti nel progetto.

wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
./ecli -h

wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
./ecc -h

./ecc ebpf-probe.c
sudo ./ecli run package.json 


Fonti 

https://play.instruqt.com/embed/isovalent/tracks/ebpf-tutorial/challenges/xdp/assignment#tab-2

https://github.com/eunomia-bpf/bpf-developer-tutorial

https://github.com/zoidyzoidzoid/awesome-ebpf

https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

https://github.com/politepixels/code-examples/tree/master/building-first-ebpf-app
https://www.bilibili.com/video/BV1f54y1h74r/?spm_id_from=333.999.0.0 

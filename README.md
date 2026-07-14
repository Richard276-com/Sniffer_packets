Sniffer Packets

Progetto didattico in Python per catturare e visualizzare pacchetti di rete.

Struttura
Sniffer_packets/
├── Linux_Fedora/
│   ├── sniffer_code.py
│   ├── sniffer_tui.py
│   └── sniffer_ui_2.py
├── Windows/
│   └── sniffer_ui_3.py
└── README.md
sniffer_code.py: versione base da terminale per Fedora Linux.
sniffer_tui.py: interfaccia realizzata con Tkinter per Fedora Linux.
sniffer_ui_2.py: interfaccia grafica realizzata con PySide6 per Fedora Linux.
sniffer_ui_3.py: versione destinata a Windows.
Fedora Linux

Installa Python, Tkinter e le dipendenze grafiche:

sudo dnf install python3 python3-pip python3-tkinter mesa-libEGL mesa-libGL libxkbcommon-x11
python3 -m pip install --user PySide6

Avvia la versione PySide6:

sudo python3 Linux_Fedora/sniffer_ui_2.py

In alternativa, avvia la versione Tkinter:

sudo python3 Linux_Fedora/sniffer_tui.py
Windows

Installa PyQt5:

py -m pip install PyQt5

Il file della versione Windows si trova in:

Windows/sniffer_ui_3.py
Nota

La cattura dei pacchetti richiede privilegi amministrativi. Usa il programma esclusivamente su reti e dispositivi per i quali hai l’autorizzazione.

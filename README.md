NIDS Platform unifying individual protocol anomaly detectors

Command to run the platform (run from outside the nids_platform directory):
python -m nids_platform.main    

Command to run all tests:
pytest -v tests/*.py

requirements:
scapy
pytest

Note:
Unknown packets have been removed from output logs temporarily.
Uncomment lines 66-69 in routing/router.py to add logs of unknown packets to output.

Run validation_packets.py along with the main module to verify the capture and classification. 
Currently support for ARP, BGP, STP and LLDP packets is available.

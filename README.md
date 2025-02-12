Instructions:

Run [main.py](./main.py) file in the terminal of the node (master, or remote) that has the permissions to access the Kubernetes cluster.

Arguments for main.py:

  - `--include-auto`: To remediate all automated controls
  - `--include-all`: To remediate all automated controls and provide instructions for manual controls
  - `--exempt`: To exclude certain controls from automatic remediation.

# distrib_block_crypto: BLOCKCHAIN COMMUNICATION LIBRARY DEMO
This repository contains the code used for the work presented in the paper "Blockchain Cryptographic Framework for Reproducibility and Accountability in Distributed Healthcare Analytics". The code implements a library for communication with a blockchain system via API and manages the cryptographic procedures necessary for the operations described in the paper.
## Tutorial
- Clone repository and access the repo folder
```
cd distrib_block_crypto/
```ls

- Install requirements:
```
pip install -r requirements.txt
```
- IF NECESSARY, generate public/private key pair and install the public one in the remote host:
```
ssh-keygen -t rsa
ssh-copy-id -i ~/.ssh/mykey.pub username@my_remote_host
```
- Add your blockchain credentials and paths to the config.yaml file.
- Add path to the logfile in the main.py.
- Run the main.py file to notarize and sign the test_file_repo_demo.txt.
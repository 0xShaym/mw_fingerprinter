# mw_fingerprinter

## Take fingerprint of your malware
Malware samples fingerprinter tool. 

### Outputs
Hashes : 
- MD5
- SHA-1
- SHA-256
- SSDEEP
- IMPHASH (for PE samples only)

Command :
- strings
- hex dump
- file
- trid
- clamscan


## Installation : 

Create venv python
```
python3 -m venv env
source env/bin/activate
```
Install dependecies
```
sudo apt install libfuzzy-dev
sudo apt install libfuzzy2
sudo apt install ssdeep
```
Python modules
```
pip install -r requirements.txt
```
Clamav
```
sudo apt install clamav-freshclam
sudo apt install clamav
```
TrID
```
wget http://mark0.net/download/trid_linux_64.zip
unzip trid_linux_64.zip
wget http://mark0.net/download/triddefs.zip
unzip triddefs.zip
sudo mv trid triddefs.trd /usr/local/bin/
rm triddefs.zip trid_linux_64.zip readme.txt
sudo chmod +x /usr/local/bin/trid
```

## How to use : 
Pass the path to a folder or path to a sample as an argument :
```
$ python3 fingerprinter.py
usage: fingerprinter.py [-h] [--clamav] sample
```
You can specify if you want a clamav scan during the analysis
## Result :
```
$ tree sample/
sample/
├── sample0
├── sample1
├── sample10
├── sample2
├── sample3
├── sample6
├── sample7
├── sample8
├── sample9
└── sample_analysed
    ├── sample0.md
    ├── sample10.md
    ├── sample1.md
    ├── sample2.md
    ├── sample3.md
    ├── sample6.md
    ├── sample7.md
    ├── sample8.md
    └── sample9.md
```
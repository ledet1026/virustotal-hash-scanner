import requests
import json

#send the hash file and te antivirus scan and give the report in json format 
api_key=input("Enter your VirusTotal API key: ").strip()
headers={
    "x-apikey":api_key
}
def hash(hash_value):
    url =  f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        response= requests.get(url,headers=headers)
    except requests.exceptions.RequestException:
        print("Error: Network Problem")
        exit()
    if response.status_code ==401:
        print("Error: Invalid API key")
        exit()
    elif response.status_code ==404:
        print("Error: Hash not found")
        exit()
    elif response.status_code ==429:
        print("Error: API limit exceeded")
        exit()
    elif response.status_code != 200:
        print("Error:",response.status_code)
        exit()
    try:
        data=response.json()
    except:
        print("Error: Response is not JSON")
        exit()

    status=data["data"]["attributes"]
    vote=status.get("total_votes",{"harmless":0,"malicious":0})
    mal= vote.get("malicious",0)
    harm=vote.get("harmless",0) 
    susp=vote.get("suspicious",0) 
    undetect=vote.get("undetected",0)

    print("Malicious: ",mal)
    print("Suspicious: ",susp)
    print("Harmless: ",harm)
    print("Undetected: ",undetect)
    auto_detect(mal,susp)
def auto_detect(malicious, suspicious):
    if malicious > 0:
        print("Final Result: Malicious")
    elif suspicious >0:
        print("Final Result: Suspicious")
    else:
        print("Final Result: Safe ")

file_hash=input("Enter Hash Value separated by comma: ")
if file_hash.strip()!="":
    hashes=file_hash.split(",")
    for idx, h in enumerate(hashes, start=1):
        h=h.strip()
        print(f"\nHash {idx}: {h}")
        hash(h)
        print("-"*80)
else:
    try:
        with open("hash.txt","r") as f:
            hashes=f.read().splitlines()
        if len(hashes)==0:
            print("The file is empty")
        else:

            for idx, h in enumerate(hashes, start=1):
                h=h.strip()
                print(f"\nHash {idx}: {h}")
                hash(h)
                print("-"*80)
    except FileNotFoundError:
        print("File hash.txt is not exist!")
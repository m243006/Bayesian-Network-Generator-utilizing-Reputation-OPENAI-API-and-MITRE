import csv
import time
import openai
import sys
from Final_FormatFin1 import print_packet_info_for_unique_ips
#from Updated_FormatFin1 import print_packet_info_for_unique_ips

from openai import OpenAI
import json

client = OpenAI()
api_key = ""
if len(sys.argv) == 2:
    api_key = sys.argv[1]
    client = openai.OpenAI(api_key=api_key)
elif len(sys.argv) > 2:
    print("Usage: python script.py <API_KEY> or no API KEY")
    sys.exit(1)


model = "gpt-4"
# model = 'gpt-3.5-turbo-1106'
function = function = [{
         "name": "check_dangerous",
         "description": "Labels a network packet as malicious or not, and gives a reason why if they are malicious",
         "parameters": {
             "type": "object",
             "properties": {
                 "dangerous": {
                     "type": "boolean",
                     "description": "True to indicate malicious (with the descrption), false to indicate benign.",
                 },
                 "relation": { 
                     "type" : "string",
                     "description": "Sentence that describes why is this packet malicious and what part of MITRE ATT&CK framework it belongs to."
                 },
                 "TNum": { 
                     "type" : "string",
                     "description": "Return the number of the Subtechnique or technique that this packet relates to, format it in the same way every time"
                 },
             },
             "required": ["dangerous", "relation", "TNum"],
         },
     },]
system = "You are an experienced cyber security analyst. Use the given check_dangerous function to label a given packet as malicios (true) or not (false), and give description if its truee"

def check_pack(packet):
    response = client.chat.completions.create(model=model, messages=[{"role":"system", "content":system}, {"role":"user", "content":packet}], functions=function, temperature= 0)
    try:
        res = json.loads(response.choices[0].message.function_call.arguments)
        #print(res)
        return res['dangerous'], res['relation'], res['TNum']
    except Exception as e:
        print(f"Error processing packet: {e}")
        return False, '', ''



def getPayload(s):
    parts = s.split("Decoded Payload: ")
    try:
        return parts[1]
        #`classification = check_pack(parts[1])
        #writer.writerow([1, classification, "English"])

    except:
        print("Excetpion--------------------------------------------------------------------------------------------------------------------------------------------------")
        print(parts[0])

def getIp(s):
    source_ip_index = s.find("Source IP: ")
    # Extract the substring starting from "Source IP:"
    substring_from_source_ip = s[source_ip_index:]

    # Split the substring on space and take the second element (the IP address)
    source_ip = substring_from_source_ip.split()[2]  # Index 2 as "Source IP:" are the first two elements
    return source_ip

def check_ip_payload_in_csv(source_ip, payload, filename):
    with open(filename, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        first = True 
        for row in reader:
            if row:
                if first:
                    first = False 
                    pass
                else: 
                    if source_ip == row[0] and payload == row[2]:
                        return True  # Found the IP and payload in the file
        return False  # IP and payload not found in the file 

# change this to determine tareget------------------

filename = input("Name the output .csv file: ")
filename1 = input("Name the input .pcapng file: ")

formatted_packets = print_packet_info_for_unique_ips(filename1, 'unique_ips.txt')
# ----------------------------------------------------------------------------------------------

with open(filename, 'w', newline='') as file:
#with open(filename, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Label", "Description", "Technique Number", "Payload"])
    
    for formatted_packet in formatted_packets:
        if "Unable to decode" not in  formatted_packet:
            print(formatted_packet)
            pay = getPayload(formatted_packet)
            source = getIp(formatted_packet)
            retry_delay = 1
            if pay:
                try:
                    classification, descritption, tnum= check_pack(pay)
                    writer.writerow([source, classification, descritption, tnum, pay])
                except openai.RateLimitError:
                    print(f"Waiting for {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Double the delay with each attempt

            


                

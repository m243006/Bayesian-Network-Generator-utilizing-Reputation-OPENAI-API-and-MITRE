from pgmpy.models import DynamicBayesianNetwork as DBN
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import json
import math
from collections import Counter, defaultdict
from itertools import product
from pgmpy.inference import VariableElimination
import re
from AttackersHashTable import AttackersHash
import argparse



def is_valid_ttp(ttp):
    # Regular expression to match the TTP format
    pattern = r"^T\d{1,4}(\.\d{1,3})?$"
    return re.match(pattern, ttp) is not None

def load_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def get_technique_info(data, ttp_id):
    for technique in data.get("objects", []):  # Adjusted to handle nested structure
        if isinstance(technique, dict):
            external_refs = technique.get('external_references', [])
            for ref in external_refs:
                if ref.get('external_id') == ttp_id:
                    return technique["name"]
    return None


def get_unique_ttp_ids(csv_file_path, column_name):
    # Load the CSV file
    df = pd.read_csv(csv_file_path)

    # Check if the specified column exists
    if column_name not in df.columns:
        raise ValueError(f"Column '{column_name}' not found in the CSV file.")
        
    # Filter the DataFrame for rows where the column value is "True"
    filtered_df = df[(df["Label"] == True) &  # Or "True" if it's a string
                    (df["Technique Number"].str.len() >= 5) &
                    (df["Technique Number"].str.startswith('T'))]


    # Assuming 'TTP_ID' is the column that contains TTP IDs, adjust as necessary
    unique_ttp_ids = filtered_df[column_name].unique()

    return unique_ttp_ids

def get_ttps(csv_file_path, column_name):
    # Load the CSV file
    df = pd.read_csv(csv_file_path)

    # Check if the specified column exists
    if column_name not in df.columns:
        raise ValueError(f"Column '{column_name}' not found in the CSV file.")


    filtered_df = df[(df["Label"] == True) &  # Or "True" if it's a string
                    (df["Technique Number"].str.len() >= 5) &
                    (df["Technique Number"].str.startswith('T'))]

    # Assuming 'TTP_ID' is the column that contains TTP IDs, adjust as necessary
    ttps_list = filtered_df[column_name].dropna().tolist()
    return ttps_list

def get_techniques_by_phase(data, phase_name):
    techniques = []
    for item in data.get("objects", []):
        if item.get("type") == "attack-pattern":
            for phase in item.get("kill_chain_phases", []):
                if phase.get("phase_name").lower() == phase_name.lower():
                    technique_id = item.get("external_references", [{}])[0].get("external_id")
                    if technique_id:
                        techniques.append(technique_id)
    return techniques

# make sure that the data is clean and ready to process
def cleanup(test_list): 
    res = [i for i in test_list if type(i) == str and i[0] == 'T'] 
    return res 

def inference_query_single_ttp(userin):
    if userin in unique_ttp_ids:
        evidence = {userin: 1}
        result = inference.query(variables=[Attacker], evidence=evidence)
        return result
    else:
        raise ValueError("TTP is not in the Graph")

def bayesian_update(prior, likelihood):
    # Assuming binary nature (e.g., presence or absence of an attacker)
    not_prior = 1 - prior
    not_likelihood = 1 - likelihood
    # Bayes' theorem application
    posterior = (likelihood * prior) / ((likelihood * prior) + (not_likelihood * not_prior))
    return posterior

def inference_query_combined_ttps(ttp_list):
    total_ttps = len(ttp_list.split(','))
    skipped_ttps = 0
    prior = 0.5  # Starting with a neutral prior probability
    for ttp in ttp_list.split(','):
        ttp = ttp.strip()
        try:
            result = inference_query_single_ttp(ttp)
            print(result)
            likelihood = result.values[1]# Assuming result contains probabilities for 'Attacker'
            prior = bayesian_update(prior, likelihood)
        except ValueError as e:
            print(f"Skipping {ttp}: {e}")
            skipped_ttps += 1

    if skipped_ttps > 0:
        decrease_factor = skipped_ttps / total_ttps
        prior *= (1 - decrease_factor)
    return prior

# -----------------------------------------------------------------------------------------------------------



# Usage
# csv_file_paths = ['N0.csv', 'Id1.csv', 'W-B-01.csv'] # Replace with the path to your CSV file
parser = argparse.ArgumentParser(description='Process the attacker\'s name.')
parser.add_argument('attacker_name', type=str, help='The name of the attacker')
args = parser.parse_args()
Attacker = args.attacker_name
# csv_file_paths = ['Try.csv'] # Replace with the path to your CSV file
csv_file_paths = ['N-0Final.csv', 'Id1.csv', 'Try.csv'] # Replace with the path to your CSV file
column_name = 'Technique Number'  # Replace with the name of the column containing TTP IDs
file_path = 'enterprise-attack.json'  # Replace with the path to your dataset file
data = load_data(file_path)

unique_ttp_ids = set()
ordered_ttps = []
for csv_file_path in csv_file_paths:
    unique_not_cleaned = get_unique_ttp_ids(csv_file_path, column_name)
    ordered_ttps_not = get_ttps(csv_file_path,column_name)
    unique= cleanup(unique_not_cleaned)
    ordered = cleanup(ordered_ttps_not)
    ordered.append(Attacker)
 
    # Two print statements if for debugging 
    # print(ordered)
    # print(unique)
    unique_ttp_ids.update(unique)


    ordered_ttps.extend(ordered)

    #check the intersection
    recon_techniques= get_techniques_by_phase(data, "reconnaissance")
    resource_dev_techniques = get_techniques_by_phase(data, "resource-development")
    initial_access_techniques = get_techniques_by_phase(data, "initial-access")
    execution_techniques = get_techniques_by_phase(data, "execution")
    persistence_techniques = get_techniques_by_phase(data, "persistence")
    privilege_escalation_techniques = get_techniques_by_phase(data, "privilege-escalation")
    defense_evasion_techniques = get_techniques_by_phase(data, "defense-evasion")
    credential_access_techniques = get_techniques_by_phase(data, "credential-access")
    discovery_techniques = get_techniques_by_phase(data, "discovery")
    lateral_movement_techniques = get_techniques_by_phase(data, "lateral-movement")
    collection_techniques = get_techniques_by_phase(data, "collection")
    command_and_control_techniques = get_techniques_by_phase(data, "command-and-control")
    exfiltration_techniques = get_techniques_by_phase(data, "exfiltration")
    impact_techniques = get_techniques_by_phase(data, "impact")



    unique_ttp_names = []
    c = 0
    for i in unique_ttp_ids:
        technique_info = get_technique_info(data, i)
        if technique_info:
            if c == 0:
                unique_ttp_names.append(technique_info)
                print(f"{json.dumps(technique_info, indent=4)}",end="")  # Pretty print the technique information
                c = 1
            else:
                unique_ttp_names.append(technique_info)
                print(f" ==> {json.dumps(technique_info, indent=4)}",end="")  # Pretty print the technique information
        elif i == Attacker:
            unique_ttp_names.append(i)
            print(i)
        else:
            continue

    print("")
    matching_ttps = set(unique_ttp_ids).intersection(recon_techniques)
    print("Matching TTPs in Reconnaissance category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(resource_dev_techniques)
    print("Matching TTPs in Resource Development category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(initial_access_techniques)
    print("Matching TTPs in Initial Access category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(execution_techniques)
    print("Matching TTPs in Execution category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(persistence_techniques)
    print("Matching TTPs in Persistence category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(privilege_escalation_techniques)
    print("Matching TTPs in Privilege Escalation category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(defense_evasion_techniques)
    print("Matching TTPs in Defense Evasion category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(credential_access_techniques)
    print("Matching TTPs in Credential Access category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(discovery_techniques)
    print("Matching TTPs in Discovery category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(lateral_movement_techniques)
    print("Matching TTPs in Lateral Movement category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(collection_techniques)
    print("Matching TTPs in Collection category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(command_and_control_techniques)
    print("Matching TTPs in Command and Control category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(exfiltration_techniques)
    print("Matching TTPs in Exfiltration category:", matching_ttps)
    matching_ttps = set(unique_ttp_ids).intersection(impact_techniques)
    print("Matching TTPs in Impact category:", matching_ttps)






unique.append(Attacker)
# Step 1: Count Transitions
transition_counts = defaultdict(Counter)
print(ordered_ttps)
for i in range(len(ordered_ttps) - 1):
    current_ttp = ordered_ttps[i]
    print(current_ttp)
    next_ttp = ordered_ttps[i + 1]
    transition_counts[current_ttp][next_ttp] += 1

# Step 2: Calculate Transition Probabilities
transition_probabilities = {}
for current_ttp in transition_counts:
    total_transitions = sum(transition_counts[current_ttp].values())
    transition_probabilities[current_ttp] = {next_ttp: count / total_transitions 
                                             for next_ttp, count in transition_counts[current_ttp].items()}



print(transition_probabilities)
relationships = transition_probabilities


# Graph analysis 
# Make a graph out of the relationships, that algorithm calculated
G = nx.DiGraph()
for parent, children in relationships.items():
    for child in children:
        if parent != Attacker:
            G.add_edge(parent, child)


try:
    cycle = nx.find_cycle(G, orientation='original')
    print("Cycle detected:", cycle)
    while(True):
        # get the first node of the last edge in the cycle and remove it
        node_to_remove = cycle[-1][1]  
        print("this is the cycle", cycle)

        print("Removing node:", node_to_remove)
        # Remove the node
        G.remove_node(node_to_remove)
        print(f"Node {node_to_remove} has been removed.")
        del relationships[node_to_remove]
        # Check again for cycles, to ensure the graph is now acyclic
        try:
            cycle = nx.find_cycle(G, orientation='original')
            print("Cycle detected:", cycle)
        except nx.NetworkXNoCycle:
            print("No cycle detected.")
            # Check if 'Attacker' has any incoming edges
            if Attacker in G.nodes():
                has_incoming_edges = len(list(G.in_edges(Attacker))) > 0

                if not has_incoming_edges:
                    print(f"'{Attacker}' node is isolated; it has no incoming edges.")

                    # Find a node to connect to the 'Attacker' node
                    # Example: find a node with outgoing edges or the last node in some processing order
                    # As an example, we take a node with outgoing edges (if exists)
                    potential_nodes = [node for node in G.nodes() if node != Attacker and len(list(G.out_edges(node))) > 0]
                    if potential_nodes:
                        # Choose a node to connect (for example, the first from the list)
                        node_to_connect = cycle[-1][0] 
                        
                        # Add an edge from 'node_to_connect' to 'Attacker'
                        G.add_edge(node_to_connect, Attacker)
                        relationships[node_to_connect] = {Attacker : 1}
                        print(f"Added edge from '{node_to_connect}' to '{Attacker}'")
                else:
                    print(f"'{Attacker}' node has incoming edges and is connected in the graph.")
            break
except nx.NetworkXNoCycle:
    print("No cycle detected.")


# here is how to find the longest path now
# print(nx.dag_longest_path(G))

# Create a Bayesian Model
model = BayesianNetwork()
child_parents = {}
# Create edges and identify parents of each child
for parent, children in relationships.items():
    for child in children:
        if parent != Attacker:
            model.add_edge(parent, child)
            if child not in child_parents:
                child_parents[child] = []
            child_parents[child].append(parent)

# Create CPDs for each child node considering all its parents
for child, parents in child_parents.items():
    # Calculate the cardinality for each parent
    parent_cards = [2] * len(parents)
    
    # Create all combinations of parent states (0 or 1)
    parent_state_combinations = list(product([0, 1], repeat=len(parents)))

    # Calculate the probability values for the CPD
    cpd_values = []
    for state_comb in parent_state_combinations:
        prob = 1
        for parent, state in zip(parents, state_comb):
            if state == 0:
                prob *= (1 - relationships[parent].get(child, 0))
            else:
                prob *= relationships[parent].get(child, 0)
        cpd_values.append([1 - prob, prob])

    # Transpose to match pgmpy's CPD format
    cpd_values = list(map(list, zip(*cpd_values)))

    # Create and add the CPD
    cpd = TabularCPD(variable=child, variable_card=2, values=cpd_values,
                        evidence=parents, evidence_card=parent_cards)
    model.add_cpds(cpd)


# After defining CPDs for child nodes, check if all nodes have CPDs
all_nodes = set(model.nodes())
nodes_with_cpds = set(cpd.variable for cpd in model.get_cpds())

# Nodes without CPDs
nodes_without_cpds = all_nodes - nodes_with_cpds

# Define prior probabilities for nodes without CPDs (assuming binary nodes)
for node in nodes_without_cpds:
    prior_prob = 0.5  # This is an example, adjust it based on your knowledge or data
    cpd = TabularCPD(variable=node, variable_card=2, values=[[1 - prior_prob], [prior_prob]])
    model.add_cpds(cpd)


# model.l
if model.check_model():
    print("Model is correctly specified.")
else:
    print("Model has errors.")

nx_graph = nx.DiGraph()




# -----------------------------------------------------------------------------------------------draw
for edge in model.edges():
    nx_graph.add_edge(edge[0], edge[1])

# Identify the first and last nodes
# first_nodes = [node for node in model.nodes() if model.in_degree(node) == 0]

# If there are multiple starting/ending nodes, you may choose one or handle them differently
# first_node = first_nodes[0] if first_nodes else None

nodes_without_parents = [node for node in model.nodes() if model.in_degree(node) == 0]
print(nodes_without_parents)

# Draw the network with a circular layout
# pos = nx.kamada_kawai_layout(nx_graph)
pos = nx.shell_layout(nx_graph)

# Define node colors and sizes
# node_colors = ["red" if node in nodes_without_parents else "lightblue" for node in nx_graph.nodes()]
node_colors = ["lightblue" for node in nx_graph.nodes()]
node_sizes = [100 for node in nx_graph.nodes()]
nx.draw_networkx_nodes(nx_graph, pos, node_color=node_colors, node_size=node_sizes)
nx.draw_networkx_edges(nx_graph, pos)
nx.draw_networkx_labels(nx_graph, pos, font_size=5)
# Save the graph to a file
plt.savefig("spectral_graph2.png")
plt.close()



# Perform inference
inference = VariableElimination(model)
attackers_hash = AttackersHash()
attackers_hash.load()
attackers_hash.set_attacker(Attacker)
attackers_hash.set_model(Attacker, model)
attackers_hash.save()



while True:
    print("1. Input a single TTP in the format 'TXXXX' or 'TXXXX.YYY'")
    print("2. Input a sequence of TTPs seperated by comma")
    print("3. Print the existing HashTavle")
    option = input("Enter your choice or type 'quit' to exit: ")
    if option == "quit":
        break
    elif option == "1":
        userin = input("Enter a TTP: ")
        if userin == "quit":
            break
        elif is_valid_ttp(userin):
            try:
                result = inference_query_single_ttp(userin)
                print(result)
            except ValueError as e:
                print(e)
        else:
            print("Invalid TTP format. Please enter a TTP in the format 'TXXXX' or 'TXXXX.YYY'.")
    elif option == "2":
        userin = input("Enter a sequence of TTPs separated by commas: ")
        if userin == "quit":
            break
        if all(is_valid_ttp(ttp.strip()) for ttp in userin.split(',')):
            try:
                result = inference_query_combined_ttps(userin)
                print("This is the result ")
                print(result)
            except ValueError as e:
                print(e)
        else:
            print("Invalid TTP format in sequence. Please ensure all TTPs are in the format 'TXXXX' or 'TXXXXX.YYY'.")
    elif option == "3":
        attackers_hash.print_hash_table()
    else:
        print("Invalid option, please choose '1' or '2'.")


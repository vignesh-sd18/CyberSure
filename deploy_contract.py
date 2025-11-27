from web3 import Web3
import json

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

if w3.is_connected():
    print("Connected to Ganache!")
else:
    print("Failed to connect.")

# Load compiled contract
with open('build/compiled_contract.json', 'r') as file:
    compiled_sol = json.load(file)

# Extract ABI and bytecode (use the correct contract name)
abi = compiled_sol['contracts']['MyContract.sol']['CyberInsurance']['abi']
bytecode = compiled_sol['contracts']['MyContract.sol']['CyberInsurance']['evm']['bytecode']['object']

# Set default account (use the first Ganache account)
w3.eth.default_account = w3.eth.accounts[0]

# Create contract instance
CyberInsurance = w3.eth.contract(abi=abi, bytecode=bytecode)

# Deploy contract
tx_hash = CyberInsurance.constructor().transact()

# Wait for transaction receipt
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

print(f"Contract deployed at address: {tx_receipt.contractAddress}")

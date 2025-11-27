# Block-chain Powered Cyber Risk Prediction and Insurance Platform

This repository is a Flask-based prototype that integrates machine learning for cyber risk prediction with a blockchain (Ethereum/Ganache) backend for recording policies and transactions.

## Key features
- Flask web application with user registration/login
- Server-side risk prediction using sklearn models
- Smart contract interaction and storage using Web3.py
- Simple KYC and admin dashboard workflows
- Basic security protections (SQLi detection, brute force protection)

---

## Prerequisites
- Python 3.11+ (Windows, Linux, or macOS)
- Git
- Node.js (for Ganache CLI) or Ganache app (GUI): https://trufflesuite.com/ganache/
- Optional: Git LFS for large ML model files: https://git-lfs.github.com/

---

## Quick setup (Windows PowerShell)
1. Clone the repo (use SSH if you set up keys):
```powershell
# using SSH
git clone git@github.com:vignesh-sd18/CyberSure.git
cd "Block-chain Powered Cyber Risk Prediction"
```

2. Create and activate a virtual environment
```powershell
python -m venv venv
# Activate PowerShell venv
venv\Scripts\Activate.ps1
```

3. Install Python requirements
```powershell
pip install --upgrade pip
pip install -r requirements.txt
# If you plan to use .env file loading, add python-dotenv
pip install python-dotenv
```

4. Install and start Ganache (choose GUI or CLI):
```powershell
# Ganache CLI (npm):
npm install -g ganache
# Start Ganache on port 8545
ganache --port 8545
```
Or use the Ganache desktop app and start a workspace.

5. Configure environment variables (create a `.env` file in project root)
Create a `.env` file with the following variables (DON'T commit `.env` to the repo):
```
backend_private_key=0xYOUR_PRIVATE_KEY_FROM_GANACHE
contract_address=  # Optional - the app will auto-deploy if not provided
SENDER_EMAIL=    # Optional: your SMTP sender email (for OTP test)
SENDER_PASSWORD= # Optional: password or app-specific password
```

> Note: The code uses `dotenv` via `load_dotenv()` if available. The app will auto-deploy the contract if `contract_address` is not set.

6. Optional: Git LFS for large model files
The repository contains ML models in `ml_models/` that may be large. To avoid large-file issues on GitHub, install and track them with Git LFS:
```powershell
# Install git-lfs
choco install git-lfs -y
# Initialize lfs
git lfs install
# Track model files
git lfs track "ml_models/*.pkl"
# Commit the .gitattributes entry and re-add your files if needed
git add .gitattributes
```

7. (Optional) Deploy contract manually
```
python deploy_contract.py
```
This deploys the compiled contract (from `build/compiled_contract.json`) to Ganache and prints the new contract address. If you want the app to auto-deploy the contract, leave `contract_address` empty in `.env` and start the app.

8. Run the Flask app
```powershell
# Option 1: run via python
python app.py
# Option 2: use flask run
$env:FLASK_APP = 'app.py'
$env:FLASK_ENV = 'development'
flask run
```
Then open http://127.0.0.1:5000 in your browser.

---

## Using the app
- Register a new user via the register page — the app generates an Ethereum wallet address for your account (private key not stored).
- If your user is `admin` role you can access admin pages:
  - Admin dashboard: `/admin/dashboard`
  - Admin policy management: `/admin/policies` and `/admin/policy`
- For predictions, log in as a customer and go to `/predict`.
- The app logs suspicious input (SQLi-like patterns, token-like hex strings) and uploads certain information to the blockchain contract.

---

## Notes & Security
- DO NOT commit `.env` or any credentials to GitHub. If you have done so already, rotate the leaked credentials immediately (private keys, SMTP passwords).
- `ml_models/*.pkl` and `instance/app.db` are local artifacts. Consider adding them to `.gitignore` if you don't want them in the repo.
- The repo contains a `.env` file in the workspace used for development/test only. Please remove or rotate tokens before publishing.
- For production deployments, use a secure secrets storage (Azure Key Vault / AWS Secrets Manager / HashiCorp Vault) and avoid running Ganache in production.

---

## Troubleshooting
- 403 or permission denied when pushing: ensure SSH keys are added to your GitHub account (or use HTTPS with a PAT), or switch remote to SSH:
```powershell
git remote set-url origin git@github.com:vignesh-sd18/CyberSure.git
```
- If the contract fails to deploy, ensure Ganache is running on port 8545 and the private key in `.env` belongs to an account with sufficient funds.
- If models fail to load (joblib error), confirm `ml_models/` files exist and are compatible.

---

## Contributing
- Add features via feature branches, and follow code style and best practices. Commit changes and open PRs for review.
- If changes involve large model files, prefer storing them in external object storage or enable Git LFS.

---

## License
- This repo does not include a license. Add a LICENSE file if you want to make it open-source.

---

If you'd like, I can:
- Add a safer `.env.example` file with placeholders
- Remove sensitive files from history and add to `.gitignore`
- Move ML models into LFS and rewrite history to avoid large pushes
- Add a simple `run_local.ps1` script to spawn Ganache & run the Flask app together

Tell me which of the above you want next and I’ll implement it.
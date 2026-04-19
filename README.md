# SSDLC - 2026-1

This project demonstrates security integration across the full software development using OWASP Juice Shop as the target application. It covers a functional system, threat modeling, and an automated DevSecOps pipeline.
Furthermore, we are using Juice-Shop to discover risks and vulnerabilities that the web environment has.

## Team Members
- Member 1 – David Alejandro Montaña Rodríguez
- Member 2 – Juan David Londoño Pinzón
- Member 3 – Santiago Melo Aguirre
---
 # How to run in CodeSpaces
---

- Installs all dependencies from ```requirements.txt``` by running:
  ```bash
  pip install -r requirements.txt
  ```
- Configures the PATH so the `semgrep` command works in the terminal:
  ```bash
  export PATH=$PATH:/home/codespace/.local/lib/python3.12/site-packages/bin
  ```
- Downloads and initializes the Juice Shop submodule by running:
  ```bash
  git submodule update --init --recursive
  ```
 
---
### 2. Verify everything is ready
 
```bash
semgrep --version
ls juice-shop/
```
 
You should see Semgrep's version number and the Juice Shop files listed.
---

### 3. Run a Semgrep scan
 
```bash
semgrep --config=p/javascript juice-shop/ --json | python -m json.tool > reports/semgrep-results.json
```
 
Check how many findings were detected:
 
```bash
grep -c '"check_id"' reports/semgrep-results.json
```
 
---
# How to run in your OWN MACHINE
 
## Mandatory Downloads
 
| Tool | Download |
|------|----------|
| Git  | https://git-scm.com/download/win |
| Docker Desktop | https://www.docker.com/products/docker-desktop |
 
---
 
## Setup
 
### 1. Clone the repository
 
```bash
git clone https://github.com/Alejom-hub/ssslc-proyect-OWASP-juice-shop.git

cd ssslc-proyect-OWASP-juice-shop
```
 
### 2. Initialize the Juice Shop submodule
 
Without it, the folder will appear empty.
 
```bash
git submodule update --init --recursive
```
 
### 3. Configure your Git identity (first time only)
 
```bash
git config --global user.email "your email"
git config --global user.name "your name"
```
 
### 4. Docker is working

To confirm that Docker is running in your machine, run the folliwing command in the console:

```bash
docker --version
```

 
### 5. Launch OWASP Juice Shop
 
```bash
docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```
 
### 6. Verify Juice Shop is running
 
Open your browser and go to:
 
```
http://localhost:3000
```
 
You should see the Juice Shop front. If you do, everything is working correctly.
 
---
 
## Useful Docker Commands
 
```bash
# See running containers and their IDs
docker ps
 
# Stop Juice Shop
docker stop <CONTAINER_ID>
 
# Start it again
docker start <CONTAINER_ID>
 
# View Juice Shop logs
docker logs <CONTAINER_ID>
```
 
> You can find the `CONTAINER_ID` by running `docker ps`.
 
---
 
## Pulling Latest Changes from the Repository
 
When a teammate pushes new code, run this to sync your local copy:
 
```bash
git pull
git submodule update --recursive
```
 
---



 
## References
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

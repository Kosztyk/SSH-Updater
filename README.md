# SSH-Updater

A tiny web UI to update many Linux hosts over SSH, run ad-hoc scripts, and watch live logs
stream back—backed by MongoDB and secured with JWT. Great for homelabs, small fleets, or any
time you don’t want to copy-paste the same command into 10 terminals.
Highlights
• Add & manage hosts (name, IP, SSH user, password, port, root flag)
• One-click apt update/upgrade per host or Update all
• Run custom commands or full bash scripts on selected hosts
• Live log streaming (SSE) for single/all/custom jobs
• JWT authentication with MongoDB storage
• Docker-ready (sample docker-compose included)

# Screenshots
<img width="693" height="446" alt="Screenshot 2025-10-14 at 21 52 34" src="https://github.com/user-attachments/assets/1d47b60c-95b2-4854-a8a0-2ec3ca22c53c" />
<img width="1702" height="453" alt="Screenshot 2025-10-14 at 21 38 48" src="https://github.com/user-attachments/assets/560c2e9f-cdfd-4f88-ab80-c214f6a1487a" />
<img width="1182" height="453" alt="Screenshot 2025-10-14 at 21 40 44" src="https://github.com/user-attachments/assets/8235700e-e9e6-4ba2-a2a9-e0010e7941e9" />
<img width="1182" height="317" alt="Screenshot 2025-10-14 at 21 41 35" src="https://github.com/user-attachments/assets/8ed14d5d-6aac-40d4-8349-9bc74e93b600" />
<img width="1182" height="794" alt="Screenshot 2025-10-14 at 21 42 24" src="https://github.com/user-attachments/assets/996240d1-3d34-499e-b94d-01ecc6e970cc" />

# Quick Start (Docker Compose)

Use the provided docker-compose file to launch SSH Updater along with MongoDB and
mongo-express.

Once started, access the web UI at http://localhost:8099.

The first user can self-register. After that, only logged-in users can add more users.

# docker-compose.yml example

```
services:
  web:
    image: kosztyk/ssh-updater:latest
    container_name: ssh-updater
    restart: unless-stopped
    ports:
      - "8099:8080"
    environment:
      - TZ=Europe/Bucharest
      - MONGO_URL=mongodb://mongo:27017/sshupdater
      - JWT_SECRET=changeme
    depends_on:
      mongo:
        condition: service_healthy

  mongo:
    image: mongo:4.4
    container_name: ssh-updater-mongo
    restart: unless-stopped
    command: ["--bind_ip_all"]
    ports:
      - "27017:27017"   # optional for host debugging; you can remove later
    volumes:
      - mongo_data:/data/db
    healthcheck:
      test: ["CMD", "mongo", "--quiet", "--eval", "db.adminCommand('ping').ok"]
      interval: 10s
      timeout: 5s
      retries: 10

  mongo-express:
    image: mongo-express
    container_name: mongo-express
    restart: always
    ports:
      - "8082:8081"
    environment:
      ME_CONFIG_MONGODB_SERVER: mongo
      ME_CONFIG_BASICAUTH_USERNAME: changeme
      ME_CONFIG_BASICAUTH_PASSWORD: changeme
      ME_CONFIG_MONGODB_URL: mongodb://mongo:27017/
    depends_on:
      - mongo   

volumes:
  mongo_data:
```

# Security Notes

• Passwords are stored in MongoDB for demo convenience — use SSH keys in production.
• Set a strong JWT_SECRET.
• Prefer HTTPS and restrict network access to known hosts.

# License
MIT License — use freely, no warranty.
Do what you want, just don’t blame us if your cat upgrades the wrong server.

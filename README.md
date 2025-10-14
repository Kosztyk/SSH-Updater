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

Include images such as:
• Dashboard – Add Host & Update All
• Run Custom Script (with live logs)
• Live Logs – Update All (SSE)
• Edit Host Modal
(Place images under docs/screenshots/ and link them in README.md)
Quick Start (Docker Compose)
Use the provided docker-compose file to launch SSH Updater along with MongoDB and
mongo-express.
Once started, access the web UI at http://localhost:8099.
The first user can self-register. After that, only logged-in users can add more users.

# Security Notes

• Passwords are stored in MongoDB for demo convenience — use SSH keys in production.
• Set a strong JWT_SECRET.
• Prefer HTTPS and restrict network access to known hosts.

# License
MIT License — use freely, no warranty.
Do what you want, just don’t blame us if your cat upgrades the wrong server.

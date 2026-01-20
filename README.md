# VPS Security Settings

A collection of scripts and configurations to harden your VPS for better security. This repository offers opinionated yet flexible settings for Linux servers.

## Ubuntu 25.04 Security Hardening Script

A comprehensive, well-documented bash script that applies security best practices to a fresh Ubuntu 25.04 VPS. Designed for intermediate users with sensible defaults and interactive prompts.

### What It Does

| Security Layer | Description |
|----------------|-------------|
| **User Management** | Creates a non-root sudo user to prevent direct root access |
| **SSH Hardening** | Key-based authentication, disabled root login, limited auth attempts |
| **UFW Firewall** | Blocks all incoming traffic except explicitly allowed ports |
| **Fail2ban** | Automatically bans IPs after repeated failed login attempts |
| **Auto Updates** | Configures unattended security updates to keep system patched |
| **Security Auditing** | Installs rkhunter and lynis with weekly automated scans |

---

## Quick Install (One-Liner)

Run this command on your fresh Ubuntu 25.04 VPS:

```bash
curl -sSL https://raw.githubusercontent.com/codingwithmanny/vps-security-settings/main/secure-ubuntu.sh -o secure-ubuntu.sh && chmod +x secure-ubuntu.sh && sudo ./secure-ubuntu.sh
```

Or with wget:

```bash
wget -qO secure-ubuntu.sh https://raw.githubusercontent.com/codingwithmanny/vps-security-settings/main/secure-ubuntu.sh && chmod +x secure-ubuntu.sh && sudo ./secure-ubuntu.sh
```

---

## Manual Installation

### Step 1: Download the Script

**Option A: Clone the repository**
```bash
git clone https://github.com/codingwithmanny/vps-security-settings.git
cd vps-security-settings
```

**Option B: Download just the script**
```bash
curl -O https://raw.githubusercontent.com/codingwithmanny/vps-security-settings/main/secure-ubuntu.sh
```

Or:
```bash
wget https://raw.githubusercontent.com/codingwithmanny/vps-security-settings/main/secure-ubuntu.sh
```

### Step 2: Make It Executable

```bash
chmod +x secure-ubuntu.sh
```

### Step 3: Run the Script

```bash
sudo ./secure-ubuntu.sh
```

---

## Usage Options

### Interactive Mode (Recommended for First Use)

```bash
sudo ./secure-ubuntu.sh
```

The script will guide you through each security configuration with prompts and sensible defaults.

### Dry-Run Mode (Preview Changes)

```bash
sudo ./secure-ubuntu.sh --dry-run
```

Shows exactly what changes would be made without actually applying them. Perfect for reviewing before committing.

### Quiet Mode (Automated Deployments)

```bash
sudo ./secure-ubuntu.sh --quiet
```

Uses all default values without prompting. Ideal for scripted/automated server provisioning.

### Help

```bash
./secure-ubuntu.sh --help
```

---

## Requirements

- **Operating System:** Ubuntu 25.04 (will warn on older versions)
- **Permissions:** Must be run as root or with sudo
- **Network:** Internet access required to install packages
- **SSH Access:** Ensure you have console access as a backup before running

---

## What Gets Configured

### 1. User Management
- Creates a new sudo user (you choose the username)
- Sets up `.ssh` directory with proper permissions
- Option to disable direct root login

### 2. SSH Hardening
- Disables root login via SSH
- Limits authentication attempts (MaxAuthTries 3)
- Sets login grace time to 60 seconds
- Disables empty passwords
- Disables X11 forwarding
- Optional: Change SSH port from default 22
- Optional: Key-based authentication only (disables passwords)

### 3. UFW Firewall
- Default deny all incoming traffic
- Default allow all outgoing traffic
- Allows your SSH port (default 22 or custom)
- Option to open additional ports (80, 443, etc.)

### 4. Fail2ban
- Protects SSH from brute-force attacks
- Default: Ban IP for 1 hour after 5 failed attempts
- Configurable ban duration

### 5. Automatic Updates
- Installs `unattended-upgrades`
- Configures security-only automatic updates
- Optional: Auto-reboot when required (with configurable time)

### 6. Security Auditing
- Installs `rkhunter` (rootkit detection)
- Installs `lynis` (security auditing)
- Creates weekly automated scan schedule
- Logs stored in `/var/log/security-audit/`

---

## Important Notes

### Before Running

1. **Have console access ready** - If SSH gets misconfigured, you'll need VPS provider console access
2. **Know your SSH public key** - Have it ready to paste if you want key-only authentication
3. **Note current SSH port** - Default is 22, but know if it's different

### After Running

1. **Test SSH in a new terminal** before closing your current session
2. **Note the new connection command** shown at the end of the script
3. **Save backup location** - All original configs are backed up to `/root/security-backup-{timestamp}/`

### SSH Connection After Hardening

```bash
ssh your-username@your-server-ip -p SSH_PORT
```

Example with custom port:
```bash
ssh admin@192.168.1.100 -p 2222
```

---

## File Locations

| File | Purpose |
|------|---------|
| `/var/log/secure-ubuntu.log` | Script execution log |
| `/root/security-backup-*` | Backup of original config files |
| `/etc/ssh/sshd_config` | SSH server configuration |
| `/etc/fail2ban/jail.local` | Fail2ban configuration |
| `/var/log/security-audit/` | Weekly security scan results |

---

## Troubleshooting

### Locked Out of SSH

1. Access your server via VPS provider's console/VNC
2. Restore SSH config from backup:
   ```bash
   cp /root/security-backup-*/etc/ssh/sshd_config /etc/ssh/sshd_config
   systemctl restart sshd
   ```

### Fail2ban Banned Your IP

From VPS console:
```bash
# Check if your IP is banned
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client set sshd unbanip YOUR_IP_ADDRESS
```

### Firewall Blocking Something

```bash
# Check current rules
sudo ufw status numbered

# Allow a port
sudo ufw allow PORT_NUMBER/tcp

# Delete a rule by number
sudo ufw delete RULE_NUMBER
```

### Check Service Status

```bash
# SSH
sudo systemctl status sshd

# Fail2ban
sudo systemctl status fail2ban
sudo fail2ban-client status

# Firewall
sudo ufw status verbose
```

---

## Security Recommendations

After running this script, consider these additional hardening steps:

1. **Set up SSH keys** if you haven't already
2. **Enable 2FA** for SSH using Google Authenticator
3. **Configure log monitoring** with tools like Logwatch
4. **Set up intrusion detection** with AIDE or OSSEC
5. **Regular security audits** - run `sudo lynis audit system` monthly
6. **Keep the system updated** - even with auto-updates, check manually periodically

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## License

MIT License - feel free to use and modify for your own servers.

---

## Disclaimer

This script modifies critical system security settings. While it follows best practices, always:
- Test in a non-production environment first
- Ensure you have backup access (console) before running
- Review the script before executing on production servers
- Understand what each setting does (the script is heavily commented)

**Use at your own risk.**

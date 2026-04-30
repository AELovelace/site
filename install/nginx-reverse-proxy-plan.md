**Topology**

`10.1.1.23`
- Runs the Node app as `sitechat`
- Listens only on an internal port such as `3000`
- Installs into `/opt/sitechat`

`10.1.1.20`
- Runs nginx
- Terminates public HTTP/HTTPS
- Reverse proxies traffic to `10.1.1.23:3000`

**Fedora App Host**

1. Copy the curated repo to `10.1.1.23`.
2. Run `sudo bash install/fedora-install.sh`.
3. Verify the service:
   `systemctl status sitechat`
4. Confirm local listening:
   `ss -ltnp | grep 3000`
5. If `firewalld` is enabled and nginx is on a different host, allow only the webserver:
   `firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.1.1.20/32" port protocol="tcp" port="3000" accept'`
6. Remove broad access if needed:
   `firewall-cmd --permanent --remove-service=http`
   Only if that machine should not serve public HTTP directly.
7. Reload firewall:
   `firewall-cmd --reload`

**Nginx Reverse Proxy**

Use a dedicated upstream and pass the forwarding headers the app may need later.

Example nginx config on `10.1.1.20`:

```nginx
upstream sitechat_upstream {
    server 10.1.1.23:3000;
    keepalive 32;
}

server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://sitechat_upstream;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Connection "";

        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }
}
```

**Why These Settings Matter**

- `X-Forwarded-Proto` lets the app mark cookies as `Secure` when traffic is HTTPS at nginx.
- `proxy_buffering off` helps the live event stream stay responsive.
- Long read/send timeouts prevent the event stream from getting cut off too aggressively.
- `client_max_body_size 2m` is enough for IMAGI uploads and leaves little room for abuse.

**Verification Checklist**

On `10.1.1.23`:
- `curl -I http://127.0.0.1:3000/login.php`

On `10.1.1.20`:
- `curl -I http://10.1.1.23:3000/login.php`
- `nginx -t`
- `systemctl reload nginx`

From a browser:
- Load the public host
- Register/login
- Send a chat message
- Confirm live updates still work
- Confirm IMAGI upload still works
- Confirm cookies are marked `Secure` on HTTPS

**Operational Notes**

- App logs:
  `journalctl -u sitechat -f`
- Restart after deploying updates:
  `systemctl restart sitechat`
- If you update files in `/opt/sitechat`, keep `data/` intact so users and chat history remain.

# Purpose & Inner-workings

1. Listen on port 8008 (HTTP)
2. C2 Comms:
- C2 Pannel not considered here. Must be accessed by other means (SSH tunnels, etc)
- C2 Traffic from Mythic C2 agents: Redirected to http://localhost:80, if http_user_agent matches the one set in Mythic C2
- Else, Redirected to /var/www/html/files/index.html (This can be anything we want, for decoy)
3. File Share Server:
- Path at /fetch/ - No specific rules or restrictions here. Files accessible on this path.

# Configuration

- Place config file at /etc/nginx/conf.d/ and make sure this path is "included" in /etc/nginx/nginx.conf file
- HTTP Port 8008 is the main entry for Nginx, so that's our inbound connection.
-   Hence, we need to handle TLS termination with other means (ALB, Cloudfront, etc). 

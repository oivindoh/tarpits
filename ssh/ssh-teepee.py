import asyncio
import socket
import asyncpg
from datetime import datetime
import maxminddb
import random
import os
import logging
import json
import hashlib
import signal
import ipaddress
from ipaddress import ip_network, collapse_addresses

class ShutdownException(Exception):
    """Custom exception for task failure"""
    pass

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.msg,
        }
        # Define fields to exclude (default LogRecord attributes)
        exclude_fields = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename', 'module',
            'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName', 'created', 'msecs',
            'relativeCreated', 'thread', 'threadName', 'processName', 'process', 'logger'
        }
        # Include only extra fields explicitly passed, excluding defaults
        extra_data = {k: v for k, v in record.__dict__.items() if k not in exclude_fields and not k.startswith('_')}
        log_data.update(extra_data)
        return json.dumps(log_data)

cloud_asns = {
    14061: {
        'name': 'DigitalOcean US'
    },
    396982: {
        'name': 'GoogleCloud US'
    },
    45102: {
        'name': 'Alibaba US'
    },
    8075: {
        'name': 'Microsoft'
    },
    16509: {
        'name': 'Amazon'
    },
    398324: {
        'name': 'Censys'
    }
}

# Configure logging
logger = logging.getLogger('ssh-tarpit')
log_level = os.getenv("TARPIT_LOG_LEVEL", "INFO").upper()
log_level_map = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}
logger.setLevel(log_level_map.get(log_level))
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.handlers = [handler]

# Database configuration (adjust or use environment variables)
DB_CONFIG = {
    "database": os.getenv("TARPIT_DATABASE_DBNAME","postgres"),
    "user": os.getenv("TARPIT_DATABASE_USER","postgres"),
    "password": os.getenv("TARPIT_DATABASE_PASSWORD","your_password"),
    "host": os.getenv("TARPIT_DATABASE_HOST","localhost"),
    "port": "5432"
}

# Global set to track active tasks (not just connections)
active_tasks = set()
max_tasks = int(os.getenv("TARPIT_MAX_CONCURRENCY", '200'))

# Load GeoIP database
ipdb_path = os.getenv('TARPIT_IPDB_PATH', '/ipnetdb_prefix_latest.mmdb') # https://cdn.ipnetdb.net/ipnetdb_prefix_latest.mmdb
mmdb_path = os.getenv('TARPIT_MMDB_PATH', '/GeoLite2-City.mmdb')
TEST_SUBNET = ipaddress.ip_network("::ffff:172.16.0.0/108")

"""
if os.getenv('TARPIT_DOWNLOAD_MISSING_IPDB','yes'):
    import requests

    url = "https://cdn.ipnetdb.net/ipnetdb_prefix_latest.mmdb"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Referer": "https://cdn.ipnetdb.net/",  # Adjust based on what your browser sends
        "If-Range": "f8c07a2921801cc789f86e1f6554fc60-21"
    }

    response = requests.get(url, headers=headers)

    if response.status_code in (200, 206):
        with open(ipdb_path, "wb") as file:
            file.write(response.content)
        print(f"File downloaded successfully with status {response.status_code}!")
    else:
        print(f"Failed to download file. Status code: {response.status_code}")
"""

if os.path.isfile(mmdb_path):
    GEOIP_DATABASE = maxminddb.open_database(mmdb_path)
    ENRICH_GEOIP = True
    logger.info("GEOIP enrichment enabled", extra={"mmdb_path": mmdb_path})
else:
    logger.warning("IP enrichment disabled", extra={"mmdb_path": mmdb_path, "reason": "File not found"})
    ENRICH_GEOIP = False
if os.path.isfile(mmdb_path):
    IPDB_DATABASE = maxminddb.open_database(ipdb_path)
    ENRICH_IPDB = True
    logger.info("IPDB enrichment enabled", extra={"mmdb_path": ipdb_path})    
else:
    logger.warning("IPDB enrichment disabled", extra={"mmdb_path": ipdb_path, "reason": "File not found"})
    ENRICH_IPDB = False

RICKROLL = os.getenv('TARPIT_RICKROLL','False')

async def init_pool():
    global pool
    pool = await asyncpg.create_pool(**DB_CONFIG, min_size=1, max_size=20)

async def fetch_total_cidr_addresses():
    async with pool.acquire() as conn:
        query = "SELECT net, prefix FROM ssh_connections WHERE net is not null and prefix is not null"
        rows = await conn.fetch(query)
    
        net_networks = []
        prefix_networks = []
        
        # Collect valid networks
        for row in rows:
            try:
                net_networks.append(ip_network(row['net'], strict=False))
            except ValueError as e:
                logger.error(f"Invalid net CIDR", extra={"cidr": str(row['net']), "error": str(e)})
            try:
                prefix_networks.append(ip_network(row['prefix'], strict=False))
            except ValueError as e:
                logger.error(f"Invalid prefix CIDR", extra={"cidr": str(row['prefix']), "error": str(e)})
        
        # Collapse overlapping networks
        net_collapsed = list(collapse_addresses(net_networks))
        prefix_collapsed = list(collapse_addresses(prefix_networks))
        
        # Sum the totals
        net_total = sum(net.num_addresses for net in net_collapsed)
        prefix_total = sum(prefix.num_addresses for prefix in prefix_collapsed)
        
        return net_total, prefix_total

def create_stable_hash(client_ip: str, client_string: str, client_port: int) -> str:
    # Normalize inputs
    normalized_ip = client_ip.strip()  # Remove whitespace
    normalized_string = client_string.lower().strip()  # Case-insensitive, no whitespace
    normalized_port = str(client_port)  # Convert port to string

    # Combine inputs in a fixed order with a delimiter
    combined_input = f"{normalized_ip}|{normalized_string}|{normalized_port}".encode('utf-8')

    # Generate SHA-256 hash (you can use other hash functions like MD5 or hashlib.sha1)
    hash_object = hashlib.sha256(combined_input)
    
    # Return the hexadecimal representation of the hash
    return hash_object.hexdigest()

# Wait for database to be available with retry
async def wait_for_db(max_attempts=30, initial_delay=2):
    attempt = 1
    delay = initial_delay
    logger.info("Attempting to connect to database", extra={"config": DB_CONFIG})
    while attempt <= max_attempts:
        try:
            conn = await asyncpg.connect(**DB_CONFIG)
            await conn.close()
            logger.info("Database connection successful", extra={"attempt": attempt})
            return True
        except Exception as e:
            logger.warning("Database not ready", extra={"attempt": attempt, "max_attempts": max_attempts, "error": str(e)})
            if attempt == max_attempts:
                logger.error("Max attempts reached. Exiting")
                return False
            await asyncio.sleep(delay)
            attempt += 1
            delay = min(delay * 2, 30)

# Initialize the database table
async def init_db():
    async with pool.acquire() as conn:
        # Main connections table (removed client_version)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ssh_connections (
                client_ip INET PRIMARY KEY,
                connections BIGINT DEFAULT 1,
                first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                total_time_wasted BIGINT DEFAULT 0,
                active_connections BIGINT DEFAULT 0,
                country_code CHAR(2),
                latitude DOUBLE PRECISION,
                longitude DOUBLE PRECISION,
                last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                max_concurrent BIGINT DEFAULT 0,
                asn BIGINT,
                prefix INET,
                net INET,
                sent_bytes BIGINT DEFAULT 0
            );
        """)
        await conn.execute("""
            UPDATE ssh_connections 
            SET max_concurrent = GREATEST(max_concurrent, active_connections)
            WHERE max_concurrent < active_connections;
        """)
        logger.info("Resetting stale active connections")
        reset_rows = await conn.fetch("""
            UPDATE ssh_connections 
            SET active_connections = 0 
            WHERE active_connections != 0 
            AND last_updated < NOW() - INTERVAL '5 minutes'
            RETURNING client_ip, active_connections AS old_active;
        """)
        if reset_rows:
            for row in reset_rows:
                logger.info("Reset active connection", extra={"client_ip": str(row['client_ip']), "old_active": row['old_active']})
        else:
            logger.info("No stale active connections to reset")

        # Table for unique client versions
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS client_versions (
                id SERIAL PRIMARY KEY,
                version TEXT UNIQUE NOT NULL
            );
        """)

        # Junction table to link IPs to client versions
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_client_versions (
                client_ip INET REFERENCES ssh_connections(client_ip),
                version_id INTEGER REFERENCES client_versions(id),
                first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                PRIMARY KEY (client_ip, version_id)
            );
        """)

async def upsert_connection_start(client_ip, country_code, latitude, longitude, client_version, client_hash, net, prefix, asn):
    logger.debug('Database storing started', extra={"client_ip": client_ip})
    now = datetime.utcnow()
    try:
        async with pool.acquire() as conn:
            # Upsert into ssh_connections
            active = await conn.fetchval("""
                INSERT INTO ssh_connections (
                    client_ip, first_seen, last_seen, country_code, 
                    latitude, longitude, active_connections, last_updated, max_concurrent,
                    net, prefix, asn
                )
                VALUES ($1, $2, $3, $4, $5, $6, 1, $7, 1, $8, $9, $10)
                ON CONFLICT (client_ip)
                DO UPDATE SET
                    connections = ssh_connections.connections + 1,
                    last_seen = EXCLUDED.last_seen,
                    active_connections = ssh_connections.active_connections + 1,
                    last_updated = EXCLUDED.last_updated,
                    max_concurrent = GREATEST(ssh_connections.max_concurrent, ssh_connections.active_connections + 1)
                RETURNING active_connections;
            """, client_ip, now, now, country_code, latitude, longitude, now, net, prefix, asn)
            logger.debug("Stored start of connection", extra={"client_ip": str(client_ip), "active_connections": active, "hash": client_hash})

            # Upsert client version into client_versions
            version_id = await conn.fetchval("""
                INSERT INTO client_versions (version)
                VALUES ($1)
                ON CONFLICT (version)
                DO UPDATE SET version = EXCLUDED.version
                RETURNING id;
            """, client_version)

            # Link IP to client version in ip_client_versions
            await conn.execute("""
                INSERT INTO ip_client_versions (client_ip, version_id, first_seen, last_seen)
                VALUES ($1, $2, $3, $3)
                ON CONFLICT (client_ip, version_id)
                DO UPDATE SET last_seen = EXCLUDED.last_seen;
            """, client_ip, version_id, now)
    except Exception as e:
        logger.error("Unexpected error storing connection start", extra={"client_ip": str(client_ip), "hash": client_hash, "err": str(e)})

async def upsert_connection_end(client_ip, duration_seconds, client_hash, sent_bytes):
    now = datetime.utcnow()
    try:
        async with pool.acquire() as conn:
            active = await conn.fetchval("""
                UPDATE ssh_connections
                SET
                    last_seen = $1,
                    total_time_wasted = total_time_wasted + $2,
                    active_connections = GREATEST(active_connections - 1, 0),
                    last_updated = $3,
                    sent_bytes = sent_bytes + $5
                WHERE client_ip = $4
                RETURNING active_connections;
            """, now, duration_seconds, now, client_ip, sent_bytes)
            logger.debug("Stored end of connection", extra={"client_ip": str(client_ip), "active_connections": active, "duration_seconds": duration_seconds, "hash": client_hash, "sent_bytes": sent_bytes})
    except Exception as e:
        logger.error("Unexpected error storing connection end", extra={"client_ip": str(client_ip), "hash": client_hash, "err": str(e)})



# Get geodata from IP (extract country code and coordinates)
async def get_geodata(ip):
    result = {}
    class GeoException(Exception):
        pass
    class IPDBException(Exception):
        pass
    
    loop = asyncio.get_event_loop()
    
    try:
        if ENRICH_GEOIP:
            geodata = await loop.run_in_executor(None, GEOIP_DATABASE.get, str(ip))
            if geodata is not None:
                result["country_code"] = geodata.get("country", {}).get("iso_code") or None
                result["latitude"] = geodata.get("location", {}).get("latitude") or None
                result["longitude"] = geodata.get("location", {}).get("longitude") or None
            else:
                raise GeoException(f"No GeoIP-data found for {ip}")
                
        if ENRICH_IPDB:
            ipdbdata = await loop.run_in_executor(None, IPDB_DATABASE.get, str(ip).split('::ffff:')[-1])
            if ipdbdata is not None:
                result["allocated_net"] = ipdbdata.get("allocation") or None
                result["allocated_prefix"] = ipdbdata.get("prefix") or None
                result["allocated_asn"] = ipdbdata.get("as") or None
            else:
                raise IPDBException(f"No IPDB-data found for {ip}")
                
    except (GeoException, IPDBException) as e:
        logger.error("Enrich failed", extra={"ip": ip, "error": str(e)})

    logger.debug("Got geo/asn result", extra={"ip": str(ip), "result": result})
    return result

async def handle_client(reader, writer):
    # Check active tasks count before proceeding
    if len(active_tasks) > max_tasks:
        logger.info(f"Active connections exceeded {max_tasks}. Restarting.")
        # Send SIGTERM to the current process
        os.kill(os.getpid(), signal.SIGTERM)

    # Your async connection code here
    await asyncio.sleep(1)  # Example async operation

    client_addr = writer.get_extra_info('peername')
    client_ip = client_addr[0]
    client_port = client_addr[1]
    start_time = datetime.utcnow()
    client_version_str = "Unknown"
    if ipaddress.ip_address(client_ip) in TEST_SUBNET:
        logger.debug("Converting test subnet IP to public IP")
        client_ip = "::ffff:195.88.54.16"
    try:
        client_version = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=1.0)
        decoded = client_version.decode('utf-8', errors='replace')[:64]
        client_version_str = ''.join(c for c in decoded if c.isprintable()).strip()
        #client_version_str = ''.join(c for c in decoded if ord(c) < 128).strip() # only ascii
    except (asyncio.TimeoutError, UnicodeDecodeError, asyncio.LimitOverrunError, Exception) as e:
        logger.warning("Failed to read client version", extra={"client_ip": client_ip, "error": str(e)})
    
    writer.transport.pause_reading()
    client_hash = create_stable_hash(client_ip,client_version_str,client_port)

    # Track this connection
    task = asyncio.current_task()
    active_tasks.add(task)

    logger.info("Received connection", extra={"client_ip": client_ip, "active_tasks": len(active_tasks), "version": client_version_str, "hash": client_hash})
    
    result = await get_geodata(client_ip)
    await upsert_connection_start(client_ip, result.get("country_code"), result.get("latitude"), result.get("longitude"), client_version_str, client_hash, result.get("allocated_net"), result.get("allocated_prefix"), result.get("allocated_asn"))

    sock = writer.transport.get_extra_info('socket')
    if sock:
        try:
            sock.shutdown(socket.SHUT_RD)
        except (TypeError, OSError):
            direct_sock = socket.socket(sock.family, sock.type, sock.proto, sock.fileno())
            try:
                direct_sock.shutdown(socket.SHUT_RD)
            finally:
                direct_sock.detach()
    preamble = [
        b'never\r\n',
        b'gonna\r\n',
        b'give\r\n',
        b'you\r\n',
        b'up\r\n',
        b'never\r\n',
        b'gonna\r\n',
        b'let\r\n',
        b'you\r\n',
        b'down\r\n',
        b'never\r\n',
        b'gonna\r\n',
        b'turn\r\n',
        b'around\r\n',
        b'and\r\n',
        b'desert\r\n',
        b'you\n'
    ]
    try:
        preamble_length = len(preamble)
        sent = 0
        sent_bytes = 0
        while True:
            await asyncio.sleep(random.uniform(0.5, 1))
            if sent < preamble_length and RICKROLL == 'True':
                writer.write(preamble[sent])
                sent_bytes = sent_bytes + len(preamble[sent])
                sent = sent + 1
            else: 
                writer.write(b'%.2x\r\n' % random.randrange(2**8))
                sent_bytes = sent_bytes + 4
            await writer.drain()
            
            logger.debug("Sent data", extra={"client_ip": client_ip, "hash": client_hash})
    except (ConnectionResetError, BrokenPipeError) as e:
        logger.info("Client disconnected", extra={"client_ip": client_ip, "error": str(e), "hash": client_hash})
    except (RuntimeError, TimeoutError) as e:
        logger.warning("Terminating connection", extra={"client_ip": client_ip, "error": str(e), "hash": client_hash})
    except OSError as e:
        logger.error("OSError in connection", extra={"client_ip": client_ip, "error": str(e), "hash": client_hash})
        if e.errno == 107:
            pass
        else:
            raise
    except (asyncio.CancelledError, ShutdownException) as e:
        logger.info("Cancelling task, received expected shutdown exception")
    finally:
        end_time = datetime.utcnow()
        duration_seconds = int((end_time - start_time).total_seconds())
        await upsert_connection_end(client_ip, duration_seconds, client_hash, sent_bytes)
        logger.info("Connection closed", extra={"client_ip": client_ip, "duration_seconds": duration_seconds, "hash": client_hash})
        writer.close()
        try:
            await writer.wait_closed()
        except BrokenPipeError:
            pass
        active_tasks.discard(task)
        logger.debug('Discarded task', extra={"task": str(task)})

async def shutdown(server, signal_name):
    logger.info(f"Received {signal_name}, closing all {len(active_tasks)} connections")
    
    for task in list(active_tasks):  # Convert to list to avoid set iteration issues
        await asyncio.sleep(0.1)
        if not task.done():
            logger.debug("Canceling task", extra={"task": str(task)})            
            task.cancel()
            await asyncio.sleep(0)  # Yield to event loop briefly
            try:
                await task
            except asyncio.CancelledError:
                pass
    # Close server and database
    logger.debug("Closing down server")
    server.close()
    await server.wait_closed()
    logger.debug("Closing down DB")
    await pool.close()
    
    logger.info(f"Shutdown complete.")
    if len(active_tasks) > 0:
        logger.info(f"Sleeping a little bit extra before getting wrecked because there are {len(active_tasks)} tasks active", extra={"tasks": str(active_tasks)})
        await asyncio.wait(active_tasks,timeout=len(active_tasks))
    for handler in logger.handlers:
        handler.flush()


# Main server
async def main():
    if not await wait_for_db(max_attempts=30, initial_delay=2):
        logger.error("Failed to connect to database. Exiting")
        return
    
    await init_pool()
    await init_db()

    net_total, prefix_total = await fetch_total_cidr_addresses()

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server_socket.bind(('::', 2222))
    server_socket.listen()

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w),
        sock=server_socket
    )
    logger.info("SSH tarpit running", extra={"address": "[::]:2222"})
    logger.info("Current address space covered by database entries", extra={"net": net_total, "prefix": prefix_total})
    
    # Set up signal handlers
    loop = asyncio.get_running_loop()
    shutdown_task = None
    
    def handle_signal(sig):
        nonlocal shutdown_task
        if shutdown_task is None:
            shutdown_task = asyncio.create_task(shutdown(server, sig.name))
            logger.debug(f"Signal {sig.name} received and shutdown task created")

    signals = [signal.SIGINT]
    if hasattr(signal, 'SIGTERM'):
        signals.append(signal.SIGTERM)
    
    for sig in signals:
        loop.add_signal_handler(sig, handle_signal, sig)
    
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        logger.info("Server interrupted, shutting down")
        if shutdown_task:
            await shutdown_task

if __name__ == "__main__":
    asyncio.run(main())

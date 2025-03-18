import asyncio
import asyncpg
import logging
import json
import os
import signal
from datetime import datetime

# Custom JSON logging formatter
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.msg,
        }
        exclude_fields = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename', 'module',
            'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName', 'created', 'msecs',
            'relativeCreated', 'thread', 'threadName', 'processName', 'process', 'logger'
        }
        extra_data = {k: v for k, v in record.__dict__.items() if k not in exclude_fields and not k.startswith('_')}
        log_data.update(extra_data)
        return json.dumps(log_data)

# Configure logging
logger = logging.getLogger('http-tarpit')
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

# Database configuration with environment variables
DB_CONFIG = {
    "database": os.getenv("TARPIT_DATABASE_DBNAME", "postgres"),
    "user": os.getenv("TARPIT_DATABASE_USER", "postgres"),
    "password": os.getenv("TARPIT_DATABASE_PASSWORD", "your_password"),
    "host": os.getenv("TARPIT_DATABASE_HOST", "localhost"),
    "port": "5432"
}

# Preamble data for Rickroll
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
    b'you\r\n'
]

# Standard Nginx 500 error page
NGINX_500_PAGE = (
    b"HTTP/1.1 500 Internal Server Error\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: text/html\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><body><h1>500 Internal Server Error</h1><p>nginx</p></body></html>"
)

# Standard 200 page with link
NGINX_200_PAGE = (
    b"HTTP/1.1 200 Ok\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: text/html\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><body><h1>Admin panel</h1><p><ul><li><a href=\"/admin/63616E27742062656C6965766520796F752066656C6C20666F722074686973/database.php\">Database shell</a></li></ul></p></body></html>"
)

# Global sets to track active tasks and seen IPs
active_tasks = set()
seen_ips = set()

async def init_db_pool():
    try:
        pool = await asyncpg.create_pool(**DB_CONFIG)
        async with pool.acquire() as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id SERIAL PRIMARY KEY,
                    client_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS paths (
                    id SERIAL PRIMARY KEY,
                    request_id INTEGER REFERENCES requests(id),
                    path TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payloads (
                    id SERIAL PRIMARY KEY,
                    request_id INTEGER REFERENCES requests(id),
                    payload_preview TEXT
                );
            ''')
        logger.info("Database pool initialized")
        return pool
    except Exception as e:
        logger.error("Failed to initialize database pool", extra={"error": str(e)})
        raise

async def log_request(pool, client_ip, method, path, payload_preview):
    try:
        logger.debug("Attempting to log request to database", extra={"client_ip": client_ip, "method": method, "path": path})
        async with pool.acquire() as conn:
            request_id = await conn.fetchval(
                'INSERT INTO requests (client_ip, method) VALUES ($1, $2) RETURNING id',
                client_ip, method
            )
            logger.debug("Inserted into requests table", extra={"client_ip": client_ip, "request_id": request_id})
            await conn.execute(
                'INSERT INTO paths (request_id, path) VALUES ($1, $2)',
                request_id, path
            )
            logger.debug("Inserted into paths table", extra={"client_ip": client_ip, "request_id": request_id})
            if payload_preview:
                await conn.execute(
                    'INSERT INTO payloads (request_id, payload_preview) VALUES ($1, $2)',
                    request_id, payload_preview
                )
                logger.debug("Inserted into payloads table", extra={"client_ip": client_ip, "request_id": request_id})
        logger.debug("Request successfully logged to database", extra={"client_ip": client_ip, "method": method, "path": path})
    except Exception as e:
        logger.error("Database logging failed", extra={"client_ip": client_ip, "error": str(e)})
        raise

async def handle_client(reader, writer, pool):
    task = asyncio.current_task()
    active_tasks.add(task)
    addr = writer.get_extra_info('peername')
    client_ip = addr[0]
    try:
        logger.debug("Starting client handling", extra={"client_ip": client_ip})
        request_line = await reader.readline()
        if not request_line:
            logger.info("No request received", extra={"client_ip": client_ip})
            await log_request(pool, client_ip, "UNKNOWN", "NO_PATH", None)
            writer.write(NGINX_500_PAGE)
            await writer.drain()
            return

        method, path, _ = request_line.decode().split(" ", 2)
        if path == "/favicon.ico":
            raise Exception("Ignoring favicon request")
        logger.info(f"{method} {path}", extra={"client_ip": client_ip, "method": method, "path": path})

        logger.debug("Reading headers", extra={"client_ip": client_ip})
        while True:
            line = await reader.readline()
            if line == b'\r\n' or not line:
                break
        logger.debug("Finished reading headers", extra={"client_ip": client_ip})

        logger.debug("Reading payload", extra={"client_ip": client_ip})
        try:
            payload_preview = await asyncio.wait_for(reader.read(100), timeout=0.3)
            payload_str = payload_preview.decode('utf-8', errors='ignore') if payload_preview else None
            logger.debug("Payload read", extra={"client_ip": client_ip, "payload_preview": payload_str})
        except asyncio.TimeoutError:
            logger.warning("Payload read timed out", extra={"client_ip": client_ip})
            payload_str = None

        await log_request(pool, client_ip, method, path, payload_str)

        # Check if this is the first request from this IP
        if client_ip not in seen_ips:
            logger.debug("First request from IP, sending standard 200", extra={"client_ip": client_ip})
            writer.write(NGINX_200_PAGE)
            await writer.drain()
            seen_ips.add(client_ip)  # Mark IP as seen
        else:
            logger.debug("Returning IP, sending Rickroll", extra={"client_ip": client_ip})
            writer.write(
                b"HTTP/1.1 500 Internal Server Error\r\n"
                b"Server: nginx\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            await writer.drain()

            timeout = 10
            for i in range(timeout):
                data = preamble[i % len(preamble)]
                logger.debug("Sending preamble data", extra={"client_ip": client_ip, "data": data.decode('utf-8', errors='ignore')})
                writer.write(data)
                await writer.drain()
                await asyncio.sleep(1)

            #logger.debug("Sending 500 response after Rickroll", extra={"client_ip": client_ip})
            #writer.write(NGINX_500_PAGE)
            await writer.drain()

    except (ConnectionError, BrokenPipeError, ValueError) as e:
        logger.error("Client error", extra={"client_ip": client_ip, "error": str(e)})
    except asyncio.CancelledError:
        logger.info("Task cancelled", extra={"client_ip": client_ip})
        raise
    except Exception as e:
        logger.error("Unexpected error in client handling", extra={"client_ip": client_ip, "error": str(e)})
        raise
    finally:
        try:
            logger.debug("Closing writer", extra={"client_ip": client_ip})
            writer.close()
            await writer.wait_closed()
            logger.info("Disconnected", extra={"client_ip": client_ip})
        except (ConnectionError, BrokenPipeError):
            logger.error("Error closing writer", extra={"client_ip": client_ip})
        active_tasks.discard(task)

async def shutdown(db_pool, server, signal_name):
    logger.info(f"Received {signal_name}, closing all {len(active_tasks)} connections")
    
    for task in active_tasks.copy():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    
    server.close()
    await server.wait_closed()
    await db_pool.close()
    
    logger.info("Shutdown complete")
    for handler in logger.handlers:
        handler.flush()

async def main():
    pool = await init_db_pool()
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, pool), '0.0.0.0', 8080
    )
    addr = server.sockets[0].getsockname()
    logger.info("Server started", extra={"address": str(addr)})

    loop = asyncio.get_running_loop()
    shutdown_task = None
    
    def handle_signal(sig):
        nonlocal shutdown_task
        if shutdown_task is None:
            shutdown_task = asyncio.create_task(shutdown(pool, server, sig.name))
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

# Run the server
asyncio.run(main())

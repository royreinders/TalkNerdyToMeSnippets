import sqlite3
from datetime import datetime
from outflank_stage1.bot import BaseBot
from outflank_stage1.task import GenericTask
from outflank_stage1.services.task_service import TaskService
from outflank_stage1.implant import Implant

DB_PATH = "/shared/mcp.sqlite"

def get_unexecuted_commands(implant_uid: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, command FROM commands WHERE implant_uid = ? AND executed = 0",
        (implant_uid,)
    )
    rows = c.fetchall()
    conn.close()
    return rows

def mark_command_executed(command_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE commands SET executed = 1 WHERE id = ?", (command_id,))
    conn.commit()
    conn.close()

def insert_implant(implant: Implant):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO active_implants (
            implant_uid, username, hostname, os, arch,
            pid, proc_name, first_seen, last_checkin
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        implant.get_uid(),
        implant.get_username() or "unknown",
        implant.get_hostname() or "unknown",
        implant.get_os() or "unknown",
        "unknown",  # For some reason inserting the arch does not work yet
        implant.get_pid() or 0,
        implant.get_proc_name() or "unknown",
        implant.get_first_seen().isoformat() if implant.get_first_seen() else now,
        now
    ))
    conn.commit()
    conn.close()



def update_lastseen(implant: Implant):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE active_implants
        SET last_checkin = ?
        WHERE implant_uid = ?
    """, (
        now,
        implant.get_uid()
    ))
    conn.commit()
    conn.close()

class MCPBot(BaseBot):
    def on_new_implant(self, implant: Implant):
        insert_implant(implant)
        task_service = TaskService()
        for cmd_id, cmd_text in get_unexecuted_commands(implant.get_uid()):
            task = GenericTask(cmd_text)
            task_service.schedule_task(implant_uid=implant.get_uid(), task=task)
            mark_command_executed(cmd_id)

    def on_implant_checkin(self, implant: Implant):
        update_lastseen(implant)
        task_service = TaskService()

        # Schedule unexecuted commands
        for cmd_id, cmd_text in get_unexecuted_commands(implant.get_uid()):
            task = GenericTask(cmd_text)
            task_service.schedule_task(implant_uid=implant.get_uid(), task=task)
            mark_command_executed(cmd_id)

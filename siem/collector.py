"""
Mini-SOC SIEM Log Collector
Tails Suricata eve.json and forwards alerts to the correlation engine.
"""

import os
import json
import time
import logging
import threading
from typing import Optional, Callable

logger = logging.getLogger("siem.collector")


class SuricataLogCollector:
    def __init__(self, log_path: str = "eve.json", alert_handler: Optional[Callable] = None):
        self.log_path = log_path
        self.alert_handler = alert_handler
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._tail_file, daemon=True)
        self._thread.start()
        logger.info(f"Suricata Log Collector started monitoring {self.log_path}")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        logger.info("Suricata Log Collector stopped")

    def _tail_file(self):
        while self._running:
            if not os.path.exists(self.log_path):
                time.sleep(1.0)
                continue

            try:
                with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                    # Seek to end on startup to avoid processing old lines unless required
                    f.seek(0, os.SEEK_END)
                    while self._running:
                        line = f.readline()
                        if not line:
                            time.sleep(0.2)
                            continue

                        line = line.strip()
                        if not line:
                            continue

                        try:
                            record = json.loads(line)
                            if record.get("event_type") == "alert":
                                if self.alert_handler:
                                    self.alert_handler(record)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Error reading eve.json ({self.log_path}): {e}")
                time.sleep(2.0)

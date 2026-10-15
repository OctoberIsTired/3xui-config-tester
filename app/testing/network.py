"""Observe Windows routing without changing it from a Web request."""
from __future__ import annotations

import asyncio
import json
import socket
import sys
from typing import Any


async def direct_route_status(host: str) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"status": "unsupported", "direct": None}
    try:
        addresses = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_INET)
        ips = sorted({item[4][0] for item in addresses})
        # DNS results are IP literals, never shell text from configuration.
        ip_json = json.dumps(ips).replace("'", "''")
        script = (f"$ips = ConvertFrom-Json '{ip_json}'; "
                  "$physical = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up'); "
                  "$selected = @($ips | ForEach-Object { @(Find-NetRoute -RemoteIPAddress $_) | "
                  "Select-Object -ExpandProperty InterfaceIndex -Unique }); "
                  "@{direct=(@($selected | Where-Object {$_ -notin $physical.InterfaceIndex}).Count -eq 0);"
                  "interface_indexes=@($selected | Sort-Object -Unique)} | ConvertTo-Json -Compress")
        process = await asyncio.create_subprocess_exec(
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            output, _ = await asyncio.wait_for(process.communicate(), 15)
        except TimeoutError:
            process.kill()
            await process.communicate()
            return {"status": "unavailable", "direct": None}
        if process.returncode:
            return {"status": "unavailable", "direct": None}
        return {"status": "observed", **json.loads(output.decode("utf-8-sig"))}
    except (OSError, ValueError):
        return {"status": "unavailable", "direct": None}

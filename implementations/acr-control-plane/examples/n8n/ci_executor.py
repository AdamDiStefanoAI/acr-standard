"""Disposable observer around the real synthetic ticket implementation."""

from copy import deepcopy

from examples.protected_executor import app as executor

app = executor.app
records = []
original = executor._ALLOWED_TOOLS["create_ticket"]


def observed_ticket(customer_id: str, subject: str, priority: str = "normal"):
    result = original(customer_id, subject, priority)
    records.append(deepcopy(result))
    return result


executor._ALLOWED_TOOLS["create_ticket"] = observed_ticket


@app.get("/__test/ledger")
async def ledger():
    return records

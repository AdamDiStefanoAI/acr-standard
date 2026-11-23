"""Outbound integrations (v1.5.0 WS4).

Slack / Teams approvals and alerts, ServiceNow incidents, and Microsoft
Sentinel decision export, all delivered asynchronously from the durable
integration outbox (see acr.integrations.outbox). Chat approvals are
clients of the pillar 6 approvals API — never a side door around it.
"""

import re, json, functools, ipaddress
from fnmatch import fnmatch


def detect(record):
    return (
        (
            record.get("data", {})
            .get("protoPayload", {})
            .get("authorizationInfo", {})
            .get("permission")
            in (
                "accesscontextmanager.accessPolicies.delete",
                "accesscontextmanager.accessPolicies.accessLevels.delete",
                "accesscontextmanager.accessPolicies.accessZones.delete",
                "accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete",
            )
        )
        and record.get("data", {})
        .get("protoPayload", {})
        .get("authorizationInfo", {})
        .get("granted")
        == "true"
        and record.get("data", {}).get("protoPayload", {}).get("serviceName")
        == "accesscontextmanager.googleapis.com"
    )

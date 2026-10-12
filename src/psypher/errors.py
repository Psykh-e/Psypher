"""Stable error categories shared by the API, menu, and CLI."""


class PsypherError(Exception):
    code = 5


class UsageError(PsypherError):
    code = 2


class AccessError(PsypherError):
    code = 3


class IntegrityError(PsypherError):
    code = 4


class StorageError(PsypherError):
    code = 5


class LockedError(AccessError):
    pass

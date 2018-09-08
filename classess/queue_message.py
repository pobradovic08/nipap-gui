class QueueMessage:
    STATUS_ERROR = 0
    STATUS_OK = 1

    TYPE_PREFIXES = 1
    TYPE_VRFS = 2
    TYPE_STATUS = 3
    TYPE_ERROR = 4

    def __init__(self, type, data, status):
        self.type = type
        self.data = data
        self.status = status
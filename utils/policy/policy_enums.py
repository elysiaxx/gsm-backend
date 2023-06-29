import enum


class AddrTypes(enum.Enum):
    SRC = 0
    DST = 1

class PolicyPartType(enum.Enum):
    Header = 0
    General = 1
    Detection = 2
    NonDetection = 3
    PostDetection = 4
    Modifier = 5
    
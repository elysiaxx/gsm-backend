from utils.policy.policy_enums import PolicyPartType


def is_numeric(val):
    return any(char.isdigit() for char in val)

def check_enclose_bracket(data):
    return False if data[0] != '\"' or data[-1] != '\"' \
                else True


def policy_part_str(tp):
    if tp == PolicyPartType.Header:
        return "header"
    if tp == PolicyPartType.General:
        return "general"
    if tp == PolicyPartType.Detection:
        return "detection"
    if tp == PolicyPartType.NonDetection:
        return "non_detection"
    if tp == PolicyPartType.PostDetection:
        return "post_detection"
    if tp == PolicyPartType.Modifier:
        return "modifiers"
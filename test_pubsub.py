import meshtastic
import meshtastic.tcp_interface
from pubsub import pub

# Print all topics
topicMgr = pub.getDefaultTopicMgr()
tree = topicMgr.getRootAllTopics()
def print_tree(t, prefix=""):
    print(prefix + t.getName())
    for st in t.getSubtopics():
        print_tree(st, prefix + "  ")

print_tree(tree)

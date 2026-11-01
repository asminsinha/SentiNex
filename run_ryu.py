import sys, os
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(0, os.path.abspath('./src'))
import eventlet
eventlet.monkey_patch()
from ryu.cmd.manager import main
if __name__ == '__main__':
    main()

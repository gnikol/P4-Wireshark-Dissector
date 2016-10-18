import os
import sys
sys.path.append('../p4_hlir/')
from p4_hlir.main import HLIR

p4_source = sys.argv[1]
absolute_source = os.path.join(os.getcwd(), p4_source)
if not os.path.isfile(absolute_source):
    print "Source file '" + p4_source + \
          "' could not be opened or does not exist."

hlir = HLIR(absolute_source)
hlir.build()
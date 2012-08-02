
from FingerPrint.plugins import PluginManager



swirlFile = PluginManager.getSwirl('/etc/passwd')
swirlFile = PluginManager.getSwirl('/bin/ls')

print "File: ", swirlFile


p = PluginManager.get_plugins()
print "plugins: ", p


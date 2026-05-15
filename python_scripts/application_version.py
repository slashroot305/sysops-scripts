import os
stream = os.popen('mdls -raw -name kMDItemVersion /Applications/"Logic Pro X.app"')
targetVersion = 'Version is ' + stream.read()
print(targetVersion)
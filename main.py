import hashlib
filename = "/root/PycharmProjects/research/Benign_2017/a.envisionmobile.caa.apk"
hasher = hashlib.md5()
l = hashlib.sha512()
with open(filename,'rb') as f:
    co = f.read()
    hasher.update(co)

print(l.hexdigest())
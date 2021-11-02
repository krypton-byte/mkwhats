# Inspirated By Flask
class lists:
    def __init__(self) -> None:
        self.ad = []
        pass
    def execute(self):
        for i in self.ad:
            print(i(1))
            print('a')
    def anu(self, t):
        def ani(f):
            def ano(a):
                print(t)
                self.ad.append(f)
            return ano
        return ani  
anu=lists()
@anu.anu('hah')
def ha(a):
    print(a)

ha(1)
print(anu.ad)
anu.execute()
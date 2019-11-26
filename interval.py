#naive implementation of an interval set using a sorted list
#efficiency very poor, unwise to use with more than about 1000 intervals
from sortedcontainers import SortedList
import ast

class IntervalSet:

    #hideously inefficient, use only for short interval sets
    def compress(self):
        sl = self.sl
        l = len(sl)
        i = 0

        while i < l - 1:
            #print("compress_interval " + str(i) + " => " + str(sl[i]) + "-" + str(sl[i+1])) 
            if sl[i][1] >= sl[i+1][0] - 1:
                # merge
                new = (min(sl[i][0], sl[i+1][0]), max(sl[i][1], sl[i+1][1]))
                sl.remove(sl[i+1])
                sl.remove(sl[i])
                sl.add(new)
                l -= 1
                continue
            i+=1 
    
    def __init__(self, l = None):
        if l == None:
            self.sl = SortedList()
            return
        if type(l) == str:
            self.sl = SortedList()
            self.restore(l)
            return
        if type(l) == tuple:
            self.sl = SortedList()
            self.add(l)
            return
        if type(l) == list:
            l = l[:]
            for i in range(0, len(l)):
                if type(l[i]) != tuple:
                    raise Exception('created intervalset with list containing something other than a tuple: ' + str(l[i]))
                n = l[i]
                if n[0] > n[1]:
                    new = (n[1], n[0])
                    l.remove(n)
                    l.add(new)
                    i = 0
            self.sl = SortedList(l)
            return

        raise Exception('attempted to create an interval set with unknown parameter type: ' + str(type(l)))

    def add(self, x, y = None):
        if type(x) != int or x < 0 or ( not y == None and ( type(y) != int or y < 0 ) ) :
            raise Exception('intervalset must be supplied with positive integers')
        
        sl = self.sl
        if x == None:
            raise Exception('attempted to add empty to integer set')
        if y == None:
            y = x
        if x > y:
            a = x
            x = y
            y = a
        sl.add( (x,y) )
        self.compress()

    def __len__(self):
        return len(self.sl)

    def __str__(self):
        return 'IntervalSet' + str(self.sl)[10:] 


    def save(self, fn):
        sl = self.sl
        f = open(fn, "w+")
        for x in sl:
            f.write(str(x) + ",")
        f.close()

    def restore(self, fn):
        sl = self.sl
        f = open(fn, "r+")
        content = f.read()
        if len(content) == 0:
            self.sl = SortedList()
            return

        if content[-1] == ",":
            content = content[:-1]
        self.sl = SortedList(ast.literal_eval("[" + content + "]"))
        
    def contains(self, x):
        sl = self.sl
        i = 0
        l = len(sl)
        if l == 0:
            return False
        while i < l and sl[i][0] <= x:
            if sl[i][0] <= x and sl[i][1] >= x:
                return True
            i += 1

        return False

    #fetch the largest missing number that would go toward closing intervals
    # false if intervals are closed
    def last_missing(self):
        if len(self.sl) == 0:
            return False
        if len(self.sl) == 1:
            if self.sl[0][0] == 0:
                return False
            return self.sl[0][0]-1
        return self.sl[len(self.sl)-1][0]-1

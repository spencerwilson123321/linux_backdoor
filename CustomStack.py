
class Stack():

    def __init__(self):
        self.__list = []
        self.__index = 0
    
    def top(self):
        return self.__list[self.__index]
    
    def push(self, element):
        self.__list.append(element)
        self.__index += 1
    
    def pop(self):
        self.__index -= 1
        return self.__list.pop()
    
    def isEmpty(self):
        return len(self.__list) == 0

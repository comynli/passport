
import functools

__author__ = 'comyn'


class A(object):
    def __init__(self, data):
        self.data = data

    def __call__(self, fn):
        @functools.wraps(fn)
        def decorated(instance, *args, **kwargs):
            print instance
            print self.data
            fn(instance, *args, **kwargs)
        return decorated



class B(object):
    @A('test')
    def test(self):
        print "okkkkkk"
        raise Exception('djkfkldj')



if __name__ == '__main__':
    b = B()
    b.test()
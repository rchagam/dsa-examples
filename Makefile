all: libdsaproxy dsa-fill-sample dsa-sample-mt dsa-memproxy-test

DML_LIB_CXX=-D_GNU_SOURCE

dsa-fill-sample: dsa-fill-sample.c
	gcc dsa-fill-sample.c $(DML_LIB_CXX) libdsaproxy.so.1.0 -lpthread -laccel-config -ldl -o dsa-fill-sample

dsa-sample-mt: dsa-sample-mt.c
	gcc dsa-sample-mt.c $(DML_LIB_CXX) libdsaproxy.so.1.0 -lpthread -laccel-config -ldl -o dsa-sample-mt

dsa-memproxy-test: dsa-memproxy-test.c
	gcc dsa-memproxy-test.c $(DML_LIB_CXX) -o dsa-memproxy-test -ldsaproxy -laccel-config -lpthread -ldl

libdsaproxy: dsa-memproxy.c
	gcc -shared -fPIC -Wl,-soname,libdsaproxy.so dsa-memproxy.c $(DML_LIB_CXX) -o libdsaproxy.so.1.0 -ldl

install:
	cp libdsaproxy.so.1.0 /usr/lib64/
	ln -sf /usr/lib64/libdsaproxy.so.1.0 /usr/lib64/libdsaproxy.so.1
	ln -sf /usr/lib64/libdsaproxy.so.1.0 /usr/lib64/libdsaproxy.so
clean:
	rm -rf *.o *.so dsa-fill-sample dsa-sample-mt dsa-memproxy-test 

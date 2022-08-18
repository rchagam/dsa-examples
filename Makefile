all: dsa-memproxy.so dsa-fill-sample dsa-sample-mt dsa-memproxy-test

DML_LIB_CXX=-D_GNU_SOURCE

dsa-fill-sample: dsa-fill-sample.c
	gcc dsa-fill-sample.c $(DML_LIB_CXX) -lpthread -ldl -o dsa-fill-sample

dsa-sample-mt: dsa-sample-mt.c
	gcc dsa-sample-mt.c $(DML_LIB_CXX) -lpthread -ldl -o dsa-sample-mt

dsa-memproxy-test: dsa-memproxy-test.c
	gcc dsa-memproxy-test.c $(DML_LIB_CXX) -o dsa-memproxy-test  -lpthread -ldl

dsa-memproxy.so: dsa-memproxy.c
	gcc -shared -fPIC dsa-memproxy.c $(DML_LIB_CXX) -o dsa-memproxy.so -ldl

clean:
	rm -rf *.o *.so dsa-fill-sample dsa-sample-mt dsa-memproxy-test 
